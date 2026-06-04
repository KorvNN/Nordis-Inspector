"""Memory-only orchestration for local, allow-listed password-audit tools."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Event, Lock, RLock, Thread
from time import monotonic
from typing import Protocol
from uuid import uuid4

from nordis_smb_inspector.core.credential_audit import (
    AuditMaterial,
    AuditToolBinding,
    audit_tool_formats,
)

MAX_WORDLIST_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_WORDLIST_LINE_BYTES = 64 * 1024
_ALLOWED_RUNTIME_SECONDS = frozenset({30, 120, 300})
_PROCESS_GRACE_SECONDS = 5
_TERMINATE_GRACE_SECONDS = 2
_MAX_RESULT_FILE_BYTES = 128 * 1024


class AuditJobStatus(StrEnum):
    RUNNING = "running"
    CANCELLING = "cancelling"
    CRACKED = "cracked"
    EXHAUSTED = "exhausted"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    FAILED = "failed"


_ACTIVE_JOB_STATUSES = frozenset(
    {AuditJobStatus.RUNNING, AuditJobStatus.CANCELLING}
)


class AuditRunOutcome(StrEnum):
    CRACKED = "cracked"
    EXHAUSTED = "exhausted"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    FAILED = "failed"


class AuditError(RuntimeError):
    """Base error with no submitted material in its representation."""


class AuditAlreadyRunning(AuditError):
    pass


class AuditToolUnavailable(AuditError):
    pass


class AuditRequestError(AuditError):
    pass


class AuditInvalidTransition(AuditError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class AuditToolAvailability:
    tool_id: str
    display_name: str
    available: bool
    reason: str | None = None
    supported_formats: tuple[str, ...] = ()
    executable_path: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        formats = tuple(
            sorted(
                {
                    value.casefold()
                    for value in self.supported_formats
                    if isinstance(value, str) and value and value.isascii()
                }
            )
        )
        if len(formats) != len(self.supported_formats):
            raise ValueError("Tool formats must be unique non-empty ASCII text.")
        if self.available and not formats:
            raise ValueError("An available audit tool must expose supported formats.")
        object.__setattr__(self, "supported_formats", formats)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(tool_id={self.tool_id!r}, "
            f"display_name={self.display_name!r}, available={self.available!r}, "
            f"reason={self.reason!r}, supported_formats={self.supported_formats!r}, "
            f"executable_path=<redacted>)"
        )

    def supports_format(self, format_name: str) -> bool:
        return self.available and format_name.casefold() in self.supported_formats

    def public_payload(self) -> dict[str, object]:
        return {
            "id": self.tool_id,
            "name": self.display_name,
            "available": self.available,
            "reason": self.reason,
            "formats": list(self.supported_formats),
        }


@dataclass(frozen=True, slots=True, repr=False)
class AuditRunRequest:
    executable_path: str = field(repr=False)
    binding: AuditToolBinding
    material: str = field(repr=False)
    wordlist_path: Path = field(repr=False)
    wordlist_size: int
    runtime_seconds: int

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(executable_path=<redacted>, "
            f"binding={self.binding!r}, material=<redacted>, "
            f"wordlist_path=<redacted>, wordlist_size={self.wordlist_size!r}, "
            f"runtime_seconds={self.runtime_seconds!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class WordlistUploadHandle:
    upload_id: str
    path: Path = field(repr=False)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(upload_id={self.upload_id!r}, path=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class UploadedWordlist:
    upload_id: str
    path: Path = field(repr=False)
    size_bytes: int
    entry_count: int

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(upload_id={self.upload_id!r}, path=<redacted>, "
            f"size_bytes={self.size_bytes!r}, entry_count={self.entry_count!r})"
        )

    def public_payload(self) -> dict[str, object]:
        return {
            "upload_id": self.upload_id,
            "size_bytes": self.size_bytes,
            "entry_count": self.entry_count,
        }


@dataclass(slots=True)
class WordlistUploadValidator:
    """Incrementally validate a large newline-delimited wordlist."""

    size_bytes: int = 0
    entry_count: int = 0
    _line_bytes: int = 0
    _line_has_content: bool = False

    def consume(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            raise TypeError("wordlist chunks must be bytes.")
        self.size_bytes += len(chunk)
        if self.size_bytes > MAX_WORDLIST_UPLOAD_BYTES:
            raise AuditRequestError("WORDLIST_TOO_LARGE")
        parts = chunk.split(b"\n")
        for index, part in enumerate(parts):
            self._line_bytes += len(part)
            if self._line_bytes > MAX_WORDLIST_LINE_BYTES:
                raise AuditRequestError("WORDLIST_LINE_TOO_LONG")
            self._line_has_content = self._line_has_content or any(
                value != 0x0D for value in part
            )
            if index < len(parts) - 1:
                if self._line_has_content:
                    self.entry_count += 1
                self._line_bytes = 0
                self._line_has_content = False

    def finish(self) -> tuple[int, int]:
        if self._line_has_content:
            self.entry_count += 1
            self._line_has_content = False
        if self.size_bytes == 0:
            raise AuditRequestError("WORDLIST_SIZE_INVALID")
        if self.entry_count == 0:
            raise AuditRequestError("WORDLIST_ENTRY_COUNT_INVALID")
        return self.size_bytes, self.entry_count


@dataclass(frozen=True, slots=True, repr=False)
class AuditRunResult:
    outcome: AuditRunOutcome
    plaintext: str | None = field(default=None, repr=False)
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.outcome is AuditRunOutcome.CRACKED:
            if not isinstance(self.plaintext, str):
                raise ValueError("A cracked result requires plaintext.")
        elif self.plaintext is not None:
            raise ValueError("Only cracked results may retain plaintext.")
        if self.outcome is AuditRunOutcome.FAILED:
            if not isinstance(self.error_code, str) or not self.error_code:
                raise ValueError("A failed result requires a safe error code.")
        elif self.error_code is not None:
            raise ValueError("Only failed results may contain an error code.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(outcome={self.outcome.value!r}, "
            f"plaintext={'<redacted>' if self.plaintext is not None else None}, "
            f"error_code={self.error_code!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class AuditJobSnapshot:
    job_id: str
    candidate_id: str
    tool_id: str
    format_id: str
    variant: str
    status: AuditJobStatus
    runtime_seconds: int
    started_at: datetime
    finished_at: datetime | None = None
    plaintext: str | None = field(default=None, repr=False)
    error_code: str | None = None

    @property
    def active(self) -> bool:
        return self.status in _ACTIVE_JOB_STATUSES

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(job_id={self.job_id!r}, "
            f"candidate_id={self.candidate_id!r}, tool_id={self.tool_id!r}, "
            f"format_id={self.format_id!r}, "
            f"variant={self.variant!r}, status={self.status.value!r}, "
            f"runtime_seconds={self.runtime_seconds!r}, "
            f"started_at={self.started_at!r}, finished_at={self.finished_at!r}, "
            f"plaintext={'<redacted>' if self.plaintext is not None else None}, "
            f"error_code={self.error_code!r})"
        )

    def public_payload(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "candidate_id": self.candidate_id,
            "tool_id": self.tool_id,
            "format": self.format_id,
            "variant": self.variant,
            "status": self.status.value,
            "runtime_seconds": self.runtime_seconds,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "plaintext": self.plaintext,
            "error_code": self.error_code,
        }


class AuditToolRunner(Protocol):
    tool_id: str
    display_name: str

    def availability(self) -> AuditToolAvailability: ...

    def run(self, request: AuditRunRequest, cancellation: Event) -> AuditRunResult: ...


class CredentialAuditManager:
    """Own at most one local audit job and retain only its in-memory result."""

    def __init__(self, runners: Iterable[AuditToolRunner] | None = None) -> None:
        selected = tuple(runners) if runners is not None else (HashcatRunner(), JohnRunner())
        if not selected:
            raise ValueError("At least one audit runner is required.")
        self._runners: dict[str, AuditToolRunner] = {}
        for runner in selected:
            if runner.tool_id in self._runners:
                raise ValueError("Audit runner IDs must be unique.")
            self._runners[runner.tool_id] = runner
        self._lock = RLock()
        self._job: AuditJobSnapshot | None = None
        self._cancellation: Event | None = None
        self._wordlist_directory = tempfile.TemporaryDirectory(prefix="nordis-wordlists-")
        self._wordlist_root = Path(self._wordlist_directory.name)
        self._wordlist_root.chmod(0o700)
        self._pending_upload: WordlistUploadHandle | None = None
        self._wordlist: UploadedWordlist | None = None
        self.worker: Thread | None = None

    @property
    def snapshot(self) -> AuditJobSnapshot | None:
        with self._lock:
            return self._job

    @property
    def active(self) -> bool:
        with self._lock:
            return (
                (self._job is not None and self._job.active)
                or self._pending_upload is not None
            )

    @property
    def wordlist(self) -> UploadedWordlist | None:
        with self._lock:
            return self._wordlist

    def tools(self) -> tuple[AuditToolAvailability, ...]:
        return tuple(runner.availability() for runner in self._runners.values())

    def begin_wordlist_upload(self) -> WordlistUploadHandle:
        with self._lock:
            if self._job is not None and self._job.active:
                raise AuditAlreadyRunning("AUDIT_ALREADY_RUNNING")
            if self._pending_upload is not None:
                raise AuditAlreadyRunning("WORDLIST_UPLOAD_IN_PROGRESS")
            upload_id = str(uuid4())
            handle = WordlistUploadHandle(
                upload_id=upload_id,
                path=self._wordlist_root / f"{upload_id}.txt",
            )
            self._pending_upload = handle
            return handle

    def complete_wordlist_upload(
        self,
        handle: WordlistUploadHandle,
        *,
        size_bytes: int,
        entry_count: int,
    ) -> UploadedWordlist:
        if not isinstance(handle, WordlistUploadHandle):
            raise TypeError("handle must be a WordlistUploadHandle.")
        if size_bytes <= 0 or size_bytes > MAX_WORDLIST_UPLOAD_BYTES:
            raise AuditRequestError("WORDLIST_SIZE_INVALID")
        if entry_count <= 0:
            raise AuditRequestError("WORDLIST_ENTRY_COUNT_INVALID")
        try:
            actual_size = handle.path.stat().st_size
        except OSError as exc:
            raise AuditRequestError("INVALID_WORDLIST") from exc
        if actual_size != size_bytes:
            raise AuditRequestError("INVALID_WORDLIST")
        with self._lock:
            if self._pending_upload != handle:
                raise AuditInvalidTransition("STALE_WORDLIST_UPLOAD")
            previous = self._wordlist
            uploaded = UploadedWordlist(
                upload_id=handle.upload_id,
                path=handle.path,
                size_bytes=size_bytes,
                entry_count=entry_count,
            )
            self._wordlist = uploaded
            self._pending_upload = None
        if previous is not None and previous.path != uploaded.path:
            _discard_private_file(previous.path)
        return uploaded

    def abort_wordlist_upload(self, handle: WordlistUploadHandle) -> None:
        if not isinstance(handle, WordlistUploadHandle):
            raise TypeError("handle must be a WordlistUploadHandle.")
        with self._lock:
            if self._pending_upload == handle:
                self._pending_upload = None
        _discard_private_file(handle.path)

    def start(
        self,
        *,
        material: AuditMaterial,
        tool_id: object,
        wordlist_upload_id: object,
        runtime_seconds: object,
    ) -> AuditJobSnapshot:
        if not isinstance(material, AuditMaterial):
            raise TypeError("material must be AuditMaterial.")
        if not isinstance(tool_id, str):
            raise AuditRequestError("INVALID_TOOL")
        if (
            isinstance(runtime_seconds, bool)
            or not isinstance(runtime_seconds, int)
            or runtime_seconds not in _ALLOWED_RUNTIME_SECONDS
        ):
            raise AuditRequestError("INVALID_RUNTIME")
        if not isinstance(wordlist_upload_id, str):
            raise AuditRequestError("INVALID_WORDLIST")
        binding = material.binding_for(tool_id)
        if binding is None:
            raise AuditRequestError("INCOMPATIBLE_TOOL")
        runner = self._runners.get(tool_id)
        if runner is None:
            raise AuditRequestError("INVALID_TOOL")
        availability = runner.availability()
        if not availability.available or availability.executable_path is None:
            raise AuditToolUnavailable("TOOL_UNAVAILABLE")
        if not availability.supports_format(binding.format_name):
            raise AuditRequestError("INCOMPATIBLE_TOOL")

        now = datetime.now(UTC)
        with self._lock:
            if self._job is not None and self._job.active:
                raise AuditAlreadyRunning("AUDIT_ALREADY_RUNNING")
            if self._pending_upload is not None:
                raise AuditAlreadyRunning("WORDLIST_UPLOAD_IN_PROGRESS")
            wordlist = self._wordlist
            if wordlist is None or wordlist.upload_id != wordlist_upload_id:
                raise AuditRequestError("WORDLIST_NOT_FOUND")
            request = AuditRunRequest(
                executable_path=availability.executable_path,
                binding=binding,
                material=material.material,
                wordlist_path=wordlist.path,
                wordlist_size=wordlist.size_bytes,
                runtime_seconds=runtime_seconds,
            )
            job = AuditJobSnapshot(
                job_id=str(uuid4()),
                candidate_id=material.candidate_id,
                tool_id=tool_id,
                format_id=material.format_id,
                variant=material.variant,
                status=AuditJobStatus.RUNNING,
                runtime_seconds=runtime_seconds,
                started_at=now,
            )
            cancellation = Event()
            self._job = job
            self._cancellation = cancellation
            worker = Thread(
                target=self._run,
                args=(job.job_id, runner, request, cancellation),
                name=f"nordis-audit-{job.job_id}",
                daemon=True,
            )
            self.worker = worker
            worker.start()
            return job

    def cancel(self) -> AuditJobSnapshot:
        with self._lock:
            if self._job is None or not self._job.active or self._cancellation is None:
                raise AuditInvalidTransition("AUDIT_NOT_RUNNING")
            self._cancellation.set()
            self._job = replace(self._job, status=AuditJobStatus.CANCELLING)
            return self._job

    def clear(self) -> None:
        """Discard terminal results and the staged private wordlist."""

        with self._lock:
            if (self._job is not None and self._job.active) or self._pending_upload:
                raise AuditInvalidTransition("AUDIT_STILL_RUNNING")
            wordlist = self._wordlist
            self._job = None
            self._wordlist = None
            self.worker = None
        if wordlist is not None:
            _discard_private_file(wordlist.path)

    def close(self) -> None:
        """Release private temporary storage after all work has stopped."""

        with self._lock:
            if (self._job is not None and self._job.active) or self._pending_upload:
                raise AuditInvalidTransition("AUDIT_STILL_RUNNING")
            self._wordlist = None
        self._wordlist_directory.cleanup()

    def _run(
        self,
        job_id: str,
        runner: AuditToolRunner,
        request: AuditRunRequest,
        cancellation: Event,
    ) -> None:
        try:
            result = runner.run(request, cancellation)
        except Exception:
            result = AuditRunResult(
                AuditRunOutcome.FAILED,
                error_code="TOOL_EXECUTION_FAILED",
            )
        status = AuditJobStatus(result.outcome.value)
        if cancellation.is_set() and status is not AuditJobStatus.CRACKED:
            status = AuditJobStatus.CANCELLED
            result = AuditRunResult(AuditRunOutcome.CANCELLED)
        with self._lock:
            if self._job is None or self._job.job_id != job_id:
                return
            self._job = replace(
                self._job,
                status=status,
                finished_at=datetime.now(UTC),
                plaintext=result.plaintext,
                error_code=result.error_code,
            )
            self._cancellation = None

class _ExecutableRunner:
    tool_id: str
    display_name: str
    executable_name: str

class HashcatRunner(_ExecutableRunner):
    tool_id = "hashcat"
    display_name = "Hashcat"
    executable_name = "hashcat"

    def __init__(self) -> None:
        self._availability_lock = Lock()
        self._cached_availability: AuditToolAvailability | None = None

    def availability(self) -> AuditToolAvailability:
        with self._availability_lock:
            if self._cached_availability is not None:
                return self._cached_availability
            executable = shutil.which(self.executable_name)
            if executable is None:
                availability = AuditToolAvailability(
                    self.tool_id,
                    self.display_name,
                    False,
                    "not_installed",
                )
            else:
                backend_available = _hashcat_backend_available(executable)
                catalog = (
                    _hashcat_format_catalog(executable) if backend_available else None
                )
                supported_formats = _supported_formats("hashcat", catalog)
                available = backend_available and catalog is not None and bool(
                    supported_formats
                )
                reason = None
                if not backend_available:
                    reason = "backend_unavailable"
                elif catalog is None:
                    reason = "format_catalog_unavailable"
                elif not supported_formats:
                    reason = "no_supported_formats"
                availability = AuditToolAvailability(
                    self.tool_id,
                    self.display_name,
                    available,
                    reason,
                    supported_formats,
                    executable if available else None,
                )
            self._cached_availability = availability
            return availability

    def run(self, request: AuditRunRequest, cancellation: Event) -> AuditRunResult:
        if request.binding.tool_id != self.tool_id:
            return AuditRunResult(AuditRunOutcome.FAILED, error_code="FORMAT_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="nordis-hashcat-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            hash_path = root / "target.hash"
            result_path = root / "recovered.txt"
            _write_private(hash_path, request.material.encode("utf-8") + b"\n")
            environment = _hashcat_environment(root)
            command = (
                request.executable_path,
                "--hash-type",
                request.binding.format_name,
                "--attack-mode",
                "0",
                "--quiet",
                "--potfile-disable",
                "--restore-disable",
                "--logfile-disable",
                "--wordlist-autohex-disable",
                "--outfile-autohex-disable",
                "--workload-profile",
                "1",
                "--runtime",
                str(request.runtime_seconds),
                "--outfile",
                str(result_path),
                "--outfile-format",
                "2",
                str(hash_path),
                str(request.wordlist_path),
            )
            process_result = _run_process(
                command,
                cwd=root,
                environment=environment,
                cancellation=cancellation,
                runtime_seconds=request.runtime_seconds,
            )
            if process_result.cancelled:
                return AuditRunResult(AuditRunOutcome.CANCELLED)
            plaintext = _read_hashcat_result(result_path)
            if plaintext is not None:
                return AuditRunResult(AuditRunOutcome.CRACKED, plaintext=plaintext)
            if process_result.timed_out or process_result.return_code in {2, 3, 4}:
                return AuditRunResult(AuditRunOutcome.TIMED_OUT)
            if process_result.return_code == 1:
                return AuditRunResult(AuditRunOutcome.EXHAUSTED)
            return AuditRunResult(
                AuditRunOutcome.FAILED,
                error_code="HASHCAT_FAILED",
            )


class JohnRunner(_ExecutableRunner):
    tool_id = "john"
    display_name = "John the Ripper"
    executable_name = "john"

    def __init__(self) -> None:
        self._availability_lock = Lock()
        self._cached_availability: AuditToolAvailability | None = None

    def availability(self) -> AuditToolAvailability:
        with self._availability_lock:
            if self._cached_availability is not None:
                return self._cached_availability
            executable = shutil.which(self.executable_name)
            if executable is None:
                availability = AuditToolAvailability(
                    self.tool_id,
                    self.display_name,
                    False,
                    "not_installed",
                )
            else:
                catalog = _john_format_catalog(executable)
                supported_formats = _supported_formats("john", catalog)
                available = catalog is not None and bool(supported_formats)
                reason = None
                if catalog is None:
                    reason = "initialization_failed"
                elif not supported_formats:
                    reason = "no_supported_formats"
                availability = AuditToolAvailability(
                    self.tool_id,
                    self.display_name,
                    available,
                    reason,
                    supported_formats,
                    executable if available else None,
                )
            self._cached_availability = availability
            return availability

    def run(self, request: AuditRunRequest, cancellation: Event) -> AuditRunResult:
        if request.binding.tool_id != self.tool_id:
            return AuditRunResult(AuditRunOutcome.FAILED, error_code="FORMAT_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="nordis-john-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            hash_path = root / "target.hash"
            pot_path = root / "audit.pot"
            session_path = root / "audit-session"
            john_material = _john_material(request.binding, request.material)
            _write_private(hash_path, john_material.encode("utf-8") + b"\n")
            environment = _john_environment(root)
            command = (
                request.executable_path,
                f"--format={request.binding.format_name}",
                f"--wordlist={request.wordlist_path}",
                f"--pot={pot_path}",
                f"--session={session_path}",
                f"--max-run-time={request.runtime_seconds}",
                "--nolog",
                "--verbosity=1",
                str(hash_path),
            )
            process_result = _run_process(
                command,
                cwd=root,
                environment=environment,
                cancellation=cancellation,
                runtime_seconds=request.runtime_seconds,
            )
            if process_result.cancelled:
                return AuditRunResult(AuditRunOutcome.CANCELLED)
            plaintext = _read_john_result(pot_path, john_material)
            if plaintext is not None:
                return AuditRunResult(AuditRunOutcome.CRACKED, plaintext=plaintext)
            if process_result.timed_out:
                return AuditRunResult(AuditRunOutcome.TIMED_OUT)
            if process_result.return_code in {0, 1}:
                return AuditRunResult(AuditRunOutcome.EXHAUSTED)
            return AuditRunResult(
                AuditRunOutcome.FAILED,
                error_code="JOHN_FAILED",
            )


@dataclass(frozen=True, slots=True)
class _ProcessResult:
    return_code: int
    cancelled: bool = False
    timed_out: bool = False


def _hashcat_backend_available(executable_path: str) -> bool:
    try:
        with tempfile.TemporaryDirectory(prefix="nordis-hashcat-check-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            result = subprocess.run(  # noqa: S603 - fixed executable and flag
                (executable_path, "--backend-info"),
                cwd=root,
                env=_hashcat_environment(root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                timeout=5,
                check=False,
                umask=0o077,
            )
            return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _hashcat_format_catalog(executable_path: str) -> frozenset[str] | None:
    try:
        with tempfile.TemporaryDirectory(prefix="nordis-hashcat-formats-") as directory:
            root = Path(directory)
            result = subprocess.run(  # noqa: S603 - fixed executable and flag
                (executable_path, "-hh"),
                cwd=root,
                env=_hashcat_environment(root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                timeout=5,
                check=False,
                umask=0o077,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0:
                return None
            formats = frozenset(
                match.group(1)
                for match in re.finditer(
                    r"(?m)^\s*([0-9]+)\s+\|",
                    result.stdout,
                )
            )
            return formats or None
    except (OSError, subprocess.SubprocessError):
        return None


def _john_format_catalog(executable_path: str) -> frozenset[str] | None:
    try:
        with tempfile.TemporaryDirectory(prefix="nordis-john-check-") as directory:
            root = Path(directory)
            result = subprocess.run(  # noqa: S603 - fixed executable and flag
                (executable_path, "--list=formats"),
                cwd=root,
                env=_john_environment(root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                timeout=5,
                check=False,
                umask=0o077,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0:
                return None
            formats = frozenset(
                value.casefold()
                for value in re.split(r"[,\s]+", result.stdout)
                if value
            )
            return formats or None
    except (OSError, subprocess.SubprocessError):
        return None


def _supported_formats(
    tool_id: str,
    catalog: frozenset[str] | None,
) -> tuple[str, ...]:
    if catalog is None:
        return ()
    return tuple(
        sorted(
            format_name
            for format_name in audit_tool_formats(tool_id)
            if format_name.casefold() in catalog
        )
    )


def _hashcat_environment(root: Path) -> dict[str, str]:
    data_home = root / "data"
    cache_home = root / "cache"
    config_home = root / "config"
    (data_home / "hashcat" / "sessions").mkdir(parents=True, mode=0o700)
    cache_home.mkdir(mode=0o700)
    config_home.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment.update(
        {
            "XDG_DATA_HOME": str(data_home),
            "XDG_CACHE_HOME": str(cache_home),
            "XDG_CONFIG_HOME": str(config_home),
        }
    )
    return environment


def _john_environment(root: Path) -> dict[str, str]:
    private_home = root / "home"
    private_home.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(private_home),
            "XDG_CACHE_HOME": str(private_home / ".cache"),
            "XDG_CONFIG_HOME": str(private_home / ".config"),
            "XDG_DATA_HOME": str(private_home / ".local" / "share"),
            "OMP_NUM_THREADS": "2",
        }
    )
    return environment


def _john_material(binding: AuditToolBinding, material: str) -> str:
    prefixes = {"nt": "$NT$", "lm": "$LM$"}
    prefix = prefixes.get(binding.format_name)
    if prefix is None or material.startswith(prefix):
        return material
    return f"{prefix}{material}"


def _run_process(
    command: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    cancellation: Event,
    runtime_seconds: int,
) -> _ProcessResult:
    started = monotonic()
    process = subprocess.Popen(  # noqa: S603 - executable and arguments are allow-listed
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        umask=0o077,
    )
    while True:
        return_code = process.poll()
        if return_code is not None:
            return _ProcessResult(return_code)
        if cancellation.wait(0.1):
            _stop_process(process)
            return _ProcessResult(process.returncode or -1, cancelled=True)
        if monotonic() - started > runtime_seconds + _PROCESS_GRACE_SECONDS:
            _stop_process(process)
            return _ProcessResult(process.returncode or -1, timed_out=True)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=_TERMINATE_GRACE_SECONDS)


def _write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(content)


def create_private_upload_file(path: Path) -> None:
    """Create an empty upload target with owner-only permissions."""

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)


def _discard_private_file(path: Path) -> None:
    with suppress(OSError):
        path.unlink()


def _bounded_file_lines(path: Path) -> tuple[bytes, ...]:
    try:
        if path.stat().st_size > _MAX_RESULT_FILE_BYTES:
            return ()
        return tuple(path.read_bytes().splitlines())
    except OSError:
        return ()


def _display_plaintext(value: bytes) -> str | None:
    if not value or len(value) > MAX_WORDLIST_LINE_BYTES:
        return None
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1")


def _read_hashcat_result(path: Path) -> str | None:
    for line in _bounded_file_lines(path):
        plaintext = _display_plaintext(line)
        if plaintext is not None:
            return plaintext
    return None


def _read_john_result(path: Path, material: str) -> str | None:
    prefix = material.encode("utf-8") + b":"
    for line in _bounded_file_lines(path):
        if line.startswith(prefix):
            return _display_plaintext(line[len(prefix) :])
    return None
