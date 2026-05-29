"""Memory-only orchestration for local, allow-listed password-audit tools."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Event, RLock, Thread
from time import monotonic
from typing import Protocol
from uuid import uuid4

from nordis_smb_inspector.core.credential_audit import AuditMaterial, AuditToolBinding

_MAX_WORDLIST_BYTES = 512 * 1024
_MAX_WORDLIST_LINE_BYTES = 4096
_MAX_WORDLIST_ENTRIES = 100_000
_ALLOWED_RUNTIME_SECONDS = frozenset({30, 120, 300})
_PROCESS_GRACE_SECONDS = 5
_TERMINATE_GRACE_SECONDS = 2
_MAX_RESULT_FILE_BYTES = _MAX_WORDLIST_BYTES + _MAX_WORDLIST_ENTRIES


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
    executable_path: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(tool_id={self.tool_id!r}, "
            f"display_name={self.display_name!r}, available={self.available!r}, "
            "executable_path=<redacted>)"
        )

    def public_payload(self) -> dict[str, object]:
        return {
            "id": self.tool_id,
            "name": self.display_name,
            "available": self.available,
        }


@dataclass(frozen=True, slots=True, repr=False)
class AuditRunRequest:
    executable_path: str = field(repr=False)
    binding: AuditToolBinding
    material: str = field(repr=False)
    wordlist: bytes = field(repr=False)
    wordlist_entries: tuple[bytes, ...] = field(repr=False)
    runtime_seconds: int

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(executable_path=<redacted>, "
            f"binding={self.binding!r}, material=<redacted>, wordlist=<redacted>, "
            f"wordlist_entries={len(self.wordlist_entries)!r}, "
            f"runtime_seconds={self.runtime_seconds!r})"
        )


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
            f"tool_id={self.tool_id!r}, format_id={self.format_id!r}, "
            f"variant={self.variant!r}, status={self.status.value!r}, "
            f"runtime_seconds={self.runtime_seconds!r}, "
            f"started_at={self.started_at!r}, finished_at={self.finished_at!r}, "
            f"plaintext={'<redacted>' if self.plaintext is not None else None}, "
            f"error_code={self.error_code!r})"
        )

    def public_payload(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
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
        self.worker: Thread | None = None

    @property
    def snapshot(self) -> AuditJobSnapshot | None:
        with self._lock:
            return self._job

    @property
    def active(self) -> bool:
        current = self.snapshot
        return current is not None and current.active

    def tools(self) -> tuple[AuditToolAvailability, ...]:
        return tuple(runner.availability() for runner in self._runners.values())

    def start(
        self,
        *,
        material: AuditMaterial,
        tool_id: object,
        wordlist_text: object,
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
        wordlist, entries = normalize_wordlist(wordlist_text)
        binding = material.binding_for(tool_id)
        if binding is None:
            raise AuditRequestError("INCOMPATIBLE_TOOL")
        runner = self._runners.get(tool_id)
        if runner is None:
            raise AuditRequestError("INVALID_TOOL")
        availability = runner.availability()
        if not availability.available or availability.executable_path is None:
            raise AuditToolUnavailable("TOOL_UNAVAILABLE")

        request = AuditRunRequest(
            executable_path=availability.executable_path,
            binding=binding,
            material=material.material,
            wordlist=wordlist,
            wordlist_entries=entries,
            runtime_seconds=runtime_seconds,
        )
        now = datetime.now(UTC)
        with self._lock:
            if self._job is not None and self._job.active:
                raise AuditAlreadyRunning("AUDIT_ALREADY_RUNNING")
            job = AuditJobSnapshot(
                job_id=str(uuid4()),
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
        """Discard a terminal result, including any recovered plaintext."""

        with self._lock:
            if self._job is not None and self._job.active:
                raise AuditInvalidTransition("AUDIT_STILL_RUNNING")
            self._job = None
            self.worker = None

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


def normalize_wordlist(value: object) -> tuple[bytes, tuple[bytes, ...]]:
    """Validate a UTF-8 browser wordlist and preserve each candidate exactly."""

    if not isinstance(value, str):
        raise AuditRequestError("INVALID_WORDLIST")
    if "\x00" in value:
        raise AuditRequestError("INVALID_WORDLIST")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AuditRequestError("INVALID_WORDLIST") from exc
    if not encoded or len(encoded) > _MAX_WORDLIST_BYTES:
        raise AuditRequestError("WORDLIST_SIZE_INVALID")

    entries = tuple(line.removesuffix(b"\r") for line in encoded.split(b"\n"))
    entries = tuple(line for line in entries if line)
    if not entries or len(entries) > _MAX_WORDLIST_ENTRIES:
        raise AuditRequestError("WORDLIST_ENTRY_COUNT_INVALID")
    if any(len(line) > _MAX_WORDLIST_LINE_BYTES for line in entries):
        raise AuditRequestError("WORDLIST_LINE_TOO_LONG")
    return b"\n".join(entries) + b"\n", entries


class _ExecutableRunner:
    tool_id: str
    display_name: str
    executable_name: str

    def availability(self) -> AuditToolAvailability:
        executable = shutil.which(self.executable_name)
        return AuditToolAvailability(
            tool_id=self.tool_id,
            display_name=self.display_name,
            available=executable is not None,
            executable_path=executable,
        )


class HashcatRunner(_ExecutableRunner):
    tool_id = "hashcat"
    display_name = "Hashcat"
    executable_name = "hashcat"

    def run(self, request: AuditRunRequest, cancellation: Event) -> AuditRunResult:
        if request.binding.tool_id != self.tool_id:
            return AuditRunResult(AuditRunOutcome.FAILED, error_code="FORMAT_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="nordis-hashcat-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            hash_path = root / "target.hash"
            wordlist_path = root / "candidates.txt"
            result_path = root / "recovered.txt"
            _write_private(hash_path, request.material.encode("utf-8") + b"\n")
            _write_private(wordlist_path, request.wordlist)
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
                str(wordlist_path),
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
            plaintext = _read_hashcat_result(result_path, request.wordlist_entries)
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

    def run(self, request: AuditRunRequest, cancellation: Event) -> AuditRunResult:
        if request.binding.tool_id != self.tool_id:
            return AuditRunResult(AuditRunOutcome.FAILED, error_code="FORMAT_MISMATCH")
        with tempfile.TemporaryDirectory(prefix="nordis-john-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            hash_path = root / "target.hash"
            wordlist_path = root / "candidates.txt"
            pot_path = root / "audit.pot"
            session_path = root / "audit-session"
            _write_private(hash_path, request.material.encode("utf-8") + b"\n")
            _write_private(wordlist_path, request.wordlist)
            environment = os.environ.copy()
            environment["OMP_NUM_THREADS"] = "2"
            command = (
                request.executable_path,
                f"--format={request.binding.format_name}",
                f"--wordlist={wordlist_path}",
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
            plaintext = _read_john_result(pot_path, request.wordlist_entries)
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


def _bounded_file_lines(path: Path) -> tuple[bytes, ...]:
    try:
        if path.stat().st_size > _MAX_RESULT_FILE_BYTES:
            return ()
        return tuple(path.read_bytes().splitlines())
    except OSError:
        return ()


def _read_hashcat_result(path: Path, candidates: tuple[bytes, ...]) -> str | None:
    allowed = frozenset(candidates)
    for line in _bounded_file_lines(path):
        if line in allowed:
            try:
                return line.decode("utf-8")
            except UnicodeDecodeError:
                return None
    return None


def _read_john_result(path: Path, candidates: tuple[bytes, ...]) -> str | None:
    by_length = sorted(candidates, key=len, reverse=True)
    for line in _bounded_file_lines(path):
        for candidate in by_length:
            if line.endswith(b":" + candidate):
                try:
                    return candidate.decode("utf-8")
                except UnicodeDecodeError:
                    return None
    return None
