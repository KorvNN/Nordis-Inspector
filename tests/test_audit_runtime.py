from __future__ import annotations

import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from nordis_smb_inspector.core.credential_audit import classify_audit_material
from nordis_smb_inspector.web.audit import (
    MAX_WORDLIST_UPLOAD_BYTES,
    AuditAlreadyRunning,
    AuditInvalidTransition,
    AuditJobStatus,
    AuditRequestError,
    AuditRunOutcome,
    AuditRunRequest,
    AuditRunResult,
    AuditToolAvailability,
    AuditToolUnavailable,
    CredentialAuditManager,
    JohnRunner,
    WordlistUploadValidator,
    create_private_upload_file,
)


class _FakeRunner:
    tool_id = "hashcat"
    display_name = "Hashcat"

    def __init__(
        self,
        *,
        available: bool = True,
        result: AuditRunResult | None = None,
        gate: threading.Event | None = None,
    ) -> None:
        self.available = available
        self.result = result or AuditRunResult(AuditRunOutcome.EXHAUSTED)
        self.gate = gate
        self.request: AuditRunRequest | None = None

    def availability(self) -> AuditToolAvailability:
        return AuditToolAvailability(
            tool_id=self.tool_id,
            display_name=self.display_name,
            available=self.available,
            reason=None if self.available else "not_installed",
            executable_path="/test/hashcat" if self.available else None,
        )

    def run(self, request: AuditRunRequest, cancellation: threading.Event) -> AuditRunResult:
        self.request = request
        if self.gate is not None:
            while not self.gate.wait(0.01):
                if cancellation.is_set():
                    return AuditRunResult(AuditRunOutcome.CANCELLED)
        return self.result


def _nt_material():
    return classify_audit_material(
        "windows-nt-hash",
        "NTLM: 8846f7eaee8fb117ad06bdd830b7586c",
    )[0]


def _stage_wordlist(manager: CredentialAuditManager, content: bytes) -> str:
    handle = manager.begin_wordlist_upload()
    create_private_upload_file(handle.path)
    handle.path.write_bytes(content)
    entries = sum(bool(line.rstrip(b"\r")) for line in content.split(b"\n"))
    uploaded = manager.complete_wordlist_upload(
        handle,
        size_bytes=len(content),
        entry_count=entries,
    )
    return uploaded.upload_id


class WordlistValidationTests(unittest.TestCase):
    def test_accepts_rockyou_scale_uploads(self) -> None:
        self.assertEqual(MAX_WORDLIST_UPLOAD_BYTES, 256 * 1024 * 1024)

    def test_validates_chunked_wordlists_without_loading_the_file(self) -> None:
        validator = WordlistUploadValidator()
        validator.consume(b"first\r\n two")
        validator.consume(b" words \n\nthird")

        self.assertEqual((25, 3), validator.finish())

    def test_rejects_empty_and_oversized_wordlists(self) -> None:
        empty = WordlistUploadValidator()
        empty.consume(b"\n\r\n")
        with self.assertRaisesRegex(AuditRequestError, "ENTRY_COUNT"):
            empty.finish()

        oversized = WordlistUploadValidator()
        with (
            patch("nordis_smb_inspector.web.audit.MAX_WORDLIST_UPLOAD_BYTES", 4),
            self.assertRaisesRegex(AuditRequestError, "WORDLIST_TOO_LARGE"),
        ):
            oversized.consume(b"12345")

    def test_rejects_an_oversized_candidate_line(self) -> None:
        validator = WordlistUploadValidator()
        with (
            patch("nordis_smb_inspector.web.audit.MAX_WORDLIST_LINE_BYTES", 4),
            self.assertRaisesRegex(AuditRequestError, "WORDLIST_LINE_TOO_LONG"),
        ):
            validator.consume(b"12345")


class ToolAvailabilityTests(unittest.TestCase):
    def test_john_probe_uses_private_runtime_directories(self) -> None:
        with (
            patch(
                "nordis_smb_inspector.web.audit.shutil.which",
                return_value="/usr/bin/john",
            ),
            patch("nordis_smb_inspector.web.audit.subprocess.run") as run,
        ):
            run.return_value.returncode = 0

            availability = JohnRunner().availability()

        self.assertTrue(availability.available)
        environment = run.call_args.kwargs["env"]
        self.assertIn("nordis-john-check-", environment["HOME"])
        self.assertNotEqual(environment["HOME"], str(Path.home()))


class CredentialAuditManagerTests(unittest.TestCase):
    def test_reports_tools_and_retains_only_a_redacted_in_memory_result(self) -> None:
        known_plaintext = "Password1!"
        runner = _FakeRunner(
            result=AuditRunResult(AuditRunOutcome.CRACKED, plaintext=known_plaintext)
        )
        manager = CredentialAuditManager((runner,))
        self.addCleanup(manager.close)
        upload_id = _stage_wordlist(manager, f"wrong\n{known_plaintext}".encode())

        tool = manager.tools()[0]
        started = manager.start(
            material=_nt_material(),
            tool_id="hashcat",
            wordlist_upload_id=upload_id,
            runtime_seconds=30,
        )
        manager.worker.join(timeout=1)
        finished = manager.snapshot

        self.assertTrue(tool.available)
        self.assertNotIn("/test/hashcat", str(tool.public_payload()))
        self.assertEqual(AuditJobStatus.RUNNING, started.status)
        self.assertEqual(AuditJobStatus.CRACKED, finished.status)
        self.assertEqual(_nt_material().candidate_id, finished.candidate_id)
        self.assertEqual(known_plaintext, finished.plaintext)
        self.assertNotIn(known_plaintext, repr(finished))
        self.assertNotIn("8846f7eaee8fb117ad06bdd830b7586c", repr(runner.request))

    def test_prevents_parallel_jobs_and_supports_cancellation(self) -> None:
        gate = threading.Event()
        runner = _FakeRunner(gate=gate)
        manager = CredentialAuditManager((runner,))
        self.addCleanup(manager.close)
        upload_id = _stage_wordlist(manager, b"candidate\n")
        manager.start(
            material=_nt_material(),
            tool_id="hashcat",
            wordlist_upload_id=upload_id,
            runtime_seconds=30,
        )

        with self.assertRaises(AuditAlreadyRunning):
            manager.start(
                material=_nt_material(),
                tool_id="hashcat",
                wordlist_upload_id=upload_id,
                runtime_seconds=30,
            )
        cancelling = manager.cancel()
        manager.worker.join(timeout=1)

        self.assertEqual(AuditJobStatus.CANCELLING, cancelling.status)
        self.assertEqual(AuditJobStatus.CANCELLED, manager.snapshot.status)
        with self.assertRaises(AuditInvalidTransition):
            manager.cancel()

    def test_rejects_unavailable_incompatible_and_invalid_requests(self) -> None:
        unavailable = CredentialAuditManager((_FakeRunner(available=False),))
        self.addCleanup(unavailable.close)
        with self.assertRaises(AuditToolUnavailable):
            unavailable.start(
                material=_nt_material(),
                tool_id="hashcat",
                wordlist_upload_id="missing",
                runtime_seconds=30,
            )

        available = CredentialAuditManager((_FakeRunner(),))
        self.addCleanup(available.close)
        for tool_id, runtime in (("john", 30), ("hashcat", 31)):
            with self.subTest(tool_id=tool_id, runtime=runtime), self.assertRaises(
                AuditRequestError
            ):
                available.start(
                    material=_nt_material(),
                    tool_id=tool_id,
                    wordlist_upload_id="missing",
                    runtime_seconds=runtime,
                )


if __name__ == "__main__":
    unittest.main()
