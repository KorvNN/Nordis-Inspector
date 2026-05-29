from __future__ import annotations

import threading
import unittest

from nordis_smb_inspector.core.credential_audit import classify_audit_material
from nordis_smb_inspector.web.audit import (
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
    normalize_wordlist,
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
            self.tool_id,
            self.display_name,
            self.available,
            "/test/hashcat" if self.available else None,
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


class WordlistValidationTests(unittest.TestCase):
    def test_normalizes_line_endings_without_trimming_candidates(self) -> None:
        payload, entries = normalize_wordlist("first\r\n two words \n\nthird")

        self.assertEqual(b"first\n two words \nthird\n", payload)
        self.assertEqual((b"first", b" two words ", b"third"), entries)

    def test_rejects_empty_oversized_and_nul_wordlists(self) -> None:
        values = ("", "\n\n", "contains\x00nul", "x" * (512 * 1024 + 1))

        for value in values:
            with self.subTest(length=len(value)), self.assertRaises(AuditRequestError):
                normalize_wordlist(value)

    def test_rejects_an_oversized_candidate_line(self) -> None:
        with self.assertRaisesRegex(AuditRequestError, "WORDLIST_LINE_TOO_LONG"):
            normalize_wordlist("x" * 4097)


class CredentialAuditManagerTests(unittest.TestCase):
    def test_reports_tools_and_retains_only_a_redacted_in_memory_result(self) -> None:
        known_plaintext = "Password1!"
        runner = _FakeRunner(
            result=AuditRunResult(AuditRunOutcome.CRACKED, plaintext=known_plaintext)
        )
        manager = CredentialAuditManager((runner,))

        tool = manager.tools()[0]
        started = manager.start(
            material=_nt_material(),
            tool_id="hashcat",
            wordlist_text=f"wrong\n{known_plaintext}",
            runtime_seconds=30,
        )
        manager.worker.join(timeout=1)
        finished = manager.snapshot

        self.assertTrue(tool.available)
        self.assertNotIn("/test/hashcat", str(tool.public_payload()))
        self.assertEqual(AuditJobStatus.RUNNING, started.status)
        self.assertEqual(AuditJobStatus.CRACKED, finished.status)
        self.assertEqual(known_plaintext, finished.plaintext)
        self.assertNotIn(known_plaintext, repr(finished))
        self.assertNotIn("8846f7eaee8fb117ad06bdd830b7586c", repr(runner.request))

    def test_prevents_parallel_jobs_and_supports_cancellation(self) -> None:
        gate = threading.Event()
        runner = _FakeRunner(gate=gate)
        manager = CredentialAuditManager((runner,))
        manager.start(
            material=_nt_material(),
            tool_id="hashcat",
            wordlist_text="candidate",
            runtime_seconds=30,
        )

        with self.assertRaises(AuditAlreadyRunning):
            manager.start(
                material=_nt_material(),
                tool_id="hashcat",
                wordlist_text="candidate",
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
        with self.assertRaises(AuditToolUnavailable):
            unavailable.start(
                material=_nt_material(),
                tool_id="hashcat",
                wordlist_text="candidate",
                runtime_seconds=30,
            )

        available = CredentialAuditManager((_FakeRunner(),))
        for tool_id, runtime in (("john", 30), ("hashcat", 31)):
            with self.subTest(tool_id=tool_id, runtime=runtime), self.assertRaises(
                AuditRequestError
            ):
                available.start(
                    material=_nt_material(),
                    tool_id=tool_id,
                    wordlist_text="candidate",
                    runtime_seconds=runtime,
                )


if __name__ == "__main__":
    unittest.main()
