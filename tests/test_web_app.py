from __future__ import annotations

import base64
import errno
import json
import tempfile
import threading
import unittest
from pathlib import Path

import httpx

from nordis_smb_inspector.core.credentials import AuthMode, Credential, CredentialKind
from nordis_smb_inspector.core.detection import DetectionConfidence
from nordis_smb_inspector.core.wordlist_store import WordlistStore
from nordis_smb_inspector.smb.inspection import (
    ContentFinding,
    FindingMethod,
    InspectionEventKind,
    InspectionResult,
    InspectionTargetEvent,
)
from nordis_smb_inspector.smb.models import (
    AuthAttempt,
    AuthAttemptOutcome,
    AuthenticationHistory,
    AuthMechanism,
    InventoryEntry,
    InventoryEntryKind,
    InventoryStatus,
    NegotiationInfo,
    SecurityFeatureState,
    SmbDialect,
    SmbErrorDetail,
    TargetOutcome,
    TargetStage,
    TargetStatus,
    TransportSecurity,
)
from nordis_smb_inspector.web.app import create_app
from nordis_smb_inspector.web.audit import (
    AuditRunOutcome,
    AuditRunRequest,
    AuditRunResult,
    AuditToolAvailability,
    CredentialAuditManager,
)

_PASSWORD = "CorrectHorseBatteryStaple!"
_NT_HASH = "0123456789ABCDEF0123456789ABCDEF"
_CCACHE = b"\x05\x04nordis-test-ccache"
_FOUND_NT_HASH = "8846f7eaee8fb117ad06bdd830b7586c"
_RECOVERED_PLAINTEXT = "Password1!"


def _credential_payload(
    *,
    kind: str = "password",
    secret: str = _PASSWORD,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "kind": kind,
        "domain": "NORDIS",
        "username": "alice",
        "auth_mode": "ntlm_only" if kind == "nt_hash" else "auto",
    }
    payload["nt_hash" if kind == "nt_hash" else "password"] = secret
    return payload


def _scan_payload(
    targets: str,
    *,
    credential: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "targets": targets,
        "credential": credential or _credential_payload(),
        "search": {"use_default": True, "additional_terms": []},
    }


def _negotiation() -> NegotiationInfo:
    return NegotiationInfo(
        dialect=SmbDialect.SMB_3_1_1,
        security=TransportSecurity(
            signing=SecurityFeatureState(
                supported=True,
                required=False,
                active=None,
            ),
            encryption=SecurityFeatureState(
                supported=True,
                required=None,
                active=None,
            ),
        ),
        max_read_size=1_048_576,
    )


def _completed_result(
    target: str,
    mechanism: AuthMechanism = AuthMechanism.NTLM,
) -> InspectionResult:
    negotiation = _negotiation()
    authentication = AuthenticationHistory(
        attempts=(
            AuthAttempt(
                mechanism=mechanism,
                outcome=AuthAttemptOutcome.SUCCEEDED,
            ),
        ),
        selected_mechanism=mechanism,
    )
    return InspectionResult(
        target=target,
        outcome=TargetOutcome(
            target=target,
            stage=TargetStage.COMPLETE,
            status=TargetStatus.COMPLETED,
        ),
        negotiation=negotiation,
        authentication=authentication,
        shares_probed=1,
        shares_accessible=1,
        inventory_items=1,
        files_seen=1,
        files_scanned=1,
        findings=1,
    )


def _connect_failure_result(target: str, status: TargetStatus) -> InspectionResult:
    raw_code = {
        TargetStatus.CONNECTION_REFUSED: errno.ECONNREFUSED,
        TargetStatus.TIMEOUT_NO_RESPONSE: errno.ETIMEDOUT,
    }[status]
    error = SmbErrorDetail(
        stage=TargetStage.NETWORK,
        status=status,
        operation="connect",
        raw_code=raw_code,
        symbolic_name=errno.errorcode[raw_code],
        safe_message="Normalized network failure.",
        retryable=status is TargetStatus.TIMEOUT_NO_RESPONSE,
        target=target,
    )
    outcome = TargetOutcome(
        target=target,
        stage=TargetStage.NETWORK,
        status=status,
        error=error,
    )
    return InspectionResult(
        target=target,
        outcome=outcome,
    )


def _share_enum_failure_result(target: str) -> InspectionResult:
    authenticated = _completed_result(target)
    error = SmbErrorDetail(
        stage=TargetStage.SHARE_ENUMERATION,
        status=TargetStatus.SHARE_ENUM_DENIED,
        operation="srvsvc_netr_share_enum",
        raw_code=0xC0000022,
        symbolic_name="SHARE_ENUM_ACCESS_DENIED",
        safe_message="Share listesi alınamadı.",
        target=target,
    )
    return InspectionResult(
        target=target,
        outcome=TargetOutcome(
            target=target,
            stage=TargetStage.SHARE_ENUMERATION,
            status=TargetStatus.SHARE_ENUM_DENIED,
            error=error,
        ),
        negotiation=authenticated.negotiation,
        authentication=authenticated.authentication,
    )


class _FakeAccessInspector:
    """No-network target workflow with sanitized observations for assertions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.observations: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> InspectionResult:
        target = kwargs["target"]
        credential = kwargs["credential"]
        on_target = kwargs.get("on_target")
        on_inventory = kwargs.get("on_inventory")
        on_finding = kwargs.get("on_finding")
        if not isinstance(target, str):
            raise TypeError("fake target must be text")
        if not isinstance(credential, Credential):
            raise TypeError("fake credential must be validated")
        if target.endswith(".9"):
            raise RuntimeError("DoNotLeakWorkerException")

        expected_secret: str | bytes = {
            CredentialKind.PASSWORD: _PASSWORD,
            CredentialKind.NT_HASH: _NT_HASH.casefold(),
            CredentialKind.CCACHE: _CCACHE,
        }[credential.kind]
        supplied_secret: str | bytes | None = {
            CredentialKind.PASSWORD: credential.password,
            CredentialKind.NT_HASH: credential.nt_hash,
            CredentialKind.CCACHE: credential.ccache_data,
        }[credential.kind]
        with self._lock:
            self.observations.append(
                {
                    "target": target,
                    "kind": credential.kind,
                    "auth_mode": credential.auth_mode,
                    "domain": credential.domain,
                    "username": credential.username,
                    "secret_was_correct": supplied_secret == expected_secret,
                    "max_depth": kwargs["max_depth"],
                    "detect_patterns": kwargs["detect_patterns"],
                    "has_search_terms": bool(kwargs["search_terms"]),
                }
            )

        if target.endswith(".1"):
            mechanism = (
                AuthMechanism.KERBEROS
                if credential.kind is CredentialKind.CCACHE
                else AuthMechanism.NTLM
            )
            result = _completed_result(target, mechanism)
            if callable(on_inventory):
                on_inventory(
                    InventoryEntry(
                        target=target,
                        share_name="Shared",
                        relative_path="config.txt",
                        kind=InventoryEntryKind.FILE,
                        status=InventoryStatus.FILE_READABLE,
                        size=19,
                    )
                )
            if callable(on_finding):
                on_finding(
                    ContentFinding(
                        target=target,
                        share="Shared",
                        path="config.txt",
                        line_number=2,
                        term="password",
                        full_line="password=lab-value",
                    )
                )
        elif target.endswith(".2"):
            result = _connect_failure_result(target, TargetStatus.CONNECTION_REFUSED)
        elif target.endswith(".5"):
            result = _completed_result(target)
            if callable(on_finding):
                on_finding(
                    ContentFinding(
                        target=target,
                        share="Shared",
                        path="tickets/admin.ccache",
                        line_number=None,
                        term="Kerberos credential cache",
                        full_line=None,
                        method=FindingMethod.ARTIFACT,
                        rule_id="kerberos-ccache-file",
                        category="Windows / AD",
                        confidence=DetectionConfidence.HIGH,
                    )
                )
        elif target.endswith(".6"):
            result = _completed_result(target)
            if callable(on_finding):
                on_finding(
                    ContentFinding(
                        target=target,
                        share="Shared",
                        path="exports/domain-hashes.txt",
                        line_number=4,
                        term="Etiketli NTLM hash",
                        full_line=f"NTLM: {_FOUND_NT_HASH}",
                        method=FindingMethod.PATTERN,
                        rule_id="windows-nt-hash",
                        category="Windows / AD",
                        confidence=DetectionConfidence.HIGH,
                    )
                )
        elif target.endswith(".4"):
            result = _share_enum_failure_result(target)
        else:
            result = _connect_failure_result(target, TargetStatus.TIMEOUT_NO_RESPONSE)

        if callable(on_target):
            if result.negotiation is not None:
                on_target(
                    InspectionTargetEvent(
                        kind=InspectionEventKind.NEGOTIATED,
                        target=target,
                        stage=TargetStage.NEGOTIATION,
                        negotiation=result.negotiation,
                    )
                )
                on_target(
                    InspectionTargetEvent(
                        kind=InspectionEventKind.AUTHENTICATED,
                        target=target,
                        stage=TargetStage.AUTHENTICATION,
                        status=TargetStatus.AUTHENTICATED,
                        negotiation=result.negotiation,
                        authentication=result.authentication,
                    )
                )
            on_target(
                InspectionTargetEvent(
                    kind=InspectionEventKind.TERMINAL,
                    target=target,
                    stage=result.stage,
                    status=result.status,
                    terminal=True,
                    negotiation=result.negotiation,
                    authentication=result.authentication,
                    error=result.outcome.error,
                )
            )
        return result


class _FakeHashToolRunner:
    def __init__(self, tool_id: str, display_name: str) -> None:
        self.tool_id = tool_id
        self.display_name = display_name
        self.request: AuditRunRequest | None = None

    def availability(self) -> AuditToolAvailability:
        return AuditToolAvailability(
            tool_id=self.tool_id,
            display_name=self.display_name,
            available=True,
            executable_path=f"/test/{self.tool_id}",
        )

    def run(self, request: AuditRunRequest, _cancellation: threading.Event) -> AuditRunResult:
        self.request = request
        if _RECOVERED_PLAINTEXT.encode() in request.wordlist_path.read_bytes().splitlines():
            return AuditRunResult(
                AuditRunOutcome.CRACKED,
                plaintext=_RECOVERED_PLAINTEXT,
            )
        return AuditRunResult(AuditRunOutcome.EXHAUSTED)


class WebAppTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.port = 8765
        self.inspector = _FakeAccessInspector()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addAsyncCleanup(self._cleanup_temporary_directory)
        temporary_root = Path(self.temporary_directory.name)
        self.content_wordlist_path = temporary_root / "content.txt"
        self.content_wordlist_path.write_text(
            "# content\npassword\napi_key\n",
            encoding="utf-8",
        )
        self.wordlists = WordlistStore(content_path=self.content_wordlist_path)
        self.hashcat_runner = _FakeHashToolRunner("hashcat", "Hashcat")
        self.john_runner = _FakeHashToolRunner("john", "John the Ripper")
        self.app = create_app(
            port=self.port,
            access_inspector=self.inspector,
            wordlist_store=self.wordlists,
            hash_tool_manager=CredentialAuditManager(
                (self.hashcat_runner, self.john_runner)
            ),
            kerberos_hostname_resolver=lambda target: target.source_hostname,
        )
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url=f"http://127.0.0.1:{self.port}",
        )
        self.csrf = self.app.state.runtime.csrf.value

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.app.state.runtime.hash_tools.close()

    async def _cleanup_temporary_directory(self) -> None:
        self.temporary_directory.cleanup()

    async def post(self, path: str, **kwargs: object) -> httpx.Response:
        headers = {
            "Origin": f"http://127.0.0.1:{self.port}",
            "X-CSRF-Token": self.csrf,
        }
        headers.update(kwargs.pop("headers", {}))
        return await self.client.post(path, headers=headers, **kwargs)

    async def put(self, path: str, **kwargs: object) -> httpx.Response:
        headers = {
            "Origin": f"http://127.0.0.1:{self.port}",
            "X-CSRF-Token": self.csrf,
        }
        headers.update(kwargs.pop("headers", {}))
        return await self.client.put(path, headers=headers, **kwargs)

    async def _start_and_wait(
        self,
        *,
        targets: str,
        credential: dict[str, object] | None = None,
    ) -> tuple[httpx.Response, dict[str, object]]:
        response = await self.post(
            "/scan",
            json=_scan_payload(targets, credential=credential),
        )
        self.assertEqual(response.status_code, 202, response.text)
        worker = self.app.state.runtime.worker
        self.assertIsNotNone(worker)
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        snapshot_response = await self.client.get("/scan/snapshot")
        self.assertEqual(snapshot_response.status_code, 200)
        return response, snapshot_response.json()

    async def test_homepage_is_local_asset_only_and_never_cached(self) -> None:
        response = await self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("NordisGlobal SMB Inspector", response.text)
        self.assertIn("Taramayı başlat", response.text)
        self.assertIn("Tarama çalışma alanı", response.text)
        self.assertIn("Wordlist yönetimi", response.text)
        self.assertIn('role="tablist"', response.text)
        self.assertIn('data-result-tab="targets"', response.text)
        self.assertIn('data-result-tab="inventory"', response.text)
        self.assertIn('data-result-tab="findings"', response.text)
        self.assertIn("CCache", response.text)
        self.assertIn('id="target-selection-detail"', response.text)
        self.assertIn('id="inventory-selection-detail"', response.text)
        self.assertIn('id="finding-selection-detail"', response.text)
        self.assertIn('id="inventory-groups"', response.text)
        self.assertIn('id="findings-groups"', response.text)
        self.assertIn('id="history-delete-dialog"', response.text)
        self.assertIn('id="detect-patterns"', response.text)
        self.assertIn('id="toggle-term-generator"', response.text)
        self.assertIn('id="term-generator-roots"', response.text)
        self.assertIn("Veri Kalıplarını Aramaya Dahil Et", response.text)
        self.assertIn("example.com, files.example.com", response.text)
        self.assertIn("example, client_secret", response.text)
        self.assertIn(self.csrf, response.text)
        self.assertNotIn("https://", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    async def test_wordlists_are_loaded_and_saved_through_the_panel_api(self) -> None:
        initial = await self.client.get("/wordlists")

        self.assertEqual(initial.status_code, 200)
        self.assertEqual(initial.json()["content"]["entry_count"], 2)
        self.assertNotIn("shares", initial.json())

        saved = await self.put(
            "/wordlists/content",
            json={"text": "# edited\npassword\nclient_secret"},
        )

        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertTrue(saved.json()["ok"])
        self.assertEqual(saved.json()["content"]["entry_count"], 2)
        self.assertEqual(
            self.content_wordlist_path.read_text(encoding="utf-8"),
            "# edited\npassword\nclient_secret\n",
        )

    async def test_invalid_wordlist_edit_is_rejected_without_replacing_the_file(self) -> None:
        original = self.content_wordlist_path.read_bytes()

        response = await self.put(
            "/wordlists/content",
            json={"text": "# only a comment\n\n"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            response.json()["error"],
            "Wordlist must contain at least one entry.",
        )
        self.assertEqual(self.content_wordlist_path.read_bytes(), original)

    async def test_the_removed_share_wordlist_is_no_longer_addressable(self) -> None:
        response = await self.put(
            "/wordlists/shares",
            json={"text": "Public\n"},
        )

        self.assertEqual(response.status_code, 404)

    async def test_foreign_host_is_rejected_and_still_gets_security_headers(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://evil.example",
        ) as client:
            response = await client.get("/")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")

    async def test_scan_returns_all_target_validation_errors_before_worker(self) -> None:
        response = await self.post(
            "/scan",
            json=_scan_payload("10.0.0.999, broken_name!, 10.0.0.0/99"),
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(len(response.json()["errors"]), 3)
        self.assertIsNone(self.app.state.runtime.worker)

    async def test_invalid_credential_is_rejected_before_worker(self) -> None:
        invalid = _credential_payload(kind="nt_hash", secret="not-an-nt-hash")

        response = await self.post(
            "/scan",
            json=_scan_payload("192.0.2.1", credential=invalid),
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["errors"][0]["value"], "Kimlik bilgisi")
        self.assertIsNone(self.app.state.runtime.worker)

    async def test_ccache_payload_is_decoded_in_memory_and_forces_kerberos(self) -> None:
        ccache = {
            "kind": "ccache",
            "domain": "NORDIS.TEST",
            "username": None,
            "auth_mode": "kerberos_only",
            "ccache_name": "nordis-lab.ccache",
            "ccache_base64": base64.b64encode(_CCACHE).decode("ascii"),
        }

        response, snapshot = await self._start_and_wait(
            targets="192.0.2.1",
            credential=ccache,
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(snapshot["targets"][0]["authentication_method"], "kerberos")
        latest = self.inspector.observations[-1]
        self.assertIs(latest["kind"], CredentialKind.CCACHE)
        self.assertIs(latest["auth_mode"], AuthMode.KERBEROS_ONLY)
        self.assertTrue(latest["secret_was_correct"])
        public = response.text + json.dumps(snapshot, sort_keys=True)
        self.assertNotIn(base64.b64encode(_CCACHE).decode("ascii"), public)

    async def test_invalid_ccache_base64_is_rejected_before_worker(self) -> None:
        ccache = {
            "kind": "ccache",
            "domain": "NORDIS.TEST",
            "username": None,
            "auth_mode": "kerberos_only",
            "ccache_name": "ticket.ccache",
            "ccache_base64": "%%%not-base64%%%",
        }

        response = await self.post(
            "/scan",
            json=_scan_payload("192.0.2.1", credential=ccache),
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["errors"][0]["value"], "Kimlik bilgisi")
        self.assertIsNone(self.app.state.runtime.worker)

    async def test_post_requires_exact_origin_and_csrf(self) -> None:
        payload = _scan_payload("192.0.2.1")
        wrong_origin = await self.client.post(
            "/scan",
            headers={"Origin": "http://localhost:8765", "X-CSRF-Token": self.csrf},
            json=payload,
        )
        wrong_csrf = await self.client.post(
            "/scan",
            headers={"Origin": "http://127.0.0.1:8765", "X-CSRF-Token": "wrong"},
            json=payload,
        )

        self.assertEqual(wrong_origin.status_code, 403)
        self.assertEqual(wrong_origin.json()["error"]["code"], "SAME_ORIGIN_REQUIRED")
        self.assertEqual(wrong_csrf.status_code, 403)
        self.assertEqual(wrong_csrf.json()["error"]["code"], "CSRF_REJECTED")

    async def test_json_body_limit_is_applied_during_stream_read(self) -> None:
        response = await self.post(
            "/scan",
            content=b'{"targets":"' + (b"a" * (2 * 1024 * 1024)) + b'"}',
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"]["code"], "PAYLOAD_TOO_LARGE")

    async def test_snapshot_contains_only_memory_state(self) -> None:
        response = await self.client.get("/scan/snapshot")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "idle")
        self.assertIsNone(response.json()["scan_id"])
        self.assertEqual(response.json()["targets"], [])

    async def test_access_results_drive_live_target_filter_and_terminal_state(self) -> None:
        _response, snapshot = await self._start_and_wait(
            targets="192.0.2.1,192.0.2.2,192.0.2.3"
        )

        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["terminal_reason"], "completed")
        self.assertEqual(snapshot["progress"]["phase"], "completed")
        self.assertEqual(snapshot["progress"]["phase_completed"], 3)

        # Live target rows retain positively observed SMB/auth results and an
        # explicit refusal, while a no-response timeout remains a counter only.
        by_address = {row["address"]: row for row in snapshot["targets"]}
        self.assertEqual(set(by_address), {"192.0.2.1", "192.0.2.2"})
        authenticated = by_address["192.0.2.1"]
        self.assertEqual(authenticated["tcp_status"], "port_open")
        self.assertEqual(authenticated["smb_status"], "3.1.1")
        self.assertEqual(authenticated["authentication_status"], "authenticated")
        self.assertEqual(authenticated["authentication_method"], "ntlm")
        self.assertEqual(authenticated["last_status"], "completed")
        refused = by_address["192.0.2.2"]
        self.assertEqual(refused["tcp_status"], "connection_refused")
        self.assertIsNone(refused["smb_status"])
        self.assertIsNone(refused["authentication_status"])
        self.assertEqual(refused["last_status"], "connection_refused")
        self.assertEqual(refused["raw_error_code"], errno.ECONNREFUSED)
        self.assertEqual(refused["error_name"], "ECONNREFUSED")
        self.assertEqual(refused["error_message"], "Normalized network failure.")
        self.assertEqual(snapshot["progress"]["counters"]["completed"], 1)
        self.assertEqual(snapshot["progress"]["counters"]["connection_refused"], 1)
        self.assertEqual(snapshot["progress"]["counters"]["timeout_no_response"], 1)

        observations = {item["target"]: item for item in self.inspector.observations}
        self.assertEqual(set(observations), {"192.0.2.1", "192.0.2.2", "192.0.2.3"})
        self.assertTrue(all(item["secret_was_correct"] for item in observations.values()))
        self.assertTrue(
            all(item["kind"] is CredentialKind.PASSWORD for item in observations.values())
        )
        self.assertTrue(
            all(item["auth_mode"] is AuthMode.AUTO for item in observations.values())
        )
        self.assertTrue(all(item["has_search_terms"] for item in observations.values()))
        self.assertTrue(all(item["max_depth"] == 32 for item in observations.values()))
        self.assertTrue(all(item["detect_patterns"] is True for item in observations.values()))

        self.assertEqual(snapshot["inventory_count"], 1)
        self.assertEqual(snapshot["finding_count"], 1)
        inventory = (await self.client.get("/inventory")).json()
        findings = (await self.client.get("/findings")).json()
        self.assertEqual(inventory["total_items"], 1)
        self.assertEqual(inventory["items"][0]["path"], "config.txt")
        self.assertEqual(findings["total_items"], 1)
        self.assertEqual(findings["items"][0]["line_number"], 2)
        self.assertEqual(findings["items"][0]["full_line"], "password=lab-value")
        self.assertEqual(findings["items"][0]["method"], "wordlist")
        self.assertIsNone(findings["items"][0]["rule_id"])

    async def test_binary_credential_artifact_has_no_line_content_in_api(self) -> None:
        _response, snapshot = await self._start_and_wait(targets="192.0.2.5")

        self.assertEqual(snapshot["finding_count"], 1)
        findings = (await self.client.get("/findings")).json()
        artifact = findings["items"][0]
        self.assertEqual(artifact["method"], "artifact")
        self.assertEqual(artifact["rule_id"], "kerberos-ccache-file")
        self.assertEqual(artifact["category"], "Windows / AD")
        self.assertEqual(artifact["confidence"], "high")
        self.assertIsNone(artifact["line_number"])
        self.assertIsNone(artifact["full_line"])
        self.assertEqual(artifact["audit_candidates"], [])

    async def test_hash_tools_receive_only_reclassified_supported_findings(self) -> None:
        await self._start_and_wait(targets="192.0.2.6")
        finding = (await self.client.get("/findings")).json()["items"][0]

        self.assertEqual(len(finding["audit_candidates"]), 1)
        audit_candidate = finding["audit_candidates"][0]
        self.assertEqual(len(audit_candidate.pop("id")), 64)
        self.assertEqual(
            audit_candidate,
            {
                "variant": "nt",
                "format": "ntlm",
                "tools": [
                    {"id": "hashcat", "format": "1000"},
                    {"id": "john", "format": "nt"},
                ],
            },
        )
        tool_snapshot = (await self.client.get("/hash-tools")).json()
        self.assertEqual(
            [(tool["id"], tool["available"]) for tool in tool_snapshot["tools"]],
            [("hashcat", True), ("john", True)],
        )

        wordlist = f"wrong\n{_RECOVERED_PLAINTEXT}\n".encode()
        uploaded = await self.put(
            "/hash-tools/wordlist",
            content=wordlist,
            headers={"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        uploaded_wordlist = uploaded.json()["wordlist"]
        self.assertEqual(uploaded_wordlist["size_bytes"], len(wordlist))
        self.assertEqual(uploaded_wordlist["entry_count"], 2)

        response = await self.post(
            "/hash-tools/jobs",
            json={
                "rule_id": finding["rule_id"],
                "full_line": finding["full_line"],
                "variant": "nt",
                "tool_id": "hashcat",
                "wordlist_upload_id": uploaded_wordlist["upload_id"],
                "runtime_seconds": 30,
            },
        )
        self.assertEqual(response.status_code, 202, response.text)
        worker = self.app.state.runtime.hash_tools.worker
        worker.join(timeout=1)
        completed = (await self.client.get("/hash-tools")).json()["job"]

        self.assertEqual(completed["status"], "cracked")
        self.assertEqual(completed["plaintext"], _RECOVERED_PLAINTEXT)
        self.assertNotIn(_FOUND_NT_HASH, response.text)
        self.assertNotIn(_FOUND_NT_HASH, repr(self.hashcat_runner.request))

    async def test_hash_tools_reject_arbitrary_content_and_require_csrf(self) -> None:
        body = {
            "rule_id": "windows-nt-hash",
            "full_line": "password=not-a-hash",
            "variant": "nt",
            "tool_id": "hashcat",
            "wordlist_upload_id": "missing",
            "runtime_seconds": 30,
        }
        rejected = await self.post("/hash-tools/jobs", json=body)
        no_csrf = await self.client.post(
            "/hash-tools/jobs",
            headers={"Origin": f"http://127.0.0.1:{self.port}"},
            json=body,
        )

        self.assertEqual(rejected.status_code, 422)
        self.assertEqual(rejected.json()["error"], "UNSUPPORTED_CANDIDATE")
        self.assertEqual(no_csrf.status_code, 403)
        self.assertEqual(no_csrf.json()["error"]["code"], "CSRF_REJECTED")

    async def test_hash_wordlist_upload_accepts_raw_bytes_and_rejects_empty_files(
        self,
    ) -> None:
        raw_wordlist = b"password\ncaf\xe9\n"
        accepted = await self.put(
            "/hash-tools/wordlist",
            content=raw_wordlist,
            headers={"Content-Type": "application/octet-stream"},
        )

        self.assertEqual(accepted.status_code, 201, accepted.text)
        self.assertEqual(accepted.json()["wordlist"]["size_bytes"], len(raw_wordlist))
        self.assertEqual(accepted.json()["wordlist"]["entry_count"], 2)
        self.assertNotIn("password", accepted.text)
        self.assertEqual(
            self.app.state.runtime.hash_tools.wordlist.path.read_bytes(),
            raw_wordlist,
        )

        empty = await self.put(
            "/hash-tools/wordlist",
            content=b"",
            headers={"Content-Type": "application/octet-stream"},
        )

        self.assertEqual(empty.status_code, 422)
        self.assertEqual(empty.json()["error"], "WORDLIST_SIZE_INVALID")
        self.assertEqual(
            self.app.state.runtime.hash_tools.wordlist.path.read_bytes(),
            raw_wordlist,
        )

    async def test_share_enumeration_failure_remains_visible_in_target_snapshot(self) -> None:
        _response, snapshot = await self._start_and_wait(targets="192.0.2.4")

        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["progress"]["counters"]["share_enum_denied"], 1)
        self.assertEqual(len(snapshot["targets"]), 1)
        target = snapshot["targets"][0]
        self.assertEqual(target["last_status"], "share_enum_denied")
        self.assertEqual(target["authentication_status"], "authenticated")
        self.assertEqual(target["shares_probed"], 0)
        self.assertEqual(target["error_name"], "SHARE_ENUM_ACCESS_DENIED")
        self.assertEqual(target["raw_error_code"], 0xC0000022)

    async def test_unexpected_target_worker_failure_has_a_safe_terminal_outcome(self) -> None:
        _response, snapshot = await self._start_and_wait(targets="192.0.2.9")

        self.assertEqual(snapshot["status"], "failed")
        self.assertEqual(snapshot["terminal_reason"], "worker_failed")
        self.assertEqual(
            snapshot["terminal_error"],
            {
                "phase": "inspection",
                "code": "INSPECTOR_ERROR",
                "message": (
                    "192.0.2.9 hedefinin denetim iş akışı beklenmeyen "
                    "bir uygulama hatasıyla durdu."
                ),
            },
        )
        public = json.dumps(snapshot, sort_keys=True)
        self.assertNotIn("DoNotLeakWorkerException", public)

    async def test_password_and_hash_never_leak_to_responses_snapshots_or_events(self) -> None:
        secrets = (_PASSWORD, _NT_HASH, _NT_HASH.casefold())
        response, first_snapshot = await self._start_and_wait(targets="192.0.2.1")
        hash_credential = _credential_payload(kind="nt_hash", secret=_NT_HASH)
        hash_response, second_snapshot = await self._start_and_wait(
            targets="192.0.2.1",
            credential=hash_credential,
        )

        replay = self.app.state.runtime.events.replay_after(None)
        public_surfaces = "\n".join(
            (
                response.text,
                hash_response.text,
                json.dumps(first_snapshot, sort_keys=True),
                json.dumps(second_snapshot, sort_keys=True),
                *(event.data for event in replay.events),
            )
        )
        for secret in secrets:
            with self.subTest(secret_kind="hash" if len(secret) == 32 else "password"):
                self.assertNotIn(secret, public_surfaces)

        latest = self.inspector.observations[-1]
        self.assertIs(latest["kind"], CredentialKind.NT_HASH)
        self.assertIs(latest["auth_mode"], AuthMode.NTLM_ONLY)
        self.assertTrue(latest["secret_was_correct"])

    async def test_static_asset_traversal_and_unknown_names_are_rejected(self) -> None:
        response = await self.client.get("/static/missing.js")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")


if __name__ == "__main__":
    unittest.main()
