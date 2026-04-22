from __future__ import annotations

import errno
import json
import threading
import unittest

import httpx

from nordis_smb_inspector.core.credentials import AuthMode, Credential, CredentialKind
from nordis_smb_inspector.smb.models import (
    AuthAttempt,
    AuthAttemptOutcome,
    AuthenticationHistory,
    AuthMechanism,
    NegotiationInfo,
    SecurityFeatureState,
    SmbDialect,
    SmbErrorDetail,
    TargetOutcome,
    TargetStage,
    TargetStatus,
    TransportSecurity,
)
from nordis_smb_inspector.smb.workflow import (
    AccessEvent,
    AccessEventKind,
    AccessWorkflowStatus,
    TargetAccessResult,
)
from nordis_smb_inspector.web.app import create_app

_PASSWORD = "CorrectHorseBatteryStaple!"
_NT_HASH = "0123456789ABCDEF0123456789ABCDEF"


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


def _authenticated_result(target: str) -> TargetAccessResult:
    negotiation = _negotiation()
    authentication = AuthenticationHistory(
        attempts=(
            AuthAttempt(
                mechanism=AuthMechanism.NTLM,
                outcome=AuthAttemptOutcome.SUCCEEDED,
            ),
        ),
        selected_mechanism=AuthMechanism.NTLM,
    )
    events = (
        AccessEvent(
            kind=AccessEventKind.NEGOTIATION_SUCCEEDED,
            stage=TargetStage.NEGOTIATION,
            target=target,
            negotiation=negotiation,
        ),
        AccessEvent(
            kind=AccessEventKind.AUTHENTICATION_SUCCEEDED,
            stage=TargetStage.AUTHENTICATION,
            target=target,
            authentication=authentication,
        ),
    )
    return TargetAccessResult(
        target=target,
        status=AccessWorkflowStatus.AUTHENTICATED,
        events=events,
        negotiation=negotiation,
        authentication=authentication,
    )


def _connect_failure_result(target: str, status: TargetStatus) -> TargetAccessResult:
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
    event = AccessEvent(
        kind=AccessEventKind.NEGOTIATION_FAILED,
        stage=TargetStage.NETWORK,
        target=target,
        outcome=outcome,
        error=error,
    )
    return TargetAccessResult(
        target=target,
        status=AccessWorkflowStatus.CONNECT_FAILED,
        events=(event,),
        outcome=outcome,
    )


class _FakeAccessInspector:
    """No-network target workflow with sanitized observations for assertions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.observations: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> TargetAccessResult:
        target = kwargs["target"]
        credential = kwargs["credential"]
        on_event = kwargs.get("on_event")
        if not isinstance(target, str):
            raise TypeError("fake target must be text")
        if not isinstance(credential, Credential):
            raise TypeError("fake credential must be validated")

        expected_secret = (
            _PASSWORD
            if credential.kind is CredentialKind.PASSWORD
            else _NT_HASH.casefold()
        )
        supplied_secret = (
            credential.password
            if credential.kind is CredentialKind.PASSWORD
            else credential.nt_hash
        )
        with self._lock:
            self.observations.append(
                {
                    "target": target,
                    "kind": credential.kind,
                    "auth_mode": credential.auth_mode,
                    "domain": credential.domain,
                    "username": credential.username,
                    "secret_was_correct": supplied_secret == expected_secret,
                }
            )

        if target.endswith(".1"):
            result = _authenticated_result(target)
        elif target.endswith(".2"):
            result = _connect_failure_result(target, TargetStatus.CONNECTION_REFUSED)
        else:
            result = _connect_failure_result(target, TargetStatus.TIMEOUT_NO_RESPONSE)

        if callable(on_event):
            for event in result.events:
                on_event(event)
        return result


class WebAppTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.port = 8765
        self.inspector = _FakeAccessInspector()
        self.app = create_app(port=self.port, access_inspector=self.inspector)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url=f"http://127.0.0.1:{self.port}",
        )
        self.csrf = self.app.state.runtime.csrf.value

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def post(self, path: str, **kwargs: object) -> httpx.Response:
        headers = {
            "Origin": f"http://127.0.0.1:{self.port}",
            "X-CSRF-Token": self.csrf,
        }
        headers.update(kwargs.pop("headers", {}))
        return await self.client.post(path, headers=headers, **kwargs)

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
        self.assertIn("Canlı hedef durumu", response.text)
        self.assertIn(self.csrf, response.text)
        self.assertNotIn("https://", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

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
            content=b'{"targets":"' + (b"a" * (65 * 1024)) + b'"}',
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
        self.assertEqual(authenticated["last_status"], "authenticated")
        refused = by_address["192.0.2.2"]
        self.assertEqual(refused["tcp_status"], "connection_refused")
        self.assertIsNone(refused["smb_status"])
        self.assertIsNone(refused["authentication_status"])
        self.assertEqual(refused["last_status"], "connection_refused")
        self.assertEqual(snapshot["progress"]["counters"]["authenticated"], 1)
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
