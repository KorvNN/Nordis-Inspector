from __future__ import annotations

import unittest
from threading import Event

import httpx

from nordis_smb_inspector.ad.models import (
    AdComputer,
    AdCoverage,
    AdCoverageState,
    AdEvidenceState,
    AdFinding,
    AdFindingLane,
    AdIdentity,
    AdInspectionReport,
    AdSeverity,
)
from nordis_smb_inspector.core.credentials import AuthMode, Credential
from nordis_smb_inspector.web.app import create_app


class _FakeAdInspector:
    def __init__(self) -> None:
        self.credential: Credential | None = None
        self.kerberos_hostname: str | None = None

    def __call__(self, **kwargs: object) -> AdInspectionReport:
        credential = kwargs["credential"]
        assert isinstance(credential, Credential)
        self.credential = credential
        self.kerberos_hostname = kwargs.get("kerberos_hostname")
        computer = AdComputer("WS01$", "ws01.efelab.test", "Windows 11", True)
        finding = AdFinding(
            check_id="laps_readable",
            lane=AdFindingLane.CAPABILITY,
            evidence_state=AdEvidenceState.VERIFIED,
            severity=AdSeverity.CRITICAL,
            title="Yerel yönetici parolası okunabiliyor",
            summary="Parola sonuçlara alınmadı.",
            subject="ws01.efelab.test",
        )
        on_computer = kwargs["on_computer"]
        on_finding = kwargs["on_finding"]
        assert callable(on_computer)
        assert callable(on_finding)
        on_computer(computer)
        on_finding(finding)
        return AdInspectionReport(
            identity=AdIdentity(
                "KorvNN@efelab.test",
                "CN=KorvNN,CN=Users,DC=efelab,DC=test",
                "efelab.test",
                groups=("Domain Users",),
            ),
            authentication_method="ntlm",
            computers=(computer,),
            findings=(finding,),
            coverage=(
                AdCoverage(
                    "computers_laps",
                    "Bilgisayarlar ve LAPS görünürlüğü",
                    AdCoverageState.COMPLETED,
                    records_seen=1,
                ),
            ),
        )


class _BlockingAdInspector:
    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()

    def __call__(self, **kwargs: object) -> AdInspectionReport:
        self.started.set()
        self.release.wait(timeout=2)
        on_computer = kwargs["on_computer"]
        assert callable(on_computer)
        on_computer(AdComputer("WS01$", "ws01.efelab.test", None, True))
        raise AssertionError("cancelled callback must stop before this line")


def _payload(*, auth_mode: str = "ntlm_only") -> dict[str, object]:
    return {
        "controller": "DC01.efelab.test",
        "domain": "efelab.test",
        "credential": {
            "kind": "password",
            "auth_mode": auth_mode,
            "domain": "efelab.test",
            "username": "KorvNN",
            "password": "Admin123.Aa",
        },
    }


class AdWebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.inspector = _FakeAdInspector()
        self.app = create_app(ad_inspector=self.inspector)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://127.0.0.1:8765",
        )
        self.headers = {
            "Origin": "http://127.0.0.1:8765",
            "X-CSRF-Token": self.app.state.runtime.csrf.value,
        }

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.app.state.runtime.hash_tools.close()

    async def test_ad_scan_exposes_separate_secret_safe_results(self) -> None:
        response = await self.client.post("/ad/scan", json=_payload(), headers=self.headers)
        self.assertEqual(response.status_code, 202, response.text)
        worker = self.app.state.runtime.ad_worker
        self.assertIsNotNone(worker)
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

        snapshot = (await self.client.get("/ad/scan/snapshot")).json()
        computers = (await self.client.get("/ad/computers")).json()
        findings = (await self.client.get("/ad/findings")).json()

        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["identity"]["principal"], "KorvNN@efelab.test")
        self.assertEqual(snapshot["authentication_method"], "ntlm")
        self.assertEqual(computers["items"][0]["hostname"], "ws01.efelab.test")
        self.assertEqual(findings["items"][0]["evidence_state"], "verified")
        rendered = str(snapshot) + str(computers) + str(findings)
        self.assertNotIn("Admin123.Aa", rendered)
        self.assertIs(self.inspector.credential.auth_mode, AuthMode.NTLM_ONLY)

    async def test_ad_scan_requires_explicit_authentication_mode(self) -> None:
        response = await self.client.post(
            "/ad/scan", json=_payload(auth_mode="auto"), headers=self.headers
        )

        self.assertEqual(response.status_code, 422)
        self.assertIn("Kerberos veya NTLM", response.json()["error"])
        self.assertIsNone(self.app.state.runtime.ad_worker)

    async def test_ad_scan_rejects_url_in_controller_field(self) -> None:
        payload = _payload()
        payload["controller"] = "ldap://dc01.efelab.test"

        response = await self.client.post("/ad/scan", json=payload, headers=self.headers)

        self.assertEqual(response.status_code, 422)
        self.assertIsNone(self.app.state.runtime.ad_worker)

    async def test_kerberos_with_controller_ip_requires_spn_hostname(self) -> None:
        payload = _payload(auth_mode="kerberos_only")
        payload["controller"] = "10.77.0.30"

        response = await self.client.post("/ad/scan", json=payload, headers=self.headers)

        self.assertEqual(response.status_code, 422)
        self.assertIn("hostname", response.json()["error"])

    async def test_kerberos_accepts_separate_controller_ip_and_spn_hostname(self) -> None:
        payload = _payload(auth_mode="kerberos_only")
        payload["controller"] = "10.77.0.30"
        payload["kerberos_hostname"] = "DC01.efelab.test"

        response = await self.client.post("/ad/scan", json=payload, headers=self.headers)
        self.assertEqual(response.status_code, 202, response.text)
        worker = self.app.state.runtime.ad_worker
        worker.join(timeout=2)

        snapshot = (await self.client.get("/ad/scan/snapshot")).json()
        self.assertEqual(snapshot["status"], "completed")
        self.assertIs(self.inspector.credential.auth_mode, AuthMode.KERBEROS_ONLY)
        self.assertEqual(self.inspector.kerberos_hostname, "DC01.efelab.test")

    async def test_cancellation_during_query_finishes_as_cancelled(self) -> None:
        inspector = _BlockingAdInspector()
        self.app.state.runtime.ad_inspector = inspector
        response = await self.client.post("/ad/scan", json=_payload(), headers=self.headers)
        self.assertEqual(response.status_code, 202)
        self.assertTrue(inspector.started.wait(timeout=1))

        cancelled = await self.client.post(
            "/ad/scan/cancel", json={}, headers=self.headers
        )
        self.assertEqual(cancelled.status_code, 202)
        inspector.release.set()
        worker = self.app.state.runtime.ad_worker
        worker.join(timeout=2)

        snapshot = (await self.client.get("/ad/scan/snapshot")).json()
        self.assertEqual(snapshot["status"], "cancelled")
        self.assertIsNone(snapshot["terminal_error"])
