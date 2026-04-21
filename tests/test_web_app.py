from __future__ import annotations

import errno
import unittest

import httpx2

from nordis_smb_inspector.core.connectivity import ConnectivityScanner
from nordis_smb_inspector.web.app import create_app


class WebAppTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.port = 8765
        self.app = create_app(port=self.port)
        self.client = httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=self.app),
            base_url=f"http://127.0.0.1:{self.port}",
        )
        self.csrf = self.app.state.runtime.csrf.value

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def post(self, path: str, **kwargs: object):
        headers = {
            "Origin": f"http://127.0.0.1:{self.port}",
            "X-CSRF-Token": self.csrf,
        }
        headers.update(kwargs.pop("headers", {}))
        return await self.client.post(path, headers=headers, **kwargs)

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
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=self.app),
            base_url="http://evil.example",
        ) as client:
            response = await client.get("/")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")

    async def test_scan_returns_all_validation_errors_before_starting_worker(self) -> None:
        response = await self.post(
            "/scan",
            json={"targets": "10.0.0.999, broken_name!, 10.0.0.0/99"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(len(response.json()["errors"]), 3)

    async def test_post_requires_exact_origin_and_csrf(self) -> None:
        wrong_origin = await self.client.post(
            "/scan",
            headers={"Origin": "http://localhost:8765", "X-CSRF-Token": self.csrf},
            json={"targets": "192.0.2.1"},
        )
        wrong_csrf = await self.client.post(
            "/scan",
            headers={"Origin": "http://127.0.0.1:8765", "X-CSRF-Token": "wrong"},
            json={"targets": "192.0.2.1"},
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

    async def test_scan_streams_real_connectivity_outcomes_into_target_snapshot(self) -> None:
        def connector(address: object, _port: int, _timeout: float) -> None:
            if str(address) == "192.0.2.2":
                raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
            if str(address) == "192.0.2.3":
                raise TimeoutError("no response")

        self.app.state.runtime.connectivity = ConnectivityScanner(connector=connector)

        response = await self.post(
            "/scan",
            json={"targets": "192.0.2.1,192.0.2.2,192.0.2.3"},
        )

        self.assertEqual(response.status_code, 202)
        worker = self.app.state.runtime.worker
        self.assertIsNotNone(worker)
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

        snapshot = (await self.client.get("/scan/snapshot")).json()
        self.assertEqual(snapshot["status"], "completed")
        by_address = {row["address"]: row for row in snapshot["targets"]}
        self.assertEqual(by_address["192.0.2.1"]["tcp_status"], "port_open")
        self.assertEqual(
            by_address["192.0.2.2"]["tcp_status"],
            "connection_refused",
        )
        self.assertNotIn("192.0.2.3", by_address)
        self.assertEqual(snapshot["progress"]["counters"]["timeout_no_response"], 1)
        self.assertEqual(snapshot["progress"]["phase"], "completed")

    async def test_static_asset_traversal_and_unknown_names_are_rejected(self) -> None:
        response = await self.client.get("/static/missing.js")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")


if __name__ == "__main__":
    unittest.main()
