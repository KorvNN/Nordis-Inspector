from __future__ import annotations

import unittest

import httpx2

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

    async def test_preview_keeps_cidr_expansion_out_of_browser_payload(self) -> None:
        response = await self.post(
            "/scope/preview",
            json={"targets": "192.0.2.9, 192.0.2.0/30"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["known_address_count"], 3)
        self.assertEqual(payload["candidate_address_count"], 3)
        self.assertEqual([group["source"] for group in payload["groups"]], [
            "192.0.2.9",
            "192.0.2.0/30",
        ])
        self.assertTrue(payload["groups"][0]["details_hidden"])
        self.assertTrue(payload["groups"][1]["details_hidden"])
        self.assertEqual(payload["groups"][0]["rows"], [])
        self.assertEqual(payload["groups"][1]["candidate_count"], 2)
        self.assertEqual(payload["groups"][1]["rows"], [])

    async def test_preview_summarizes_a_slash_24_as_one_group(self) -> None:
        response = await self.post(
            "/scope/preview",
            json={"targets": "10.10.50.0/24"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["candidate_address_count"], 254)
        self.assertEqual(len(payload["groups"]), 1)
        self.assertEqual(payload["groups"][0]["source"], "10.10.50.0/24")
        self.assertEqual(payload["groups"][0]["candidate_count"], 254)
        self.assertEqual(payload["groups"][0]["rows"], [])

    async def test_preview_returns_all_validation_errors_without_echoing_to_logs(self) -> None:
        response = await self.post(
            "/scope/preview",
            json={"targets": "10.0.0.999, broken_name!, 10.0.0.0/99"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(len(response.json()["errors"]), 3)

    async def test_post_requires_exact_origin_and_csrf(self) -> None:
        wrong_origin = await self.client.post(
            "/scope/preview",
            headers={"Origin": "http://localhost:8765", "X-CSRF-Token": self.csrf},
            json={"targets": "192.0.2.1"},
        )
        wrong_csrf = await self.client.post(
            "/scope/preview",
            headers={"Origin": "http://127.0.0.1:8765", "X-CSRF-Token": "wrong"},
            json={"targets": "192.0.2.1"},
        )

        self.assertEqual(wrong_origin.status_code, 403)
        self.assertEqual(wrong_origin.json()["error"]["code"], "SAME_ORIGIN_REQUIRED")
        self.assertEqual(wrong_csrf.status_code, 403)
        self.assertEqual(wrong_csrf.json()["error"]["code"], "CSRF_REJECTED")

    async def test_json_body_limit_is_applied_during_stream_read(self) -> None:
        response = await self.post(
            "/scope/preview",
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

    async def test_static_asset_traversal_and_unknown_names_are_rejected(self) -> None:
        response = await self.client.get("/static/missing.js")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["cache-control"], "no-store, max-age=0")


if __name__ == "__main__":
    unittest.main()
