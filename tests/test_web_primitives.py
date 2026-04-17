from __future__ import annotations

import hmac
import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from nordis_smb_inspector.web.events import (
    EventBrokerClosed,
    InvalidEventCursor,
    InvalidEventPayload,
    InvalidSseField,
    SseEventBroker,
    format_sse,
    parse_last_event_id,
)
from nordis_smb_inspector.web.security import (
    CsrfNonce,
    HttpErrorCode,
    SafeHttpError,
    apply_security_headers,
    expected_loopback_origin,
    require_post_security,
    require_same_origin,
    security_headers,
)


class SecurityPrimitiveTests(unittest.TestCase):
    def test_csrf_nonce_is_random_and_redacted(self) -> None:
        first = CsrfNonce()
        second = CsrfNonce()

        self.assertNotEqual(first.value, second.value)
        self.assertGreaterEqual(len(first.value), 40)
        self.assertNotIn(first.value, repr(first))
        self.assertIn("redacted", repr(first))

    def test_csrf_validation_uses_constant_time_comparison(self) -> None:
        nonce = CsrfNonce()

        with patch.object(hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            self.assertTrue(nonce.matches(nonce.value))
            self.assertFalse(nonce.matches(nonce.value[:-1] + "x"))

        self.assertEqual(compare.call_count, 2)
        self.assertFalse(nonce.matches(None))
        self.assertFalse(nonce.matches(b"not-a-string"))
        self.assertFalse(nonce.matches("şifre"))

    def test_nonce_size_cannot_be_weakened(self) -> None:
        for value in (0, 16, 31):
            with self.subTest(value=value), self.assertRaises(ValueError):
                CsrfNonce(value)
        with self.assertRaises(TypeError):
            CsrfNonce(True)

    def test_only_exact_loopback_origin_is_accepted(self) -> None:
        require_same_origin("http://127.0.0.1:8765", port=8765)

        rejected = (
            None,
            "",
            "null",
            "http://localhost:8765",
            "https://127.0.0.1:8765",
            "http://127.0.0.1:8765/",
            "http://user@127.0.0.1:8765",
            "http://127.0.0.1:8765, http://evil.example",
            "http://127.0.0.1:8765\r\nX-Forged: yes",
            "not an origin",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(SafeHttpError) as captured:
                require_same_origin(value, port=8765)
            self.assertEqual(captured.exception.code, HttpErrorCode.SAME_ORIGIN_REQUIRED)

    def test_post_security_requires_origin_before_nonce(self) -> None:
        nonce = CsrfNonce()
        require_post_security(
            origin="http://127.0.0.1:8765",
            csrf_candidate=nonce.value,
            csrf_nonce=nonce,
            port=8765,
        )

        with self.assertRaises(SafeHttpError) as captured:
            require_post_security(
                origin="http://evil.example",
                csrf_candidate="wrong",
                csrf_nonce=nonce,
                port=8765,
            )
        self.assertEqual(captured.exception.code, HttpErrorCode.SAME_ORIGIN_REQUIRED)

        with self.assertRaises(SafeHttpError) as captured:
            require_post_security(
                origin="http://127.0.0.1:8765",
                csrf_candidate="wrong",
                csrf_nonce=nonce,
                port=8765,
            )
        self.assertEqual(captured.exception.code, HttpErrorCode.CSRF_REJECTED)

    def test_loopback_origin_validates_port(self) -> None:
        self.assertEqual(expected_loopback_origin(1), "http://127.0.0.1:1")
        self.assertEqual(expected_loopback_origin(65535), "http://127.0.0.1:65535")
        for value in (0, 65536):
            with self.subTest(value=value), self.assertRaises(ValueError):
                expected_loopback_origin(value)
        with self.assertRaises(TypeError):
            expected_loopback_origin(True)

    def test_required_security_headers_are_fresh_and_overwrite_duplicates(self) -> None:
        first = security_headers()
        second = security_headers()
        first["Cache-Control"] = "public"

        self.assertEqual(second["Cache-Control"], "no-store, max-age=0")
        self.assertIn("default-src 'self'", second["Content-Security-Policy"])
        self.assertEqual(second["Referrer-Policy"], "no-referrer")
        self.assertEqual(second["X-Content-Type-Options"], "nosniff")

        response_headers = {"cache-control": "public", "Content-Type": "text/plain"}
        apply_security_headers(response_headers)
        self.assertNotIn("cache-control", response_headers)
        self.assertEqual(response_headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(response_headers["Content-Type"], "text/plain")

    def test_safe_http_error_discards_raw_exception(self) -> None:
        secret = "database_password=DoNotReflectThis"
        error = SafeHttpError.from_exception(RuntimeError(secret))
        rendered = repr(error) + str(error) + json.dumps(error.as_payload())

        self.assertNotIn(secret, rendered)
        self.assertEqual(error.status_code, 500)
        self.assertEqual(error.code, HttpErrorCode.INTERNAL_ERROR)
        self.assertIsNone(error.__cause__)


class EventPrimitiveTests(unittest.TestCase):
    def test_publish_assigns_monotonic_ids_and_strict_json(self) -> None:
        broker = SseEventBroker(capacity=4)

        first = broker.publish("phase.changed", {"phase": "inventory"})
        second = broker.publish("finding.added", {"line": "şifre\nsecond"})

        self.assertEqual((first.event_id, second.event_id), (1, 2))
        self.assertEqual(first.data, '{"phase":"inventory"}')
        self.assertEqual(second.data, '{"line":"şifre\\nsecond"}')

    def test_queue_is_bounded_and_publish_never_waits_for_a_reader(self) -> None:
        broker = SseEventBroker(capacity=3)
        published = [broker.publish("file.changed", {"number": index}) for index in range(20)]

        self.assertEqual(len(broker), 3)
        self.assertEqual(published[-1].event_id, 20)
        replay = broker.replay_after(17)
        self.assertEqual([event.event_id for event in replay.events], [18, 19, 20])

    def test_reconnect_replays_retained_events_after_id(self) -> None:
        broker = SseEventBroker(capacity=5)
        for index in range(5):
            broker.publish("target.changed", {"index": index})

        replay = broker.replay_after("2")

        self.assertFalse(replay.resync_required)
        self.assertEqual([event.event_id for event in replay.events], [3, 4, 5])
        self.assertEqual(replay.requested_after_id, 2)

    def test_reconnect_signals_resync_if_client_fell_behind(self) -> None:
        broker = SseEventBroker(capacity=3)
        for index in range(5):
            broker.publish("file.changed", {"index": index})

        still_contiguous = broker.replay_after(2)
        self.assertFalse(still_contiguous.resync_required)
        self.assertEqual([event.event_id for event in still_contiguous.events], [3, 4, 5])

        missed = broker.replay_after(1)
        self.assertTrue(missed.resync_required)
        self.assertEqual(missed.events, ())
        frame = missed.to_sse()[0].decode()
        self.assertIn("event: resync.required\n", frame)
        self.assertIn('"latest_event_id":5', frame)
        self.assertNotIn("\nid:", frame)

    def test_cursor_from_a_different_broker_generation_requires_resync(self) -> None:
        broker = SseEventBroker(capacity=2)
        broker.publish("snapshot", {})

        replay = broker.replay_after(50)

        self.assertTrue(replay.resync_required)
        self.assertEqual(replay.latest_event_id, 1)

    def test_replay_limit_preserves_forward_cursor_order(self) -> None:
        broker = SseEventBroker(capacity=10)
        for index in range(6):
            broker.publish("counters.changed", {"index": index})

        first_page = broker.replay_after(0, limit=2)
        second_page = broker.replay_after(first_page.events[-1].event_id, limit=2)

        self.assertEqual([event.event_id for event in first_page.events], [1, 2])
        self.assertEqual([event.event_id for event in second_page.events], [3, 4])

    def test_event_and_id_newline_injection_is_rejected_without_reflection(self) -> None:
        secret_name = "phase.changed\r\ndata: injected-secret"
        with self.assertRaises(InvalidSseField) as captured:
            format_sse(event=secret_name, data="{}", event_id=1)
        self.assertNotIn("injected-secret", repr(captured.exception))

        for bad_id in ("1\ndata: forged", "1\rid: forged", "1\0forged"):
            with self.subTest(bad_id=bad_id), self.assertRaises(InvalidSseField):
                format_sse(event="phase.changed", data="{}", event_id=bad_id)

    def test_last_event_id_parser_rejects_malformed_or_hostile_values(self) -> None:
        self.assertIsNone(parse_last_event_id(None))
        self.assertIsNone(parse_last_event_id(""))
        self.assertEqual(parse_last_event_id("0"), 0)
        self.assertEqual(parse_last_event_id(42), 42)

        for value in (-1, True, "-1", "+1", " 1", "1\n2", "１", "9" * 20, object()):
            with self.subTest(value=value), self.assertRaises(InvalidEventCursor):
                parse_last_event_id(value)  # type: ignore[arg-type]

    def test_sse_formatter_prefixes_every_data_line(self) -> None:
        frame = format_sse(
            event="finding.added",
            event_id="abc-123",
            data="first\r\nsecond\rthird\n",
        ).decode()

        self.assertEqual(
            frame,
            "id: abc-123\n"
            "event: finding.added\n"
            "data: first\n"
            "data: second\n"
            "data: third\n"
            "data: \n\n",
        )

    def test_payload_and_event_repr_do_not_leak_event_data(self) -> None:
        secret = "password=VisibleOnlyInTheLivePayload"
        broker = SseEventBroker()
        event = broker.publish("finding.added", {"line": secret})

        self.assertNotIn(secret, repr(event))
        self.assertNotIn(secret, repr(broker))
        self.assertIn(secret, event.to_sse().decode())

        with self.assertRaises(InvalidEventPayload) as captured:
            broker.publish("finding.added", {"value": float("nan")})
        self.assertNotIn("nan", repr(captured.exception).casefold())

    def test_concurrent_publish_ids_are_unique_and_ordered_in_buffer(self) -> None:
        broker = SseEventBroker(capacity=250)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(broker.publish, "counters.changed", {"number": index})
                for index in range(200)
            ]
            published_ids = [future.result().event_id for future in futures]

        self.assertEqual(sorted(published_ids), list(range(1, 201)))
        self.assertEqual(
            [event.event_id for event in broker.replay_after(0).events],
            list(range(1, 201)),
        )

    def test_consumer_wait_does_not_prevent_publication(self) -> None:
        broker = SseEventBroker()
        result: list[int] = []

        def consume() -> None:
            replay = broker.wait_after(0, timeout=1)
            result.extend(event.event_id for event in replay.events)

        consumer = threading.Thread(target=consume)
        consumer.start()
        time.sleep(0.01)
        broker.publish("phase.changed", {"phase": "connectivity"})
        consumer.join(timeout=1)

        self.assertFalse(consumer.is_alive())
        self.assertEqual(result, [1])

    def test_close_wakes_consumers_and_rejects_future_publication(self) -> None:
        broker = SseEventBroker()
        broker.close()

        replay = broker.wait_after(0, timeout=0.1)
        self.assertTrue(replay.closed)
        with self.assertRaises(EventBrokerClosed):
            broker.publish("phase.changed", {})


if __name__ == "__main__":
    unittest.main()
