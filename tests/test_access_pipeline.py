from __future__ import annotations

import ipaddress
import socket
import threading
import unittest
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor

from nordis_smb_inspector.core.access_pipeline import (
    AccessEventKind,
    AccessPipelineExecutor,
    AccessPipelineSettings,
)
from nordis_smb_inspector.core.targets import ExpandedTarget, TargetKind, parse_targets
from nordis_smb_inspector.smb import NEVER_CANCELLED, CancellationFlag, ScanCancelled


class AccessPipelineSettingsTests(unittest.TestCase):
    def test_invalid_bounds_are_rejected(self) -> None:
        invalid = (
            {"max_concurrency": 0},
            {"max_concurrency": True},
            {"cancellation_poll_seconds": 0},
            {"cancellation_poll_seconds": float("inf")},
            {"cancellation_poll_seconds": float("nan")},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises((TypeError, ValueError)):
                AccessPipelineSettings(**changes)


class AccessPipelineExecutorTests(unittest.TestCase):
    def test_results_are_delivered_in_completion_order_to_iterator_and_callback(self) -> None:
        release_first = threading.Event()
        callback_results: list[str] = []

        def inspect(target: ExpandedTarget, _cancellation: object) -> str:
            if str(target.address) == "192.0.2.1" and not release_first.wait(1):
                raise AssertionError("second target did not finish")
            return f"result-{target.address}"

        def callback(event: object) -> None:
            callback_results.append(event.result)  # type: ignore[attr-defined]
            if event.address == ipaddress.ip_address("192.0.2.2"):  # type: ignore[attr-defined]
                release_first.set()

        executor = AccessPipelineExecutor(AccessPipelineSettings(max_concurrency=2))
        events = list(
            executor.iter_events(
                parse_targets("192.0.2.1,192.0.2.2"),
                inspect,
                on_event=callback,
            )
        )

        self.assertEqual(
            [str(event.address) for event in events],
            ["192.0.2.2", "192.0.2.1"],
        )
        self.assertEqual(callback_results, [event.result for event in events])
        self.assertTrue(
            all(event.kind is AccessEventKind.INSPECTION_COMPLETED for event in events)
        )

    def test_dns_failure_is_normalized_without_calling_inspector(self) -> None:
        calls = 0

        def resolver(_hostname: str) -> Sequence[str]:
            raise socket.gaierror(socket.EAI_NONAME, "secret resolver detail")

        def inspect(_target: ExpandedTarget, _cancellation: object) -> str:
            nonlocal calls
            calls += 1
            return "unexpected"

        events = list(
            AccessPipelineExecutor().iter_events(
                parse_targets("missing.example"),
                inspect,
                resolver=resolver,
            )
        )

        self.assertEqual(calls, 0)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIs(event.kind, AccessEventKind.DNS_RESOLUTION_FAILED)
        self.assertIsNone(event.address)
        self.assertEqual(event.source_hostname, "missing.example")
        self.assertEqual(event.error_code, "DNS_RESOLUTION_FAILED")
        self.assertNotIn("secret resolver detail", repr(event))

    def test_overlapping_targets_are_inspected_once(self) -> None:
        calls: list[str] = []

        def inspect(target: ExpandedTarget, _cancellation: object) -> str:
            calls.append(str(target.address))
            return str(target.address)

        plan = parse_targets("192.0.2.1,192.0.2.0/30,192.0.2.2")
        events = list(AccessPipelineExecutor().iter_events(plan, inspect))

        self.assertEqual(set(calls), {"192.0.2.1", "192.0.2.2"})
        self.assertEqual(len(events), 2)

    def test_lazy_consumption_and_concurrency_are_bounded(self) -> None:
        lock = threading.Lock()
        release = threading.Event()
        workers_ready = threading.Event()
        consumed = 0
        active = 0
        maximum_active = 0

        class CountingPlan:
            def iter_scan_targets(self, _resolver=None) -> Iterator[ExpandedTarget]:
                nonlocal consumed
                for number in range(1, 31):
                    with lock:
                        consumed += 1
                    yield ExpandedTarget(
                        ipaddress.ip_address(f"10.0.0.{number}"),
                        "10.0.0.0/24",
                        TargetKind.CIDR,
                    )

        def inspect(target: ExpandedTarget, _cancellation: object) -> str:
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 4:
                    workers_ready.set()
            if not release.wait(1):
                raise AssertionError("test failed to release workers")
            with lock:
                active -= 1
            return str(target.address)

        pipeline = AccessPipelineExecutor(AccessPipelineSettings(max_concurrency=4))
        with ThreadPoolExecutor(max_workers=1) as thread:
            future = thread.submit(
                list,
                pipeline.iter_events(CountingPlan(), inspect),  # type: ignore[arg-type]
            )
            self.assertTrue(workers_ready.wait(1))
            with lock:
                self.assertEqual(consumed, 4)
                self.assertEqual(active, 4)
            release.set()
            events = future.result(timeout=2)

        self.assertEqual(len(events), 30)
        self.assertEqual(maximum_active, 4)

    def test_cancellation_stops_expansion_and_is_passed_to_inspector(self) -> None:
        cancellation = CancellationFlag()
        release = threading.Event()
        workers_ready = threading.Event()
        lock = threading.Lock()
        consumed = 0
        seen_tokens: list[object] = []

        class CountingPlan:
            def iter_scan_targets(self, _resolver=None) -> Iterator[ExpandedTarget]:
                nonlocal consumed
                for number in range(1, 101):
                    with lock:
                        consumed += 1
                    yield ExpandedTarget(
                        ipaddress.ip_address(f"10.0.0.{number}"),
                        "10.0.0.0/24",
                        TargetKind.CIDR,
                    )

        def inspect(_target: ExpandedTarget, token: object) -> str:
            with lock:
                seen_tokens.append(token)
                if len(seen_tokens) == 2:
                    workers_ready.set()
            if not release.wait(1):
                raise AssertionError("test failed to release workers")
            token.raise_if_cancelled()  # type: ignore[attr-defined]
            return "unexpected"

        pipeline = AccessPipelineExecutor(
            AccessPipelineSettings(max_concurrency=2, cancellation_poll_seconds=0.01)
        )
        with ThreadPoolExecutor(max_workers=1) as thread:
            future = thread.submit(
                list,
                pipeline.iter_events(
                    CountingPlan(),  # type: ignore[arg-type]
                    inspect,
                    cancellation=cancellation,
                ),
            )
            self.assertTrue(workers_ready.wait(1))
            cancellation.cancel()
            release.set()
            events = future.result(timeout=2)

        with lock:
            self.assertEqual(consumed, 2)
        self.assertEqual(seen_tokens, [cancellation, cancellation])
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event.kind is AccessEventKind.CANCELLED for event in events))

    def test_pre_cancelled_scan_does_not_consume_targets(self) -> None:
        cancellation = CancellationFlag()
        cancellation.cancel()
        calls = 0

        def inspect(_target: ExpandedTarget, _token: object) -> str:
            nonlocal calls
            calls += 1
            return "unexpected"

        events = list(
            AccessPipelineExecutor().iter_events(
                parse_targets("203.0.113.0/24"),
                inspect,
                cancellation=cancellation,
            )
        )

        self.assertEqual(events, [])
        self.assertEqual(calls, 0)

    def test_worker_scan_cancelled_exception_is_normalized(self) -> None:
        def inspect(_target: ExpandedTarget, _token: object) -> str:
            raise ScanCancelled()

        events = list(
            AccessPipelineExecutor().iter_events(
                parse_targets("192.0.2.1"),
                inspect,
            )
        )

        self.assertIs(events[0].kind, AccessEventKind.CANCELLED)
        self.assertEqual(events[0].error_code, "CANCELLED")

    def test_unexpected_exception_is_safe_failure(self) -> None:
        secret = "password=DoNotReflect"

        def inspect(_target: ExpandedTarget, _token: object) -> str:
            raise RuntimeError(secret)

        event = list(
            AccessPipelineExecutor().iter_events(parse_targets("192.0.2.1"), inspect)
        )[0]

        self.assertIs(event.kind, AccessEventKind.INSPECTION_FAILED)
        self.assertEqual(event.error_code, "INSPECTOR_ERROR")
        self.assertNotIn(secret, repr(event))
        self.assertFalse(hasattr(event, "message"))

    def test_executor_never_stores_inspection_closure_or_sensitive_result(self) -> None:
        secret = "credential-and-finding-secret"
        executor = AccessPipelineExecutor()

        def inspect(_target: ExpandedTarget, _token: object) -> str:
            return secret

        event = list(
            executor.iter_events(
                parse_targets("192.0.2.1"),
                inspect,
                cancellation=NEVER_CANCELLED,
            )
        )[0]

        self.assertEqual(event.result, secret)
        self.assertNotIn(secret, repr(event))
        self.assertNotIn(secret, repr(executor))
        self.assertEqual(AccessPipelineExecutor.__slots__, ("settings",))

    def test_callback_run_adapter_returns_delivered_count(self) -> None:
        received: list[str] = []

        count = AccessPipelineExecutor().run(
            parse_targets("192.0.2.1,192.0.2.2"),
            lambda target, _token: str(target.address),
            lambda event: received.append(event.result or ""),
        )

        self.assertEqual(count, 2)
        self.assertEqual(set(received), {"192.0.2.1", "192.0.2.2"})

    def test_none_is_a_valid_caller_defined_completion_result(self) -> None:
        event = list(
            AccessPipelineExecutor().iter_events(
                parse_targets("192.0.2.1"),
                lambda _target, _token: None,
            )
        )[0]

        self.assertIs(event.kind, AccessEventKind.INSPECTION_COMPLETED)
        self.assertIsNone(event.result)


if __name__ == "__main__":
    unittest.main()
