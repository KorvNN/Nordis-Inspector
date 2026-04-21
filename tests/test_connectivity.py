from __future__ import annotations

import errno
import ipaddress
import socket
import threading
import unittest
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor

from nordis_smb_inspector.core.connectivity import (
    ConnectivityScanner,
    ConnectivitySettings,
    ConnectivityStatus,
    EventCancellationProbe,
)
from nordis_smb_inspector.core.targets import ExpandedTarget, TargetKind, parse_targets


class ConnectivitySettingsTests(unittest.TestCase):
    def test_invalid_bounds_are_rejected(self) -> None:
        invalid = (
            {"port": 0},
            {"port": 65_536},
            {"timeout_seconds": 0},
            {"max_concurrency": 0},
            {"cancellation_poll_seconds": 0},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ConnectivitySettings(**changes)


class ConnectivityScannerTests(unittest.TestCase):
    def test_network_outcomes_are_classified_without_real_connections(self) -> None:
        outcomes: dict[str, Exception | None] = {
            "192.0.2.1": None,
            "192.0.2.2": TimeoutError("no reply"),
            "192.0.2.3": ConnectionRefusedError(errno.ECONNREFUSED, "refused"),
            "192.0.2.4": OSError(errno.EHOSTUNREACH, "no route"),
            "192.0.2.5": OSError(errno.ECONNRESET, "reset"),
        }
        calls: list[tuple[str, int, float]] = []

        def connector(address: object, port: int, timeout: float) -> None:
            calls.append((str(address), port, timeout))
            outcome = outcomes[str(address)]
            if outcome is not None:
                raise outcome

        scanner = ConnectivityScanner(
            ConnectivitySettings(port=445, timeout_seconds=1.25, max_concurrency=3),
            connector=connector,
        )
        results = list(scanner.iter_results(parse_targets("192.0.2.0/29")))
        by_address = {str(result.address): result for result in results}

        self.assertEqual(by_address["192.0.2.1"].status, ConnectivityStatus.PORT_OPEN)
        self.assertEqual(
            by_address["192.0.2.2"].status,
            ConnectivityStatus.TIMEOUT_NO_RESPONSE,
        )
        self.assertEqual(
            by_address["192.0.2.3"].status,
            ConnectivityStatus.CONNECTION_REFUSED,
        )
        self.assertEqual(
            by_address["192.0.2.4"].status,
            ConnectivityStatus.NETWORK_UNREACHABLE,
        )
        self.assertEqual(
            by_address["192.0.2.5"].status,
            ConnectivityStatus.CONNECTION_ERROR,
        )
        self.assertEqual(by_address["192.0.2.3"].os_error_code, errno.ECONNREFUSED)
        self.assertEqual(by_address["192.0.2.3"].error_name, "ECONNREFUSED")
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(port == 445 and timeout == 1.25 for _, port, timeout in calls))

    def test_dns_failure_is_a_result_and_never_calls_connector(self) -> None:
        connector_calls = 0

        def resolver(_hostname: str) -> Sequence[str]:
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        def connector(_address: object, _port: int, _timeout: float) -> None:
            nonlocal connector_calls
            connector_calls += 1

        scanner = ConnectivityScanner(connector=connector)
        results = list(
            scanner.iter_results(parse_targets("missing.example"), resolver=resolver)
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ConnectivityStatus.DNS_RESOLUTION_FAILED)
        self.assertEqual(results[0].source_hostname, "missing.example")
        self.assertEqual(results[0].error_name, "DNS_RESOLUTION_FAILED")
        self.assertEqual(connector_calls, 0)

    def test_overlapping_target_sources_are_connected_only_once(self) -> None:
        called: list[str] = []

        def connector(address: object, _port: int, _timeout: float) -> None:
            called.append(str(address))

        scanner = ConnectivityScanner(connector=connector)
        plan = parse_targets("192.0.2.1, 192.0.2.0/30, 192.0.2.2")

        results = list(scanner.iter_results(plan))

        self.assertEqual(set(called), {"192.0.2.1", "192.0.2.2"})
        self.assertEqual(len(results), 2)

    def test_completion_callback_and_iterator_have_the_same_order(self) -> None:
        first_can_finish = threading.Event()
        callback_order: list[str] = []

        def connector(address: object, _port: int, _timeout: float) -> None:
            if str(address) == "192.0.2.1" and not first_can_finish.wait(1):
                raise AssertionError("second result was not delivered")

        def on_result(result: object) -> None:
            address = str(result.address)  # type: ignore[attr-defined]
            callback_order.append(address)
            if address == "192.0.2.2":
                first_can_finish.set()

        scanner = ConnectivityScanner(
            ConnectivitySettings(max_concurrency=2),
            connector=connector,
        )
        iterator_order = [
            str(result.address)
            for result in scanner.iter_results(
                parse_targets("192.0.2.1,192.0.2.2"),
                on_result=on_result,
            )
        ]

        self.assertEqual(iterator_order, ["192.0.2.2", "192.0.2.1"])
        self.assertEqual(callback_order, iterator_order)

    def test_scan_callback_adapter_does_not_accumulate_another_result_list(self) -> None:
        delivered: list[str] = []
        scanner = ConnectivityScanner(connector=lambda _address, _port, _timeout: None)

        count = scanner.scan(
            parse_targets("192.0.2.1,192.0.2.2"),
            lambda result: delivered.append(str(result.address)),
        )

        self.assertEqual(count, 2)
        self.assertEqual(set(delivered), {"192.0.2.1", "192.0.2.2"})

    def test_concurrency_is_bounded(self) -> None:
        lock = threading.Lock()
        release = threading.Event()
        all_workers_active = threading.Event()
        active = 0
        maximum_active = 0

        def connector(_address: object, _port: int, _timeout: float) -> None:
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 3:
                    all_workers_active.set()
            if not release.wait(1):
                raise AssertionError("test did not release connector")
            with lock:
                active -= 1

        scanner = ConnectivityScanner(
            ConnectivitySettings(max_concurrency=3),
            connector=connector,
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                list,
                scanner.iter_results(parse_targets("198.51.100.0/28")),
            )
            self.assertTrue(all_workers_active.wait(1))
            with lock:
                self.assertEqual(active, 3)
                self.assertEqual(maximum_active, 3)
            release.set()
            results = future.result(timeout=2)

        self.assertEqual(len(results), 14)
        self.assertLessEqual(maximum_active, 3)

    def test_cancellation_stops_lazy_target_consumption(self) -> None:
        consumed = 0
        consumed_lock = threading.Lock()
        workers_started = threading.Event()
        release_workers = threading.Event()
        active_workers = 0
        cancel_event = threading.Event()

        class CountingPlan:
            def iter_scan_targets(self, _resolver: object = None) -> Iterator[ExpandedTarget]:
                nonlocal consumed
                for number in range(1, 101):
                    with consumed_lock:
                        consumed += 1
                    yield ExpandedTarget(
                        address=ipaddress.ip_address(f"10.0.0.{number}"),
                        source="10.0.0.0/24",
                        source_kind=TargetKind.CIDR,
                    )

        def connector(_address: object, _port: int, _timeout: float) -> None:
            nonlocal active_workers
            with consumed_lock:
                active_workers += 1
                if active_workers == 2:
                    workers_started.set()
            if not release_workers.wait(1):
                raise AssertionError("test did not release connector")

        scanner = ConnectivityScanner(
            ConnectivitySettings(max_concurrency=2, cancellation_poll_seconds=0.01),
            connector=connector,
        )
        cancellation = EventCancellationProbe(cancel_event)

        with ThreadPoolExecutor(max_workers=1) as executor:
            plan = CountingPlan()
            future = executor.submit(
                list,
                scanner.iter_results(plan, cancellation=cancellation),  # type: ignore[arg-type]
            )
            self.assertTrue(workers_started.wait(1))
            cancel_event.set()
            release_workers.set()
            results = future.result(timeout=2)

        with consumed_lock:
            self.assertEqual(consumed, 2)
        self.assertEqual(len(results), 2)
        self.assertTrue(
            all(
                result.status in {ConnectivityStatus.PORT_OPEN, ConnectivityStatus.CANCELLED}
                for result in results
            )
        )

    def test_cancelled_before_iteration_does_not_consume_plan(self) -> None:
        cancel_event = threading.Event()
        cancel_event.set()
        connector_calls = 0

        def connector(_address: object, _port: int, _timeout: float) -> None:
            nonlocal connector_calls
            connector_calls += 1

        scanner = ConnectivityScanner(connector=connector)
        results = list(
            scanner.iter_results(
                parse_targets("203.0.113.0/24"),
                cancellation=EventCancellationProbe(cancel_event),
            )
        )

        self.assertEqual(results, [])
        self.assertEqual(connector_calls, 0)


if __name__ == "__main__":
    unittest.main()
