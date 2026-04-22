from __future__ import annotations

import errno
import ipaddress
import socket
import threading
import unittest
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from nordis_smb_inspector.core.connectivity import ConnectivityStatus
from nordis_smb_inspector.core.pipeline import (
    AuthenticationPlaceholder,
    PipelineSettings,
    PipelineState,
    PipelineStateEvent,
    PipelineTargetEvent,
    PipelineTargetStatus,
    ScanPipeline,
    SmbPipelineStatus,
)
from nordis_smb_inspector.core.targets import ExpandedTarget, TargetKind, parse_targets
from nordis_smb_inspector.smb import NEVER_CANCELLED, CancellationFlag
from nordis_smb_inspector.smb.models import (
    AlgorithmSource,
    NegotiationInfo,
    SecurityFeatureState,
    SmbDialect,
    SmbErrorDetail,
    TargetOutcome,
    TargetStage,
    TargetStatus,
    TransportSecurity,
)


class _FakeConnectError(ConnectionError):
    def __init__(self, outcome: TargetOutcome) -> None:
        self.outcome = outcome
        super().__init__("Safe normalized failure.")


def _negotiation(dialect: SmbDialect = SmbDialect.SMB_3_1_1) -> NegotiationInfo:
    signing = SecurityFeatureState(
        supported=True,
        required=True,
        active=None,
        algorithm="AES-128-GMAC",
        algorithm_source=AlgorithmSource.NEGOTIATED,
    )
    encryption = SecurityFeatureState(
        supported=True,
        required=None,
        active=None,
        algorithm="AES-128-GCM",
        algorithm_source=AlgorithmSource.NEGOTIATED,
    )
    return NegotiationInfo(
        dialect=dialect,
        security=TransportSecurity(signing=signing, encryption=encryption),
        max_read_size=1_048_576,
    )


@dataclass
class _FakeHandle:
    negotiation: NegotiationInfo
    closed: bool = False

    def close(self) -> None:
        self.closed = True


class _FakeConnector:
    def __init__(self, outcomes: dict[str, object] | None = None) -> None:
        self.outcomes = outcomes or {}
        self.calls: list[object] = []
        self.handles: list[_FakeHandle] = []

    def connect(self, request, *, cancellation):
        cancellation.raise_if_cancelled()
        self.calls.append(request)
        outcome = self.outcomes.get(request.target)
        if isinstance(outcome, BaseException):
            raise outcome
        negotiation = outcome if isinstance(outcome, NegotiationInfo) else _negotiation()
        handle = _FakeHandle(negotiation)
        self.handles.append(handle)
        return handle


def _connect_error(target: str, status: TargetStatus) -> _FakeConnectError:
    stage = (
        TargetStage.NETWORK
        if status
        in {
            TargetStatus.TIMEOUT_NO_RESPONSE,
            TargetStatus.CONNECTION_REFUSED,
            TargetStatus.NETWORK_UNREACHABLE,
        }
        else TargetStage.NEGOTIATION
    )
    code = {
        TargetStatus.TIMEOUT_NO_RESPONSE: errno.ETIMEDOUT,
        TargetStatus.CONNECTION_REFUSED: errno.ECONNREFUSED,
        TargetStatus.NETWORK_UNREACHABLE: errno.EHOSTUNREACH,
    }.get(status, errno.EPROTO)
    error = SmbErrorDetail(
        stage=stage,
        status=status,
        operation="connect" if stage is TargetStage.NETWORK else "negotiate",
        raw_code=code,
        safe_message="Safe normalized failure.",
    )
    return _FakeConnectError(
        TargetOutcome(target=target, stage=stage, status=status, error=error)
    )


class PipelineSettingsTests(unittest.TestCase):
    def test_invalid_transport_and_concurrency_values_are_rejected(self) -> None:
        invalid = (
            {"port": 0},
            {"timeout_seconds": 0},
            {"max_concurrency": 0},
            {"max_concurrency": True},
            {"cancellation_poll_seconds": 0},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises((TypeError, ValueError)):
                PipelineSettings(**changes)


class ScanPipelineTests(unittest.TestCase):
    def test_success_reports_tcp_smb_dialect_and_awaiting_credentials(self) -> None:
        connector = _FakeConnector(
            {"192.0.2.1": _negotiation(SmbDialect.SMB_3_0_2)}
        )
        callback_events: list[object] = []
        pipeline = ScanPipeline(connector=connector)

        events = list(
            pipeline.iter_events(
                parse_targets("192.0.2.1"),
                on_event=callback_events.append,
            )
        )

        target = events[1]
        self.assertIsInstance(target, PipelineTargetEvent)
        self.assertEqual(target.address, ipaddress.ip_address("192.0.2.1"))
        self.assertIs(target.tcp_status, ConnectivityStatus.PORT_OPEN)
        self.assertIs(target.smb_status, SmbPipelineStatus.NEGOTIATED)
        self.assertIs(target.dialect, SmbDialect.SMB_3_0_2)
        self.assertIs(
            target.auth_status,
            AuthenticationPlaceholder.AWAITING_CREDENTIALS,
        )
        self.assertIs(target.last_status, PipelineTargetStatus.AWAITING_CREDENTIALS)
        final = events[-1]
        self.assertIsInstance(final, PipelineStateEvent)
        self.assertIs(final.state, PipelineState.AWAITING_CREDENTIALS)
        self.assertFalse(final.terminal)
        self.assertEqual(final.target_results, 1)
        self.assertEqual(final.negotiated_targets, 1)
        self.assertEqual(callback_events, events)
        self.assertTrue(connector.handles[0].closed)

    def test_credentials_available_only_marks_negotiation_handoff_not_scan_complete(self) -> None:
        events = list(
            ScanPipeline(connector=_FakeConnector()).iter_events(
                parse_targets("192.0.2.1"),
                credentials_available=True,
            )
        )

        target = events[1]
        self.assertIs(target.auth_status, AuthenticationPlaceholder.NOT_ATTEMPTED)
        self.assertIs(target.last_status, PipelineTargetStatus.NEGOTIATION_COMPLETE)
        final = events[-1]
        self.assertIs(final.state, PipelineState.NEGOTIATION_COMPLETE)
        self.assertFalse(final.terminal)
        self.assertNotEqual(final.state.value, "completed")

    def test_normalized_network_and_negotiation_failures_are_preserved(self) -> None:
        outcomes = {
            "192.0.2.1": _connect_error(
                "192.0.2.1", TargetStatus.CONNECTION_REFUSED
            ),
            "192.0.2.2": _connect_error(
                "192.0.2.2", TargetStatus.TIMEOUT_NO_RESPONSE
            ),
            "192.0.2.3": _connect_error(
                "192.0.2.3", TargetStatus.NETWORK_UNREACHABLE
            ),
            "192.0.2.4": _connect_error(
                "192.0.2.4", TargetStatus.NEGOTIATION_FAILED
            ),
        }
        pipeline = ScanPipeline(connector=_FakeConnector(outcomes))
        events = [
            event
            for event in pipeline.iter_events(parse_targets("192.0.2.0/29"))
            if isinstance(event, PipelineTargetEvent)
        ]
        by_ip = {str(event.address): event for event in events}

        self.assertIs(
            by_ip["192.0.2.1"].tcp_status,
            ConnectivityStatus.CONNECTION_REFUSED,
        )
        self.assertIs(by_ip["192.0.2.1"].smb_status, SmbPipelineStatus.NOT_ATTEMPTED)
        self.assertIs(
            by_ip["192.0.2.2"].tcp_status,
            ConnectivityStatus.TIMEOUT_NO_RESPONSE,
        )
        self.assertIs(
            by_ip["192.0.2.3"].tcp_status,
            ConnectivityStatus.NETWORK_UNREACHABLE,
        )
        self.assertIs(by_ip["192.0.2.4"].tcp_status, ConnectivityStatus.PORT_OPEN)
        self.assertIs(
            by_ip["192.0.2.4"].smb_status,
            SmbPipelineStatus.NEGOTIATION_FAILED,
        )
        self.assertIs(
            by_ip["192.0.2.4"].last_status,
            PipelineTargetStatus.NEGOTIATION_FAILED,
        )

    def test_dns_failure_does_not_call_connector(self) -> None:
        connector = _FakeConnector()

        def resolver(_hostname: str) -> Sequence[str]:
            raise socket.gaierror(socket.EAI_NONAME, "missing")

        events = list(
            ScanPipeline(connector=connector).iter_events(
                parse_targets("missing.example"),
                resolver=resolver,
            )
        )

        target = events[1]
        self.assertIs(target.tcp_status, ConnectivityStatus.DNS_RESOLUTION_FAILED)
        self.assertIs(target.smb_status, SmbPipelineStatus.NOT_ATTEMPTED)
        self.assertIs(target.last_status, PipelineTargetStatus.DNS_RESOLUTION_FAILED)
        self.assertEqual(connector.calls, [])

    def test_pipeline_does_not_run_a_separate_tcp_probe(self) -> None:
        connector = _FakeConnector()
        pipeline = ScanPipeline(connector=connector)

        list(pipeline.iter_events(parse_targets("192.0.2.1,192.0.2.2")))

        self.assertEqual(len(connector.calls), 2)
        self.assertEqual(
            {request.target for request in connector.calls},
            {"192.0.2.1", "192.0.2.2"},
        )

    def test_connector_exception_text_is_not_reflected_or_represented(self) -> None:
        secret = "server=192.0.2.1 password=SuperSecret"
        connector = _FakeConnector({"192.0.2.1": RuntimeError(secret)})

        events = list(
            ScanPipeline(connector=connector).iter_events(parse_targets("192.0.2.1"))
        )
        target = events[1]

        self.assertIs(target.last_status, PipelineTargetStatus.CONNECTOR_ERROR)
        self.assertNotIn(secret, repr(target))
        self.assertFalse(hasattr(target, "message"))

    def test_targets_are_lazy_and_concurrency_is_bounded(self) -> None:
        lock = threading.Lock()
        release = threading.Event()
        workers_ready = threading.Event()
        consumed = 0
        active = 0
        maximum_active = 0

        class CountingPlan:
            def iter_scan_targets(self, _resolver=None) -> Iterator[ExpandedTarget]:
                nonlocal consumed
                for number in range(1, 21):
                    with lock:
                        consumed += 1
                    yield ExpandedTarget(
                        ipaddress.ip_address(f"10.0.0.{number}"),
                        "10.0.0.0/24",
                        TargetKind.CIDR,
                    )

        class BlockingConnector(_FakeConnector):
            def connect(self, request, *, cancellation):
                nonlocal active, maximum_active
                with lock:
                    active += 1
                    maximum_active = max(maximum_active, active)
                    if active == 3:
                        workers_ready.set()
                if not release.wait(1):
                    raise AssertionError("test failed to release workers")
                with lock:
                    active -= 1
                return super().connect(request, cancellation=cancellation)

        pipeline = ScanPipeline(
            PipelineSettings(max_concurrency=3),
            connector=BlockingConnector(),
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                list,
                pipeline.iter_events(CountingPlan()),  # type: ignore[arg-type]
            )
            self.assertTrue(workers_ready.wait(1))
            with lock:
                self.assertEqual(consumed, 3)
                self.assertEqual(active, 3)
            release.set()
            events = future.result(timeout=2)

        targets = [event for event in events if isinstance(event, PipelineTargetEvent)]
        self.assertEqual(len(targets), 20)
        self.assertEqual(maximum_active, 3)

    def test_cooperative_cancellation_stops_target_expansion(self) -> None:
        cancellation = CancellationFlag()
        release = threading.Event()
        workers_ready = threading.Event()
        lock = threading.Lock()
        consumed = 0
        started = 0

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

        class BlockingConnector(_FakeConnector):
            def connect(self, request, *, cancellation):
                nonlocal started
                with lock:
                    started += 1
                    if started == 2:
                        workers_ready.set()
                if not release.wait(1):
                    raise AssertionError("test failed to release workers")
                return super().connect(request, cancellation=cancellation)

        pipeline = ScanPipeline(
            PipelineSettings(max_concurrency=2, cancellation_poll_seconds=0.01),
            connector=BlockingConnector(),
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                list,
                pipeline.iter_events(
                    CountingPlan(),  # type: ignore[arg-type]
                    cancellation=cancellation,
                ),
            )
            self.assertTrue(workers_ready.wait(1))
            cancellation.cancel()
            release.set()
            events = future.result(timeout=2)

        with lock:
            self.assertEqual(consumed, 2)
        final = events[-1]
        self.assertIsInstance(final, PipelineStateEvent)
        self.assertIs(final.state, PipelineState.CANCELLED)
        self.assertTrue(final.terminal)

    def test_cancelled_before_start_never_calls_connector(self) -> None:
        cancellation = CancellationFlag()
        cancellation.cancel()
        connector = _FakeConnector()

        events = list(
            ScanPipeline(connector=connector).iter_events(
                parse_targets("192.0.2.0/24"),
                cancellation=cancellation,
            )
        )

        self.assertEqual(connector.calls, [])
        self.assertEqual(len(events), 2)
        self.assertIs(events[0].state, PipelineState.NEGOTIATING)
        self.assertIs(events[-1].state, PipelineState.CANCELLED)

    def test_default_cancellation_token_is_usable(self) -> None:
        events = list(
            ScanPipeline(connector=_FakeConnector()).iter_events(
                parse_targets("192.0.2.1"),
                cancellation=NEVER_CANCELLED,
            )
        )

        self.assertIs(events[-1].state, PipelineState.AWAITING_CREDENTIALS)


if __name__ == "__main__":
    unittest.main()
