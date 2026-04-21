"""Bounded, read-only TCP reachability checks for expanded SMB targets."""

from __future__ import annotations

import errno
import socket
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from threading import Event
from time import perf_counter
from typing import Protocol

from nordis_smb_inspector.core.targets import (
    ExpandedTarget,
    IPAddress,
    ResolutionFailure,
    Resolver,
    TargetKind,
    TargetPlan,
)


class ConnectivityStatus(StrEnum):
    PORT_OPEN = "port_open"
    TIMEOUT_NO_RESPONSE = "timeout_no_response"
    CONNECTION_REFUSED = "connection_refused"
    NETWORK_UNREACHABLE = "network_unreachable"
    CONNECTION_ERROR = "connection_error"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ConnectivitySettings:
    port: int = 445
    timeout_seconds: float = 3.0
    max_concurrency: int = 32
    cancellation_poll_seconds: float = 0.05

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65_535:
            raise ValueError("port must be between 1 and 65535.")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be greater than zero.")
        if self.cancellation_poll_seconds <= 0:
            raise ValueError("cancellation_poll_seconds must be greater than zero.")


@dataclass(frozen=True, slots=True)
class ConnectivityResult:
    status: ConnectivityStatus
    source: str
    source_kind: TargetKind
    address: IPAddress | None = None
    source_hostname: str | None = None
    port: int = 445
    elapsed_ms: float | None = None
    os_error_code: int | None = None
    error_name: str | None = None
    message: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class CancellationProbe(Protocol):
    @property
    def requested(self) -> bool: ...


type Connector = Callable[[IPAddress, int, float], None]
type ResultCallback = Callable[[ConnectivityResult], None]


class _NeverCancelled:
    @property
    def requested(self) -> bool:
        return False


class EventCancellationProbe:
    """Adapter for callers that already own a :class:`threading.Event`."""

    def __init__(self, event: Event) -> None:
        self._event = event

    @property
    def requested(self) -> bool:
        return self._event.is_set()


class ConnectivityScanner:
    """Lazily schedule at most ``max_concurrency`` TCP connection attempts."""

    def __init__(
        self,
        settings: ConnectivitySettings | None = None,
        *,
        connector: Connector | None = None,
    ) -> None:
        self.settings = settings or ConnectivitySettings()
        self._connector = connector or socket_connector

    def iter_results(
        self,
        plan: TargetPlan,
        *,
        resolver: Resolver | None = None,
        cancellation: CancellationProbe | None = None,
        on_result: ResultCallback | None = None,
    ) -> Iterator[ConnectivityResult]:
        """Yield resolution and TCP results as soon as each is available.

        Target expansion is consumed on demand.  At most ``max_concurrency``
        successful expansions are held as pending futures, so large CIDRs do
        not become an in-memory target list.  Cancellation stops expansion and
        lets only already-running bounded attempts finish their socket timeout.
        """

        cancel = cancellation or _NeverCancelled()
        source = iter(plan.iter_scan_targets(resolver))
        pending: dict[Future[ConnectivityResult], ExpandedTarget] = {}
        source_exhausted = False
        executor = ThreadPoolExecutor(
            max_workers=self.settings.max_concurrency,
            thread_name_prefix="nordis-tcp445",
        )

        try:
            while True:
                while (
                    not source_exhausted
                    and not cancel.requested
                    and len(pending) < self.settings.max_concurrency
                ):
                    try:
                        event = next(source)
                    except StopIteration:
                        source_exhausted = True
                        break

                    if isinstance(event, ResolutionFailure):
                        result = self._resolution_result(event)
                        if on_result is not None:
                            on_result(result)
                        yield result
                        continue

                    future = executor.submit(self._probe, event, cancel)
                    pending[future] = event

                if cancel.requested:
                    for future in pending:
                        future.cancel()

                if not pending:
                    if source_exhausted or cancel.requested:
                        break
                    continue

                completed, _ = wait(
                    pending,
                    timeout=self.settings.cancellation_poll_seconds,
                    return_when=FIRST_COMPLETED,
                )
                if not completed:
                    continue

                for future in completed:
                    target = pending.pop(future)
                    if future.cancelled():
                        result = self._cancelled_result(target)
                    else:
                        result = future.result()
                    if on_result is not None:
                        on_result(result)
                    yield result
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

    def scan(
        self,
        plan: TargetPlan,
        on_result: ResultCallback,
        *,
        resolver: Resolver | None = None,
        cancellation: CancellationProbe | None = None,
    ) -> int:
        """Callback-oriented adapter returning the number of delivered rows."""

        delivered = 0
        for _result in self.iter_results(
            plan,
            resolver=resolver,
            cancellation=cancellation,
            on_result=on_result,
        ):
            delivered += 1
        return delivered

    def _probe(
        self,
        target: ExpandedTarget,
        cancellation: CancellationProbe,
    ) -> ConnectivityResult:
        if cancellation.requested:
            return self._cancelled_result(target)

        started = perf_counter()
        try:
            self._connector(
                target.address,
                self.settings.port,
                self.settings.timeout_seconds,
            )
        except Exception as exc:
            elapsed_ms = (perf_counter() - started) * 1_000
            return self._error_result(target, exc, elapsed_ms)

        return ConnectivityResult(
            status=ConnectivityStatus.PORT_OPEN,
            source=target.source,
            source_kind=target.source_kind,
            address=target.address,
            source_hostname=target.source_hostname,
            port=self.settings.port,
            elapsed_ms=(perf_counter() - started) * 1_000,
        )

    def _error_result(
        self,
        target: ExpandedTarget,
        error: Exception,
        elapsed_ms: float,
    ) -> ConnectivityResult:
        code = _os_error_code(error)
        status = _classify_error(error, code)
        return ConnectivityResult(
            status=status,
            source=target.source,
            source_kind=target.source_kind,
            address=target.address,
            source_hostname=target.source_hostname,
            port=self.settings.port,
            elapsed_ms=elapsed_ms,
            os_error_code=code,
            error_name=_error_name(error, code),
            message=str(error) or error.__class__.__name__,
        )

    def _resolution_result(self, failure: ResolutionFailure) -> ConnectivityResult:
        return ConnectivityResult(
            status=ConnectivityStatus.DNS_RESOLUTION_FAILED,
            source=failure.source,
            source_kind=TargetKind.HOSTNAME,
            source_hostname=failure.hostname,
            port=self.settings.port,
            error_name=failure.error_code,
            message=failure.message,
        )

    def _cancelled_result(self, target: ExpandedTarget) -> ConnectivityResult:
        return ConnectivityResult(
            status=ConnectivityStatus.CANCELLED,
            source=target.source,
            source_kind=target.source_kind,
            address=target.address,
            source_hostname=target.source_hostname,
            port=self.settings.port,
        )


def socket_connector(address: IPAddress, port: int, timeout_seconds: float) -> None:
    """Open and immediately close a TCP socket without sending application data."""

    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    endpoint = (
        (str(address), port, 0, 0)
        if family == socket.AF_INET6
        else (str(address), port)
    )

    connection = socket.socket(family, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout_seconds)
        connection.connect(endpoint)
    finally:
        connection.close()


_TIMEOUT_CODES = frozenset({errno.ETIMEDOUT, 10060})
_REFUSED_CODES = frozenset({errno.ECONNREFUSED, 10061})
_UNREACHABLE_CODES = frozenset(
    {
        errno.ENETDOWN,
        errno.ENETUNREACH,
        errno.EHOSTDOWN,
        errno.EHOSTUNREACH,
        errno.EADDRNOTAVAIL,
        10050,
        10051,
        10064,
        10065,
    }
)


def _classify_error(error: Exception, code: int | None) -> ConnectivityStatus:
    if isinstance(error, (TimeoutError, socket.timeout)) or code in _TIMEOUT_CODES:
        return ConnectivityStatus.TIMEOUT_NO_RESPONSE
    if isinstance(error, ConnectionRefusedError) or code in _REFUSED_CODES:
        return ConnectivityStatus.CONNECTION_REFUSED
    if code in _UNREACHABLE_CODES:
        return ConnectivityStatus.NETWORK_UNREACHABLE
    return ConnectivityStatus.CONNECTION_ERROR


def _os_error_code(error: Exception) -> int | None:
    winerror = getattr(error, "winerror", None)
    if isinstance(winerror, int):
        return winerror
    error_number = getattr(error, "errno", None)
    return error_number if isinstance(error_number, int) else None


def _error_name(error: Exception, code: int | None) -> str:
    if code is not None:
        return errno.errorcode.get(code, f"OS_ERROR_{code}")
    return error.__class__.__name__
