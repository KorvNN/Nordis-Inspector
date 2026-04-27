"""Generic bounded executor for complete per-target SMB inspection work.

The helper knows nothing about credentials, authentication mechanisms, shares,
or files.  A caller-provided ``inspect_one`` closure owns those concerns and is
invoked once for each lazily expanded target.  This module retains no closure,
result list, log, or persistence hook after iteration finishes.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeVar

from nordis_smb_inspector.core.targets import (
    ExpandedTarget,
    IPAddress,
    ResolutionFailure,
    Resolver,
    TargetKind,
    TargetPlan,
)
from nordis_smb_inspector.smb.cancellation import (
    NEVER_CANCELLED,
    CancellationToken,
    ScanCancelled,
)

ResultT = TypeVar("ResultT")


class AccessEventKind(StrEnum):
    INSPECTION_COMPLETED = "inspection_completed"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    INSPECTION_FAILED = "inspection_failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class AccessPipelineSettings:
    max_concurrency: int = 16
    cancellation_poll_seconds: float = 0.05

    def __post_init__(self) -> None:
        if isinstance(self.max_concurrency, bool) or not isinstance(
            self.max_concurrency, int
        ):
            raise TypeError("max_concurrency must be an integer.")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be greater than zero.")
        if (
            isinstance(self.cancellation_poll_seconds, bool)
            or not isinstance(self.cancellation_poll_seconds, (int, float))
            or not math.isfinite(self.cancellation_poll_seconds)
            or self.cancellation_poll_seconds <= 0
        ):
            raise ValueError("cancellation_poll_seconds must be finite and positive.")


@dataclass(frozen=True, slots=True, repr=False)
class AccessPipelineEvent[ResultT]:
    """One normalized expansion or inspection outcome.

    ``result`` is available to the live caller but intentionally absent from
    ``repr``.  The target and DNS source are redacted for the same reason.
    """

    kind: AccessEventKind
    address: IPAddress | None = field(default=None, repr=False)
    source: str = field(default="", repr=False)
    source_kind: TargetKind = TargetKind.IP
    source_hostname: str | None = field(default=None, repr=False)
    result: ResultT | None = field(default=None, repr=False)
    error_code: str | None = None
    emitted_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("source must be non-empty text.")
        if self.kind is AccessEventKind.INSPECTION_COMPLETED:
            if self.address is None:
                raise ValueError("A completed inspection requires an address.")
            if self.error_code is not None:
                raise ValueError("A completed inspection cannot contain an error code.")
        elif self.result is not None:
            raise ValueError("Only completed inspections may contain a result.")

        if self.kind is AccessEventKind.DNS_RESOLUTION_FAILED:
            if self.address is not None or self.source_kind is not TargetKind.HOSTNAME:
                raise ValueError("A DNS failure must identify an unresolved hostname.")
            if not self.source_hostname:
                raise ValueError("A DNS failure requires its source hostname.")
            if not self.error_code:
                raise ValueError("A DNS failure requires a normalized error code.")
        elif self.address is None:
            raise ValueError("A target inspection event requires an address.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(kind={self.kind.value!r}, "
            "address=<redacted>, source=<redacted>, source_hostname=<redacted>, "
            f"source_kind={self.source_kind.value!r}, result=<redacted>, "
            f"error_code={self.error_code!r})"
        )


type InspectOne[ResultT] = Callable[[ExpandedTarget, CancellationToken], ResultT]
type AccessEventCallback[ResultT] = Callable[[AccessPipelineEvent[ResultT]], None]


class AccessPipelineExecutor:
    """Run one injected full inspection per target with bounded concurrency."""

    __slots__ = ("settings",)

    def __init__(self, settings: AccessPipelineSettings | None = None) -> None:
        self.settings = settings or AccessPipelineSettings()

    def iter_events(
        self,
        plan: TargetPlan,
        inspect_one: InspectOne[ResultT],
        *,
        resolver: Resolver | None = None,
        cancellation: CancellationToken = NEVER_CANCELLED,
        on_event: AccessEventCallback[ResultT] | None = None,
    ) -> Iterator[AccessPipelineEvent[ResultT]]:
        """Yield normalized events in completion order without accumulating them."""

        if not callable(inspect_one):
            raise TypeError("inspect_one must be callable.")

        source = iter(plan.iter_scan_targets(resolver))
        pending: dict[Future[ResultT], ExpandedTarget] = {}
        source_exhausted = False
        executor = ThreadPoolExecutor(
            max_workers=self.settings.max_concurrency,
            thread_name_prefix="nordis-target-access",
        )

        try:
            while True:
                while (
                    not source_exhausted
                    and not cancellation.cancelled
                    and len(pending) < self.settings.max_concurrency
                ):
                    try:
                        target = next(source)
                    except StopIteration:
                        source_exhausted = True
                        break

                    if isinstance(target, ResolutionFailure):
                        event = self._dns_failure(target)
                        self._notify(on_event, event)
                        yield event
                        continue

                    pending[executor.submit(inspect_one, target, cancellation)] = target

                if cancellation.cancelled:
                    for future in pending:
                        future.cancel()

                if not pending:
                    if source_exhausted or cancellation.cancelled:
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
                    event = self._future_event(future, target)
                    self._notify(on_event, event)
                    yield event
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

    def run(
        self,
        plan: TargetPlan,
        inspect_one: InspectOne[ResultT],
        on_event: AccessEventCallback[ResultT],
        *,
        resolver: Resolver | None = None,
        cancellation: CancellationToken = NEVER_CANCELLED,
    ) -> int:
        """Callback-oriented adapter returning the delivered event count."""

        delivered = 0
        for _event in self.iter_events(
            plan,
            inspect_one,
            resolver=resolver,
            cancellation=cancellation,
            on_event=on_event,
        ):
            delivered += 1
        return delivered

    @staticmethod
    def _future_event(
        future: Future[ResultT],
        target: ExpandedTarget,
    ) -> AccessPipelineEvent[ResultT]:
        if future.cancelled():
            return AccessPipelineExecutor._cancelled(target)
        try:
            result = future.result()
        except ScanCancelled:
            return AccessPipelineExecutor._cancelled(target)
        except Exception:
            # The target worker owns richer domain-specific normalization.  A
            # leaked exception is reduced to a stable code with no raw text.
            return AccessPipelineEvent(
                kind=AccessEventKind.INSPECTION_FAILED,
                address=target.address,
                source=target.source,
                source_kind=target.source_kind,
                source_hostname=target.source_hostname,
                error_code="INSPECTOR_ERROR",
            )
        return AccessPipelineEvent(
            kind=AccessEventKind.INSPECTION_COMPLETED,
            address=target.address,
            source=target.source,
            source_kind=target.source_kind,
            source_hostname=target.source_hostname,
            result=result,
        )

    @staticmethod
    def _dns_failure(failure: ResolutionFailure) -> AccessPipelineEvent[ResultT]:
        return AccessPipelineEvent(
            kind=AccessEventKind.DNS_RESOLUTION_FAILED,
            source=failure.source,
            source_kind=TargetKind.HOSTNAME,
            source_hostname=failure.hostname,
            error_code=failure.error_code,
        )

    @staticmethod
    def _cancelled(target: ExpandedTarget) -> AccessPipelineEvent[ResultT]:
        return AccessPipelineEvent(
            kind=AccessEventKind.CANCELLED,
            address=target.address,
            source=target.source,
            source_kind=target.source_kind,
            source_hostname=target.source_hostname,
            error_code="CANCELLED",
        )

    @staticmethod
    def _notify(
        callback: AccessEventCallback[ResultT] | None,
        event: AccessPipelineEvent[ResultT],
    ) -> None:
        if callback is not None:
            callback(event)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(settings={self.settings!r})"
