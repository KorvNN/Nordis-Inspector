"""Framework-neutral, bounded scan pipeline through SMB negotiation.

This stage intentionally calls the SMB connector directly: its ``connect``
operation already performs TCP connection and SMB negotiation, so a separate
TCP probe would duplicate every successful connection.  Authentication is the
next pipeline stage and is represented explicitly, never implied as complete.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from nordis_smb_inspector.core.connectivity import ConnectivityStatus
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
from nordis_smb_inspector.smb.contracts import ConnectRequest, ReadOnlyConnector
from nordis_smb_inspector.smb.models import (
    SmbDialect,
    TargetOutcome,
    TargetStage,
    TargetStatus,
)


class PipelineState(StrEnum):
    NEGOTIATING = "negotiating"
    NEGOTIATION_COMPLETE = "negotiation_complete"
    AWAITING_CREDENTIALS = "awaiting_credentials"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self is PipelineState.CANCELLED


class SmbPipelineStatus(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    NEGOTIATED = "negotiated"
    NEGOTIATION_FAILED = "negotiation_failed"
    SMB1_ONLY_UNSUPPORTED = "smb1_only_unsupported"


class AuthenticationPlaceholder(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    AWAITING_CREDENTIALS = "awaiting_credentials"


class PipelineTargetStatus(StrEnum):
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    TIMEOUT_NO_RESPONSE = "timeout_no_response"
    CONNECTION_REFUSED = "connection_refused"
    NETWORK_UNREACHABLE = "network_unreachable"
    NEGOTIATION_FAILED = "negotiation_failed"
    SMB1_ONLY_UNSUPPORTED = "smb1_only_unsupported"
    NEGOTIATION_COMPLETE = "negotiation_complete"
    AWAITING_CREDENTIALS = "awaiting_credentials"
    CANCELLED = "cancelled"
    CONNECTOR_ERROR = "connector_error"


@dataclass(frozen=True, slots=True)
class PipelineSettings:
    port: int = 445
    timeout_seconds: float = 5.0
    max_concurrency: int = 32
    cancellation_poll_seconds: float = 0.05
    require_signing: bool = True
    require_encryption: bool = False
    require_secure_negotiate: bool = True

    def __post_init__(self) -> None:
        # Reuse the adapter's request validation for transport/policy fields.
        ConnectRequest(
            target="validation.invalid",
            port=self.port,
            timeout_seconds=self.timeout_seconds,
            require_signing=self.require_signing,
            require_encryption=self.require_encryption,
            require_secure_negotiate=self.require_secure_negotiate,
        )
        if isinstance(self.max_concurrency, bool) or not isinstance(
            self.max_concurrency, int
        ):
            raise TypeError("max_concurrency must be an integer.")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be greater than zero.")
        if (
            isinstance(self.cancellation_poll_seconds, bool)
            or not isinstance(self.cancellation_poll_seconds, (int, float))
            or self.cancellation_poll_seconds <= 0
        ):
            raise ValueError("cancellation_poll_seconds must be positive.")


@dataclass(frozen=True, slots=True, repr=False)
class PipelineTargetEvent:
    address: IPAddress | None = field(repr=False)
    source: str = field(repr=False)
    source_kind: TargetKind
    source_hostname: str | None = field(default=None, repr=False)
    tcp_status: ConnectivityStatus = ConnectivityStatus.CONNECTION_ERROR
    smb_status: SmbPipelineStatus = SmbPipelineStatus.NOT_ATTEMPTED
    dialect: SmbDialect | None = None
    auth_status: AuthenticationPlaceholder = AuthenticationPlaceholder.NOT_ATTEMPTED
    last_status: PipelineTargetStatus = PipelineTargetStatus.CONNECTOR_ERROR
    error_code: int | None = None
    emitted_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(address=<redacted>, source=<redacted>, "
            f"source_kind={self.source_kind.value!r}, "
            f"tcp_status={self.tcp_status.value!r}, "
            f"smb_status={self.smb_status.value!r}, "
            f"dialect={self.dialect.value if self.dialect else None!r}, "
            f"auth_status={self.auth_status.value!r}, "
            f"last_status={self.last_status.value!r}, error_code={self.error_code!r})"
        )


@dataclass(frozen=True, slots=True)
class PipelineStateEvent:
    state: PipelineState
    target_results: int
    negotiated_targets: int
    emitted_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def terminal(self) -> bool:
        return self.state.terminal


type PipelineEvent = PipelineTargetEvent | PipelineStateEvent
type PipelineCallback = Callable[[PipelineEvent], None]


class ScanPipeline:
    """Consume a target plan lazily and negotiate SMB with bounded concurrency."""

    def __init__(
        self,
        settings: PipelineSettings | None = None,
        *,
        connector: ReadOnlyConnector | None = None,
    ) -> None:
        self.settings = settings or PipelineSettings()
        if connector is None:
            # Keep framework-neutral tests and non-network UI imports usable
            # without importing the optional SMB runtime until it is needed.
            from nordis_smb_inspector.smb.smbprotocol_adapter import SmbProtocolConnector

            connector = SmbProtocolConnector()
        self._connector = connector

    def iter_events(
        self,
        plan: TargetPlan,
        *,
        resolver: Resolver | None = None,
        cancellation: CancellationToken = NEVER_CANCELLED,
        credentials_available: bool = False,
        on_event: PipelineCallback | None = None,
    ) -> Iterator[PipelineEvent]:
        """Yield target outcomes on completion and explicit pipeline state events.

        ``credentials_available`` contains no credential material.  It only
        tells this negotiation-only stage whether its hand-off state is
        ``NEGOTIATION_COMPLETE`` or ``AWAITING_CREDENTIALS``.  Neither state is
        a completed scan; a later authenticator must continue on the same
        connection inside ``_negotiate_target`` before that method closes it.
        """

        result_count = 0
        negotiated_count = 0
        initial = PipelineStateEvent(PipelineState.NEGOTIATING, 0, 0)
        self._notify(on_event, initial)
        yield initial

        source = iter(plan.iter_scan_targets(resolver))
        pending: dict[Future[PipelineTargetEvent], ExpandedTarget] = {}
        source_exhausted = False
        executor = ThreadPoolExecutor(
            max_workers=self.settings.max_concurrency,
            thread_name_prefix="nordis-smb-negotiate",
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
                        event = self._resolution_failure(target)
                        result_count += 1
                        self._notify(on_event, event)
                        yield event
                        continue

                    future = executor.submit(
                        self._negotiate_target,
                        target,
                        cancellation,
                        credentials_available,
                    )
                    pending[future] = target

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
                    event = (
                        self._cancelled_target(target)
                        if future.cancelled()
                        else future.result()
                    )
                    result_count += 1
                    if event.smb_status is SmbPipelineStatus.NEGOTIATED:
                        negotiated_count += 1
                    self._notify(on_event, event)
                    yield event
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

        if cancellation.cancelled:
            final_state = PipelineState.CANCELLED
        elif credentials_available:
            final_state = PipelineState.NEGOTIATION_COMPLETE
        else:
            final_state = PipelineState.AWAITING_CREDENTIALS

        final = PipelineStateEvent(final_state, result_count, negotiated_count)
        self._notify(on_event, final)
        yield final

    def _negotiate_target(
        self,
        target: ExpandedTarget,
        cancellation: CancellationToken,
        credentials_available: bool,
    ) -> PipelineTargetEvent:
        if cancellation.cancelled:
            return self._cancelled_target(target)

        request = ConnectRequest(
            target=str(target.address),
            port=self.settings.port,
            timeout_seconds=self.settings.timeout_seconds,
            require_signing=self.settings.require_signing,
            require_encryption=self.settings.require_encryption,
            require_secure_negotiate=self.settings.require_secure_negotiate,
        )
        try:
            handle = self._connector.connect(request, cancellation=cancellation)
        except ScanCancelled:
            return self._cancelled_target(target)
        except Exception as exc:
            outcome = getattr(exc, "outcome", None)
            if isinstance(outcome, TargetOutcome):
                return self._failed_target(target, outcome)
            # A connector implementation violated the adapter contract.  Never
            # reflect its raw exception text into an event or representation.
            return PipelineTargetEvent(
                address=target.address,
                source=target.source,
                source_kind=target.source_kind,
                source_hostname=target.source_hostname,
                tcp_status=ConnectivityStatus.CONNECTION_ERROR,
                last_status=PipelineTargetStatus.CONNECTOR_ERROR,
            )

        try:
            auth_status = (
                AuthenticationPlaceholder.NOT_ATTEMPTED
                if credentials_available
                else AuthenticationPlaceholder.AWAITING_CREDENTIALS
            )
            last_status = (
                PipelineTargetStatus.NEGOTIATION_COMPLETE
                if credentials_available
                else PipelineTargetStatus.AWAITING_CREDENTIALS
            )
            return PipelineTargetEvent(
                address=target.address,
                source=target.source,
                source_kind=target.source_kind,
                source_hostname=target.source_hostname,
                tcp_status=ConnectivityStatus.PORT_OPEN,
                smb_status=SmbPipelineStatus.NEGOTIATED,
                dialect=handle.negotiation.dialect,
                auth_status=auth_status,
                last_status=last_status,
            )
        finally:
            # Until authentication is added, no native transport may outlive
            # its worker. The future auth branch belongs above this close.
            with suppress(Exception):
                handle.close()

    def _failed_target(
        self,
        target: ExpandedTarget,
        outcome: TargetOutcome,
    ) -> PipelineTargetEvent:
        if outcome.stage is TargetStage.NETWORK:
            tcp_status = {
                TargetStatus.TIMEOUT_NO_RESPONSE: ConnectivityStatus.TIMEOUT_NO_RESPONSE,
                TargetStatus.CONNECTION_REFUSED: ConnectivityStatus.CONNECTION_REFUSED,
                TargetStatus.NETWORK_UNREACHABLE: ConnectivityStatus.NETWORK_UNREACHABLE,
            }.get(outcome.status, ConnectivityStatus.CONNECTION_ERROR)
            smb_status = SmbPipelineStatus.NOT_ATTEMPTED
        else:
            tcp_status = ConnectivityStatus.PORT_OPEN
            smb_status = (
                SmbPipelineStatus.SMB1_ONLY_UNSUPPORTED
                if outcome.status is TargetStatus.SMB1_ONLY_UNSUPPORTED
                else SmbPipelineStatus.NEGOTIATION_FAILED
            )

        last_status = {
            TargetStatus.TIMEOUT_NO_RESPONSE: PipelineTargetStatus.TIMEOUT_NO_RESPONSE,
            TargetStatus.CONNECTION_REFUSED: PipelineTargetStatus.CONNECTION_REFUSED,
            TargetStatus.NETWORK_UNREACHABLE: PipelineTargetStatus.NETWORK_UNREACHABLE,
            TargetStatus.SMB1_ONLY_UNSUPPORTED: (
                PipelineTargetStatus.SMB1_ONLY_UNSUPPORTED
            ),
        }.get(outcome.status, PipelineTargetStatus.NEGOTIATION_FAILED)
        return PipelineTargetEvent(
            address=target.address,
            source=target.source,
            source_kind=target.source_kind,
            source_hostname=target.source_hostname,
            tcp_status=tcp_status,
            smb_status=smb_status,
            last_status=last_status,
            error_code=outcome.error.raw_code if outcome.error is not None else None,
        )

    def _resolution_failure(self, failure: ResolutionFailure) -> PipelineTargetEvent:
        return PipelineTargetEvent(
            address=None,
            source=failure.source,
            source_kind=TargetKind.HOSTNAME,
            source_hostname=failure.hostname,
            tcp_status=ConnectivityStatus.DNS_RESOLUTION_FAILED,
            last_status=PipelineTargetStatus.DNS_RESOLUTION_FAILED,
        )

    def _cancelled_target(self, target: ExpandedTarget) -> PipelineTargetEvent:
        return PipelineTargetEvent(
            address=target.address,
            source=target.source,
            source_kind=target.source_kind,
            source_hostname=target.source_hostname,
            tcp_status=ConnectivityStatus.CANCELLED,
            last_status=PipelineTargetStatus.CANCELLED,
        )

    @staticmethod
    def _notify(callback: PipelineCallback | None, event: PipelineEvent) -> None:
        if callback is not None:
            callback(event)
