"""Single-target negotiate/authenticate workflow for bounded web workers.

The orchestrator calls :func:`inspect_target_access` inside its worker pool.
This module owns every connection/session handle it receives and guarantees
best-effort cleanup before returning a normalized, immutable result.
"""

from __future__ import annotations

import errno
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from nordis_smb_inspector.core.credentials import Credential, CredentialKind

from .cancellation import CancellationToken, ScanCancelled
from .contracts import ConnectionHandle, ConnectRequest, SessionHandle
from .models import (
    AuthenticationHistory,
    NegotiationInfo,
    SmbErrorDetail,
    TargetOutcome,
    TargetStage,
    TargetStatus,
)
from .smbprotocol_adapter import SmbProtocolConnectError
from .smbprotocol_auth_adapter import (
    SmbProtocolAuthenticationError,
    SmbProtocolFallbackConnectionError,
    UnsupportedAuthenticationCredential,
)


class Connector(Protocol):
    def connect(
        self,
        request: ConnectRequest,
        *,
        cancellation: CancellationToken,
    ) -> ConnectionHandle: ...


class CredentialAuthenticator(Protocol):
    def authenticate_credential(
        self,
        connection: ConnectionHandle,
        credential: Credential,
        *,
        kerberos_hostname: str | None,
        cancellation: CancellationToken,
        reconnect_for_ntlm: Callable[..., ConnectionHandle] | None = None,
    ) -> SessionHandle: ...


class AccessWorkflowStatus(StrEnum):
    AUTHENTICATED = "authenticated"
    CONNECT_FAILED = "connect_failed"
    AUTH_FAILED = "auth_failed"
    CCACHE_UNSUPPORTED = "ccache_unsupported"
    FALLBACK_CONNECT_FAILED = "fallback_connect_failed"
    CANCELLED = "cancelled"
    INTERNAL_ERROR = "internal_error"


class AccessEventKind(StrEnum):
    NEGOTIATION_SUCCEEDED = "negotiation_succeeded"
    NEGOTIATION_FAILED = "negotiation_failed"
    AUTHENTICATION_SUCCEEDED = "authentication_succeeded"
    AUTHENTICATION_FAILED = "authentication_failed"
    CREDENTIAL_UNSUPPORTED = "credential_unsupported"
    FALLBACK_CONNECTION_FAILED = "fallback_connection_failed"
    CANCELLED = "cancelled"
    CLEANUP_FAILED = "cleanup_failed"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True, slots=True, repr=False)
class AccessEvent:
    """One normalized transition; target context is deliberately repr-redacted."""

    kind: AccessEventKind
    stage: TargetStage
    target: str = field(repr=False)
    outcome: TargetOutcome | None = None
    negotiation: NegotiationInfo | None = None
    authentication: AuthenticationHistory | None = None
    error: SmbErrorDetail | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(kind={self.kind.value!r}, "
            f"stage={self.stage.value!r}, target=<redacted>, outcome={self.outcome!r}, "
            f"negotiation={self.negotiation!r}, "
            f"authentication={self.authentication!r}, error={self.error!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TargetAccessResult:
    """Terminal single-target result; it owns no live SMB handle."""

    target: str = field(repr=False)
    status: AccessWorkflowStatus
    events: tuple[AccessEvent, ...]
    negotiation: NegotiationInfo | None = None
    authentication: AuthenticationHistory | None = None
    outcome: TargetOutcome | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")
        if not self.events:
            raise ValueError("A workflow result must contain at least one event.")
        if any(event.target != self.target for event in self.events):
            raise ValueError("Every workflow event must belong to the result target.")
        if self.status is AccessWorkflowStatus.AUTHENTICATED:
            if self.negotiation is None or self.authentication is None:
                raise ValueError("An authenticated result requires negotiation and auth metadata.")
            if not self.authentication.authenticated:
                raise ValueError("An authenticated result requires a successful auth history.")

    @property
    def authenticated(self) -> bool:
        return self.status is AccessWorkflowStatus.AUTHENTICATED

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target=<redacted>, status={self.status.value!r}, "
            f"events={self.events!r}, negotiation={self.negotiation!r}, "
            f"authentication={self.authentication!r}, outcome={self.outcome!r})"
        )


def inspect_target_access(
    *,
    target: str,
    connect_request: ConnectRequest,
    credential: Credential,
    kerberos_hostname: str | None,
    connector: Connector,
    authenticator: CredentialAuthenticator,
    cancellation: CancellationToken,
    on_event: Callable[[AccessEvent], None] | None = None,
) -> TargetAccessResult:
    """Negotiate and authenticate one target, always closing owned handles.

    The explicit ``target`` must match ``connect_request.target``.  Auto-mode
    reconnects use the exact same validated request and are retained by the
    workflow so the eventual replacement handle is also closed.
    """

    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be non-empty text.")
    if target != connect_request.target:
        raise ValueError("target must match connect_request.target.")
    if not isinstance(credential, Credential):
        raise TypeError("credential must be a Credential instance.")

    events: list[AccessEvent] = []
    connections: list[ConnectionHandle] = []
    session: SessionHandle | None = None
    cleanup_failed = False

    def publish(event: AccessEvent) -> None:
        events.append(event)
        if on_event is not None:
            try:
                on_event(event)
            except Exception:
                # Event delivery belongs to the UI bridge; it must not abort a
                # target scan or prevent handle cleanup.
                return

    def reconnect_for_ntlm(*, cancellation: CancellationToken) -> ConnectionHandle:
        replacement = connector.connect(connect_request, cancellation=cancellation)
        connections.append(replacement)
        return replacement

    try:
        if credential.kind is CredentialKind.CCACHE:
            detail = _workflow_error(
                operation="credential_route",
                raw_code=errno.ENOTSUP,
                symbolic_name="CCACHE_AUTH_ADAPTER_UNAVAILABLE",
                safe_message="CCache authentication is not available in this workflow yet.",
            )
            publish(
                AccessEvent(
                    kind=AccessEventKind.CREDENTIAL_UNSUPPORTED,
                    stage=TargetStage.AUTHENTICATION,
                    target=target,
                    error=detail,
                )
            )
            return TargetAccessResult(
                target=target,
                status=AccessWorkflowStatus.CCACHE_UNSUPPORTED,
                events=tuple(events),
                outcome=_failure_outcome(target, detail),
            )

        connection = connector.connect(connect_request, cancellation=cancellation)
        connections.append(connection)
        publish(
            AccessEvent(
                kind=AccessEventKind.NEGOTIATION_SUCCEEDED,
                stage=TargetStage.NEGOTIATION,
                target=target,
                negotiation=connection.negotiation,
            )
        )

        session = authenticator.authenticate_credential(
            connection,
            credential,
            kerberos_hostname=kerberos_hostname,
            cancellation=cancellation,
            reconnect_for_ntlm=reconnect_for_ntlm,
        )
        active_connection = getattr(session, "connection", None)
        if active_connection is not None and all(
            active_connection is not known for known in connections
        ):
            connections.append(active_connection)
        publish(
            AccessEvent(
                kind=AccessEventKind.AUTHENTICATION_SUCCEEDED,
                stage=TargetStage.AUTHENTICATION,
                target=target,
                authentication=session.authentication,
            )
        )
        result = TargetAccessResult(
            target=target,
            status=AccessWorkflowStatus.AUTHENTICATED,
            events=tuple(events),
            negotiation=connection.negotiation,
            authentication=session.authentication,
        )
    except SmbProtocolConnectError as exception:
        publish(
            AccessEvent(
                kind=AccessEventKind.NEGOTIATION_FAILED,
                stage=exception.outcome.stage,
                target=target,
                outcome=exception.outcome,
                error=exception.outcome.error,
            )
        )
        result = TargetAccessResult(
            target=target,
            status=AccessWorkflowStatus.CONNECT_FAILED,
            events=tuple(events),
            outcome=exception.outcome,
        )
    except SmbProtocolAuthenticationError as exception:
        publish(
            AccessEvent(
                kind=AccessEventKind.AUTHENTICATION_FAILED,
                stage=TargetStage.AUTHENTICATION,
                target=target,
                authentication=exception.history,
                error=exception.detail,
            )
        )
        result = TargetAccessResult(
            target=target,
            status=AccessWorkflowStatus.AUTH_FAILED,
            events=tuple(events),
            negotiation=connections[0].negotiation if connections else None,
            authentication=exception.history,
            outcome=_failure_outcome(target, exception.detail),
        )
    except UnsupportedAuthenticationCredential:
        detail = _workflow_error(
            operation="credential_route",
            raw_code=errno.ENOTSUP,
            symbolic_name="CREDENTIAL_ADAPTER_UNAVAILABLE",
            safe_message="The selected credential is not supported by this workflow.",
        )
        publish(
            AccessEvent(
                kind=AccessEventKind.CREDENTIAL_UNSUPPORTED,
                stage=TargetStage.AUTHENTICATION,
                target=target,
                error=detail,
            )
        )
        result = TargetAccessResult(
            target=target,
            status=AccessWorkflowStatus.CCACHE_UNSUPPORTED,
            events=tuple(events),
            negotiation=connections[0].negotiation if connections else None,
            outcome=_failure_outcome(target, detail),
        )
    except SmbProtocolFallbackConnectionError as exception:
        detail = _workflow_error(
            operation="fallback_connect",
            raw_code=errno.ECONNABORTED,
            symbolic_name="NTLM_FALLBACK_CONNECTION_FAILED",
            safe_message="NTLM fallback could not establish a fresh SMB connection.",
            retryable=True,
        )
        publish(
            AccessEvent(
                kind=AccessEventKind.FALLBACK_CONNECTION_FAILED,
                stage=TargetStage.AUTHENTICATION,
                target=target,
                authentication=exception.kerberos_history,
                error=detail,
            )
        )
        result = TargetAccessResult(
            target=target,
            status=AccessWorkflowStatus.FALLBACK_CONNECT_FAILED,
            events=tuple(events),
            negotiation=connections[0].negotiation if connections else None,
            authentication=exception.kerberos_history,
            outcome=_failure_outcome(target, detail),
        )
    except ScanCancelled:
        publish(
            AccessEvent(
                kind=AccessEventKind.CANCELLED,
                stage=(TargetStage.AUTHENTICATION if connections else TargetStage.NEGOTIATION),
                target=target,
            )
        )
        result = TargetAccessResult(
            target=target,
            status=AccessWorkflowStatus.CANCELLED,
            events=tuple(events),
            negotiation=connections[0].negotiation if connections else None,
        )
    except Exception:
        detail = _workflow_error(
            operation="target_access_workflow",
            raw_code=errno.EIO,
            symbolic_name="INTERNAL_WORKFLOW_ERROR",
            safe_message="The target access workflow could not complete.",
        )
        publish(
            AccessEvent(
                kind=AccessEventKind.INTERNAL_ERROR,
                stage=(TargetStage.AUTHENTICATION if connections else TargetStage.NEGOTIATION),
                target=target,
                error=detail,
            )
        )
        result = TargetAccessResult(
            target=target,
            status=AccessWorkflowStatus.INTERNAL_ERROR,
            events=tuple(events),
            negotiation=connections[0].negotiation if connections else None,
            outcome=_failure_outcome(target, detail),
        )
    finally:
        if session is not None:
            cleanup_failed = _close_handle(session) or cleanup_failed
        for connection in reversed(connections):
            cleanup_failed = _close_handle(connection) or cleanup_failed

    if cleanup_failed:
        cleanup_event = AccessEvent(
            kind=AccessEventKind.CLEANUP_FAILED,
            stage=TargetStage.AUTHORIZATION,
            target=target,
        )
        publish(cleanup_event)
        result = TargetAccessResult(
            target=result.target,
            status=result.status,
            events=tuple(events),
            negotiation=result.negotiation,
            authentication=result.authentication,
            outcome=result.outcome,
        )
    return result


def _close_handle(handle: object) -> bool:
    try:
        handle.close()
    except Exception:
        return True
    return False


def _workflow_error(
    *,
    operation: str,
    raw_code: int,
    symbolic_name: str,
    safe_message: str,
    retryable: bool = False,
) -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=TargetStage.AUTHENTICATION,
        status=TargetStatus.AUTH_FAILED,
        operation=operation,
        raw_code=raw_code,
        symbolic_name=symbolic_name,
        safe_message=safe_message,
        retryable=retryable,
    )


def _failure_outcome(target: str, detail: SmbErrorDetail) -> TargetOutcome:
    return TargetOutcome(
        target=target,
        stage=detail.stage,
        status=detail.status,
        error=detail,
    )
