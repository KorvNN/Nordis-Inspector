"""One-session, read-only SMB inspection orchestration.

The orchestration in this module is independent from the web application.  It
keeps an authenticated SMB session alive while known shares are probed, their
trees are walked, and readable files are streamed through the content matcher.
Only bounded byte ranges are read; no remote file is materialized on disk.
"""

from __future__ import annotations

import errno
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Protocol

from nordis_smb_inspector.core.content import MatchOptions, scan_text
from nordis_smb_inspector.core.credentials import Credential

from .cancellation import CancellationToken, ScanCancelled
from .contracts import (
    ConnectionHandle,
    ConnectRequest,
    OpenFileRequest,
    SessionHandle,
    TreeWalkRequest,
    ValidatedRangeReader,
)
from .models import (
    AuthenticationHistory,
    InventoryEntry,
    InventoryEntryKind,
    InventoryStatus,
    NegotiationInfo,
    ShareAccessStatus,
    ShareInfo,
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

_STREAM_CHUNK_SIZE = 64 * 1024


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


class KnownShareProbeLike(Protocol):
    @property
    def share(self) -> ShareInfo: ...

    @property
    def inventory(self) -> InventoryEntry | None: ...


class ReadOnlyFileAdapter(Protocol):
    def probe_known_shares(
        self,
        session: SessionHandle,
        *,
        target: str,
        share_names: Iterable[str],
        cancellation: CancellationToken,
    ) -> Iterable[KnownShareProbeLike]: ...

    def walk_tree(
        self,
        session: SessionHandle,
        request: TreeWalkRequest,
        *,
        cancellation: CancellationToken,
    ) -> Iterator[InventoryEntry]: ...

    def open_reader(
        self,
        session: SessionHandle,
        request: OpenFileRequest,
        *,
        cancellation: CancellationToken,
    ) -> ValidatedRangeReader: ...


class InspectionEventKind(StrEnum):
    NEGOTIATED = "negotiated"
    AUTHENTICATED = "authenticated"
    PROBING_SHARES = "probing_shares"
    WALKING_SHARE = "walking_share"
    SCANNING_FILE = "scanning_file"
    STAGE_ERROR = "stage_error"
    TERMINAL = "terminal"


@dataclass(frozen=True, slots=True, repr=False)
class InspectionTargetEvent:
    """A normalized live transition for one target.

    Target, share, and path context remain available to the in-memory caller,
    while their representations are redacted to keep accidental logs clean.
    """

    kind: InspectionEventKind
    target: str = field(repr=False)
    stage: TargetStage
    status: TargetStatus | None = None
    terminal: bool = False
    share: str | None = field(default=None, repr=False)
    path: str | None = field(default=None, repr=False)
    negotiation: NegotiationInfo | None = None
    authentication: AuthenticationHistory | None = None
    error: SmbErrorDetail | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")
        if self.terminal and self.kind is not InspectionEventKind.TERMINAL:
            raise ValueError("Only terminal events may set terminal=True.")
        if self.kind is InspectionEventKind.TERMINAL and not self.terminal:
            raise ValueError("Terminal events must set terminal=True.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(kind={self.kind.value!r}, target=<redacted>, "
            f"stage={self.stage.value!r}, status="
            f"{self.status.value if self.status is not None else None!r}, "
            f"terminal={self.terminal!r}, context=<redacted>, "
            f"negotiation={self.negotiation!r}, "
            f"authentication={self.authentication!r}, error={self.error!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ContentFinding:
    """One matching term on one decoded physical line of a remote file."""

    target: str = field(repr=False)
    share: str = field(repr=False)
    path: str = field(repr=False)
    line_number: int
    term: str = field(repr=False)
    full_line: str = field(repr=False)

    def __post_init__(self) -> None:
        for name in ("target", "share", "path", "term"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty text.")
        if isinstance(self.line_number, bool) or not isinstance(self.line_number, int):
            raise TypeError("line_number must be an integer.")
        if self.line_number < 1:
            raise ValueError("line_number must be at least one.")
        if not isinstance(self.full_line, str):
            raise TypeError("full_line must be text.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(context=<redacted>, "
            f"line_number={self.line_number!r}, content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class InspectionResult:
    """Terminal metadata only; inventory and findings are callback-streamed."""

    target: str = field(repr=False)
    outcome: TargetOutcome
    negotiation: NegotiationInfo | None = None
    authentication: AuthenticationHistory | None = None
    shares_probed: int = 0
    shares_accessible: int = 0
    inventory_items: int = 0
    files_seen: int = 0
    files_scanned: int = 0
    unreadable_files: int = 0
    findings: int = 0
    content_incomplete: int = 0
    cleanup_failed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")
        if self.outcome.target != self.target:
            raise ValueError("outcome must belong to the result target.")
        for name in (
            "shares_probed",
            "shares_accessible",
            "inventory_items",
            "files_seen",
            "files_scanned",
            "unreadable_files",
            "findings",
            "content_incomplete",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer.")
        if not isinstance(self.cleanup_failed, bool):
            raise TypeError("cleanup_failed must be a boolean.")

    @property
    def status(self) -> TargetStatus:
        return self.outcome.status

    @property
    def stage(self) -> TargetStage:
        return self.outcome.stage

    @property
    def completed(self) -> bool:
        return self.status in {TargetStatus.COMPLETED, TargetStatus.PARTIAL_ACCESS}

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target=<redacted>, outcome={self.outcome!r}, "
            f"negotiation={self.negotiation!r}, "
            f"authentication={self.authentication!r}, "
            f"shares_probed={self.shares_probed!r}, "
            f"shares_accessible={self.shares_accessible!r}, "
            f"inventory_items={self.inventory_items!r}, "
            f"files_seen={self.files_seen!r}, files_scanned={self.files_scanned!r}, "
            f"unreadable_files={self.unreadable_files!r}, "
            f"findings={self.findings!r}, "
            f"content_incomplete={self.content_incomplete!r}, "
            f"cleanup_failed={self.cleanup_failed!r})"
        )


@dataclass(slots=True)
class _InspectionCounts:
    shares_probed: int = 0
    shares_accessible: int = 0
    inventory_items: int = 0
    files_seen: int = 0
    files_scanned: int = 0
    unreadable_files: int = 0
    findings: int = 0
    content_incomplete: int = 0


TargetCallback = Callable[[InspectionTargetEvent], None]
InventoryCallback = Callable[[InventoryEntry], None]
FindingCallback = Callable[[ContentFinding], None]


def inspect_target(
    *,
    target: str,
    connect_request: ConnectRequest,
    credential: Credential,
    kerberos_hostname: str | None,
    share_names: Iterable[str],
    search_terms: Iterable[str],
    max_depth: int,
    connector: Connector,
    authenticator: CredentialAuthenticator,
    file_adapter: ReadOnlyFileAdapter,
    cancellation: CancellationToken,
    on_target: TargetCallback | None = None,
    on_inventory: InventoryCallback | None = None,
    on_finding: FindingCallback | None = None,
) -> InspectionResult:
    """Inspect one target through content scanning with one live session.

    Results retain counters and normalized protocol metadata only.  Inventory
    entries and content findings are delivered as they are encountered and are
    not accumulated by the orchestrator.
    """

    _validate_inputs(target, connect_request, credential, max_depth)
    normalized_shares = _normalize_share_names(share_names)
    normalized_terms = _normalize_search_terms(search_terms)

    connections: list[ConnectionHandle] = []
    session: SessionHandle | None = None
    negotiation: NegotiationInfo | None = None
    authentication: AuthenticationHistory | None = None
    counts = _InspectionCounts()
    partial = False
    last_stage = TargetStage.NEGOTIATION
    result: InspectionResult | None = None
    cleanup_failed = False

    def publish_target(event: InspectionTargetEvent) -> None:
        _publish(on_target, event)

    def publish_inventory(entry: InventoryEntry) -> None:
        counts.inventory_items += 1
        _publish(on_inventory, entry)

    def reconnect_for_ntlm(*, cancellation: CancellationToken) -> ConnectionHandle:
        replacement_connection = connector.connect(
            connect_request,
            cancellation=cancellation,
        )
        connections.append(replacement_connection)
        return replacement_connection

    try:
        cancellation.raise_if_cancelled()
        connection = connector.connect(connect_request, cancellation=cancellation)
        connections.append(connection)
        negotiation = connection.negotiation
        publish_target(
            InspectionTargetEvent(
                kind=InspectionEventKind.NEGOTIATED,
                target=target,
                stage=TargetStage.NEGOTIATION,
                negotiation=negotiation,
            )
        )

        last_stage = TargetStage.AUTHENTICATION
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
        active_negotiation = getattr(active_connection, "negotiation", None)
        if isinstance(active_negotiation, NegotiationInfo):
            negotiation = active_negotiation
        authentication = session.authentication
        publish_target(
            InspectionTargetEvent(
                kind=InspectionEventKind.AUTHENTICATED,
                target=target,
                stage=TargetStage.AUTHENTICATION,
                status=TargetStatus.AUTHENTICATED,
                negotiation=negotiation,
                authentication=authentication,
            )
        )

        last_stage = TargetStage.AUTHORIZATION
        publish_target(
            InspectionTargetEvent(
                kind=InspectionEventKind.PROBING_SHARES,
                target=target,
                stage=TargetStage.AUTHORIZATION,
                status=TargetStatus.AUTHENTICATED,
                negotiation=negotiation,
                authentication=authentication,
            )
        )
        try:
            probes = file_adapter.probe_known_shares(
                session,
                target=target,
                share_names=normalized_shares,
                cancellation=cancellation,
            )
            for probe in probes:
                cancellation.raise_if_cancelled()
                counts.shares_probed += 1
                share = probe.share
                if share.target != target:
                    partial = True
                    publish_target(_stage_error(target, TargetStage.AUTHORIZATION))
                    continue
                if share.access_status is ShareAccessStatus.CONNECTED:
                    counts.shares_accessible += 1
                elif share.access_status is not ShareAccessStatus.NOT_FOUND:
                    partial = True
                if probe.inventory is not None:
                    publish_inventory(probe.inventory)
                if not share.content_walkable:
                    continue
                if _walk_share(
                    target=target,
                    session=session,
                    share=share,
                    search_terms=normalized_terms,
                    max_depth=max_depth,
                    file_adapter=file_adapter,
                    cancellation=cancellation,
                    counts=counts,
                    on_target=on_target,
                    on_inventory=on_inventory,
                    on_finding=on_finding,
                    negotiation=negotiation,
                    authentication=authentication,
                ):
                    partial = True
                last_stage = TargetStage.FILE_READ
        except ScanCancelled:
            raise
        except Exception:
            partial = True
            publish_target(_stage_error(target, TargetStage.AUTHORIZATION))

        terminal_status = (
            TargetStatus.PARTIAL_ACCESS if partial else TargetStatus.COMPLETED
        )
        result = _result(
            target,
            terminal_status,
            negotiation,
            authentication,
            counts,
        )
    except SmbProtocolConnectError as exception:
        result = _result_from_outcome(
            target,
            exception.outcome,
            negotiation,
            authentication,
            counts,
        )
    except SmbProtocolAuthenticationError as exception:
        authentication = exception.history
        result = _result_from_outcome(
            target,
            TargetOutcome(
                target=target,
                stage=TargetStage.AUTHENTICATION,
                status=TargetStatus.AUTH_FAILED,
                error=exception.detail,
            ),
            negotiation,
            authentication,
            counts,
        )
    except SmbProtocolFallbackConnectionError as exception:
        authentication = exception.kerberos_history
        detail = _safe_detail(
            TargetStage.AUTHENTICATION,
            TargetStatus.AUTH_FAILED,
            operation="ntlm_fallback_connect",
            raw_code=errno.ECONNABORTED,
            symbolic_name="NTLM_FALLBACK_CONNECTION_FAILED",
            message="NTLM fallback could not establish a fresh SMB connection.",
        )
        result = _result_from_outcome(
            target,
            TargetOutcome(
                target=target,
                stage=TargetStage.AUTHENTICATION,
                status=TargetStatus.AUTH_FAILED,
                error=detail,
            ),
            negotiation,
            authentication,
            counts,
        )
    except UnsupportedAuthenticationCredential:
        detail = _safe_detail(
            TargetStage.AUTHENTICATION,
            TargetStatus.AUTH_FAILED,
            operation="credential_route",
            raw_code=errno.ENOTSUP,
            symbolic_name="CREDENTIAL_ADAPTER_UNAVAILABLE",
            message="The selected credential is not supported by this adapter.",
        )
        result = _result_from_outcome(
            target,
            TargetOutcome(
                target=target,
                stage=TargetStage.AUTHENTICATION,
                status=TargetStatus.AUTH_FAILED,
                error=detail,
            ),
            negotiation,
            authentication,
            counts,
        )
    except ScanCancelled:
        result = _result_from_outcome(
            target,
            TargetOutcome(
                target=target,
                stage=last_stage,
                status=TargetStatus.CANCELLED,
            ),
            negotiation,
            authentication,
            counts,
        )
    except Exception:
        detail = _unexpected_detail(last_stage)
        result = _result_from_outcome(
            target,
            TargetOutcome(
                target=target,
                stage=detail.stage,
                status=detail.status,
                error=detail,
            ),
            negotiation,
            authentication,
            counts,
        )
    finally:
        if session is not None:
            cleanup_failed = _close_handle(session) or cleanup_failed
        for owned_connection in reversed(_unique_handles(connections)):
            cleanup_failed = _close_handle(owned_connection) or cleanup_failed

    if result is None:  # pragma: no cover - every path above produces a result
        raise RuntimeError("Inspection did not produce a terminal result.")
    if cleanup_failed:
        result = replace(result, cleanup_failed=True)
        if result.status is TargetStatus.COMPLETED:
            cleanup_detail = _safe_detail(
                TargetStage.COMPLETE,
                TargetStatus.PARTIAL_ACCESS,
                operation="handle_cleanup",
                raw_code=errno.EIO,
                symbolic_name="HANDLE_CLEANUP_FAILED",
                message="One or more SMB handles could not be closed cleanly.",
            )
            result = replace(
                result,
                outcome=TargetOutcome(
                    target=target,
                    stage=TargetStage.COMPLETE,
                    status=TargetStatus.PARTIAL_ACCESS,
                    error=cleanup_detail,
                ),
            )

    publish_target(
        InspectionTargetEvent(
            kind=InspectionEventKind.TERMINAL,
            target=target,
            stage=result.stage,
            status=result.status,
            terminal=True,
            negotiation=result.negotiation,
            authentication=result.authentication,
            error=result.outcome.error,
        )
    )
    return result


def _walk_share(
    *,
    target: str,
    session: SessionHandle,
    share: ShareInfo,
    search_terms: tuple[str, ...],
    max_depth: int,
    file_adapter: ReadOnlyFileAdapter,
    cancellation: CancellationToken,
    counts: _InspectionCounts,
    on_target: TargetCallback | None,
    on_inventory: InventoryCallback | None,
    on_finding: FindingCallback | None,
    negotiation: NegotiationInfo | None,
    authentication: AuthenticationHistory | None,
) -> bool:
    """Stream one connected disk share; return whether access was partial."""

    partial = False
    _publish(
        on_target,
        InspectionTargetEvent(
            kind=InspectionEventKind.WALKING_SHARE,
            target=target,
            stage=TargetStage.TREE_WALK,
            share=share.name,
            negotiation=negotiation,
            authentication=authentication,
        ),
    )
    try:
        entries = file_adapter.walk_tree(
            session,
            TreeWalkRequest(share=share, max_depth=max_depth),
            cancellation=cancellation,
        )
        for entry in entries:
            cancellation.raise_if_cancelled()
            if entry.target != target or entry.share_name != share.name:
                partial = True
                _publish(on_target, _stage_error(target, TargetStage.TREE_WALK))
                continue
            counts.inventory_items += 1
            _publish(on_inventory, entry)
            if entry.kind is not InventoryEntryKind.FILE:
                if entry.status is InventoryStatus.DIRECTORY_LIST_DENIED:
                    partial = True
                continue
            counts.files_seen += 1
            if entry.status is not InventoryStatus.FILE_READABLE:
                counts.unreadable_files += 1
                partial = True
                continue
            if _scan_file(
                target=target,
                session=session,
                entry=entry,
                search_terms=search_terms,
                file_adapter=file_adapter,
                cancellation=cancellation,
                counts=counts,
                on_target=on_target,
                on_inventory=on_inventory,
                on_finding=on_finding,
                negotiation=negotiation,
                authentication=authentication,
            ):
                partial = True
    except ScanCancelled:
        raise
    except Exception:
        partial = True
        _publish(on_target, _stage_error(target, TargetStage.TREE_WALK, share=share.name))
    return partial


def _scan_file(
    *,
    target: str,
    session: SessionHandle,
    entry: InventoryEntry,
    search_terms: tuple[str, ...],
    file_adapter: ReadOnlyFileAdapter,
    cancellation: CancellationToken,
    counts: _InspectionCounts,
    on_target: TargetCallback | None,
    on_inventory: InventoryCallback | None,
    on_finding: FindingCallback | None,
    negotiation: NegotiationInfo | None,
    authentication: AuthenticationHistory | None,
) -> bool:
    _publish(
        on_target,
        InspectionTargetEvent(
            kind=InspectionEventKind.SCANNING_FILE,
            target=target,
            stage=TargetStage.FILE_READ,
            share=entry.share_name,
            path=entry.relative_path,
            negotiation=negotiation,
            authentication=authentication,
        ),
    )
    reader: ValidatedRangeReader | None = None
    partial = False
    try:
        reader = file_adapter.open_reader(
            session,
            OpenFileRequest(
                target=target,
                share_name=entry.share_name,
                relative_path=entry.relative_path,
                expected_size=entry.size,
            ),
            cancellation=cancellation,
        )
        chunk_size = min(_STREAM_CHUNK_SIZE, reader.max_read_size)
        scan_result = scan_text(
            reader.iter_chunks(
                chunk_size=chunk_size,
                cancellation=cancellation,
            ),
            search_terms,
            options=MatchOptions(case_sensitive=False),
        )
        counts.files_scanned += 1
        for match in scan_result.matches:
            counts.findings += 1
            _publish(
                on_finding,
                ContentFinding(
                    target=target,
                    share=entry.share_name,
                    path=entry.relative_path,
                    line_number=match.line_number,
                    term=match.term,
                    full_line=match.line,
                ),
            )
        if not scan_result.complete:
            counts.content_incomplete += 1
            partial = True
    except ScanCancelled:
        raise
    except Exception as exception:
        counts.unreadable_files += 1
        partial = True
        detail = _file_error_detail(exception)
        status = _inventory_status_for_error(detail)
        updated_entry = InventoryEntry(
            target=entry.target,
            share_name=entry.share_name,
            relative_path=entry.relative_path,
            kind=InventoryEntryKind.FILE,
            status=status,
            size=entry.size,
            modified_at=entry.modified_at,
            error=detail,
        )
        counts.inventory_items += 1
        _publish(on_inventory, updated_entry)
        _publish(
            on_target,
            _stage_error(
                target,
                TargetStage.FILE_READ,
                share=entry.share_name,
                path=entry.relative_path,
                status=detail.status,
                error=detail,
            ),
        )
    finally:
        if reader is not None and _close_handle(reader):
            partial = True
    return partial


def _file_error_detail(exception: BaseException) -> SmbErrorDetail:
    detail = getattr(exception, "detail", None)
    if (
        isinstance(detail, SmbErrorDetail)
        and detail.stage is TargetStage.FILE_READ
        and detail.status
        in {
            TargetStatus.FILE_READ_DENIED,
            TargetStatus.SHARING_VIOLATION,
            TargetStatus.FILE_READ_ERROR,
        }
    ):
        return detail
    return _safe_detail(
        TargetStage.FILE_READ,
        TargetStatus.FILE_READ_ERROR,
        operation="file_content_scan",
        raw_code=errno.EIO,
        symbolic_name="FILE_CONTENT_SCAN_FAILED",
        message="The remote file could not be scanned.",
    )


def _inventory_status_for_error(detail: SmbErrorDetail) -> InventoryStatus:
    return {
        TargetStatus.FILE_READ_DENIED: InventoryStatus.FILE_READ_DENIED,
        TargetStatus.SHARING_VIOLATION: InventoryStatus.SHARING_VIOLATION,
        TargetStatus.FILE_READ_ERROR: InventoryStatus.READ_ERROR,
    }.get(detail.status, InventoryStatus.READ_ERROR)


def _stage_error(
    target: str,
    stage: TargetStage,
    *,
    share: str | None = None,
    path: str | None = None,
    status: TargetStatus | None = None,
    error: SmbErrorDetail | None = None,
) -> InspectionTargetEvent:
    return InspectionTargetEvent(
        kind=InspectionEventKind.STAGE_ERROR,
        target=target,
        stage=stage,
        status=status,
        share=share,
        path=path,
        error=error,
    )


def _result(
    target: str,
    status: TargetStatus,
    negotiation: NegotiationInfo | None,
    authentication: AuthenticationHistory | None,
    counts: _InspectionCounts,
) -> InspectionResult:
    detail = None
    if status is TargetStatus.PARTIAL_ACCESS:
        detail = _safe_detail(
            TargetStage.COMPLETE,
            TargetStatus.PARTIAL_ACCESS,
            operation="target_inspection",
            raw_code=errno.EACCES,
            symbolic_name="PARTIAL_ACCESS",
            message="The target inspection completed with inaccessible content.",
        )
    return _result_from_outcome(
        target,
        TargetOutcome(
            target=target,
            stage=TargetStage.COMPLETE,
            status=status,
            error=detail,
        ),
        negotiation,
        authentication,
        counts,
    )


def _result_from_outcome(
    target: str,
    outcome: TargetOutcome,
    negotiation: NegotiationInfo | None,
    authentication: AuthenticationHistory | None,
    counts: _InspectionCounts,
) -> InspectionResult:
    return InspectionResult(
        target=target,
        outcome=outcome,
        negotiation=negotiation,
        authentication=authentication,
        shares_probed=counts.shares_probed,
        shares_accessible=counts.shares_accessible,
        inventory_items=counts.inventory_items,
        files_seen=counts.files_seen,
        files_scanned=counts.files_scanned,
        unreadable_files=counts.unreadable_files,
        findings=counts.findings,
        content_incomplete=counts.content_incomplete,
    )


def _safe_detail(
    stage: TargetStage,
    status: TargetStatus,
    *,
    operation: str,
    raw_code: int,
    symbolic_name: str,
    message: str,
) -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=stage,
        status=status,
        operation=operation,
        raw_code=raw_code,
        symbolic_name=symbolic_name,
        safe_message=message,
    )


def _unexpected_detail(stage: TargetStage) -> SmbErrorDetail:
    status = {
        TargetStage.NETWORK: TargetStatus.NETWORK_UNREACHABLE,
        TargetStage.NEGOTIATION: TargetStatus.NEGOTIATION_FAILED,
        TargetStage.AUTHENTICATION: TargetStatus.AUTH_FAILED,
        TargetStage.AUTHORIZATION: TargetStatus.SHARE_CONNECT_ERROR,
        TargetStage.SHARE_ENUMERATION: TargetStatus.SHARE_ENUM_FAILED,
        TargetStage.TREE_WALK: TargetStatus.DIRECTORY_LIST_ERROR,
        TargetStage.FILE_READ: TargetStatus.FILE_READ_ERROR,
        TargetStage.COMPLETE: TargetStatus.PARTIAL_ACCESS,
    }[stage]
    return _safe_detail(
        stage,
        status,
        operation="target_inspection",
        raw_code=errno.EIO,
        symbolic_name="INTERNAL_INSPECTION_ERROR",
        message="The target inspection could not complete.",
    )


def _validate_inputs(
    target: str,
    connect_request: ConnectRequest,
    credential: Credential,
    max_depth: int,
) -> None:
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be non-empty text.")
    if target != connect_request.target:
        raise ValueError("target must match connect_request.target.")
    if not isinstance(credential, Credential):
        raise TypeError("credential must be a Credential instance.")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        raise TypeError("max_depth must be an integer.")
    if max_depth < 0:
        raise ValueError("max_depth cannot be negative.")


def _normalize_share_names(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise TypeError("Share names must be strings.")
        candidate = value.strip()
        if not candidate or candidate.startswith("#"):
            continue
        folded = candidate.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        normalized.append(candidate)
    return tuple(normalized)


def _normalize_search_terms(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise TypeError("Search terms must be strings.")
        if not value:
            raise ValueError("Search terms cannot be empty.")
        folded = value.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        normalized.append(value)
    return tuple(normalized)


def _publish(callback: Callable[[object], None] | None, value: object) -> None:
    if callback is None:
        return
    try:
        callback(value)
    except Exception:
        # UI/event delivery must not abort a scan or prevent handle cleanup.
        return


def _unique_handles(handles: Iterable[ConnectionHandle]) -> tuple[ConnectionHandle, ...]:
    result: list[ConnectionHandle] = []
    seen: set[int] = set()
    for handle in handles:
        identity = id(handle)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(handle)
    return tuple(result)


def _close_handle(handle: object) -> bool:
    try:
        handle.close()  # type: ignore[attr-defined]
    except Exception:
        return True
    return False
