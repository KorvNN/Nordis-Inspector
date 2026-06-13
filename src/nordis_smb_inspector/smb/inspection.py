"""One-session SMB inspection orchestration with an opt-in write probe.

The orchestration in this module is independent from the web application.  It
keeps an authenticated SMB session alive while known shares are probed, their
trees are walked, and readable files are streamed through the content matcher.
Only bounded byte ranges are read during normal inspection.  When explicitly
enabled, write access is tested with an empty delete-on-close probe file.
"""

from __future__ import annotations

import errno
from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field, replace
from enum import StrEnum
from itertools import chain
from typing import BinaryIO, Protocol

from nordis_smb_inspector.core.content import (
    ContentScanStatus,
    LineMatch,
    MatchOptions,
    scan_text,
)
from nordis_smb_inspector.core.credential_artifacts import (
    CredentialArtifactMatch,
    credential_artifact_header_bytes,
    detect_credential_artifact,
)
from nordis_smb_inspector.core.credentials import Credential
from nordis_smb_inspector.core.detection import (
    DEFAULT_DETECTION_RULES,
    DetectionConfidence,
    DetectionRule,
    PatternMatch,
)
from nordis_smb_inspector.core.detection import detect_patterns as detect_line_patterns
from nordis_smb_inspector.core.documents import (
    DocumentExtractionCode,
    DocumentExtractionError,
    DocumentKind,
    document_kind,
    encoded_document_lines,
    iter_archive_members,
    iter_document_lines,
)

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
    AuthMechanism,
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
    WriteAccessStatus,
)
from .range_io import RemoteRangeIO
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


class ShareDiscoveryLike(Protocol):
    @property
    def names(self) -> tuple[str, ...]: ...


class ShareDiscoverer(Protocol):
    def discover(
        self,
        *,
        target: str,
        credential: Credential,
        kerberos_hostname: str | None,
        mechanism: AuthMechanism,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> ShareDiscoveryLike: ...


class FileAdapter(Protocol):
    def probe_known_shares(
        self,
        session: SessionHandle,
        *,
        target: str,
        share_names: Iterable[str],
        cancellation: CancellationToken,
        test_write_access: bool = False,
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
    DISCOVERING_SHARES = "discovering_shares"
    PROBING_SHARES = "probing_shares"
    WALKING_SHARE = "walking_share"
    SCANNING_FILE = "scanning_file"
    STAGE_ERROR = "stage_error"
    TERMINAL = "terminal"


class FindingMethod(StrEnum):
    WORDLIST = "wordlist"
    PATTERN = "pattern"
    ARTIFACT = "artifact"


class _StageCancelled(ScanCancelled):
    __slots__ = ("stage",)

    def __init__(self, stage: TargetStage) -> None:
        super().__init__()
        self.stage = stage


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
    """One text match or binary credential artifact in a remote file."""

    target: str = field(repr=False)
    share: str = field(repr=False)
    path: str = field(repr=False)
    line_number: int | None
    term: str = field(repr=False)
    full_line: str | None = field(repr=False)
    method: FindingMethod = FindingMethod.WORDLIST
    rule_id: str | None = None
    category: str | None = None
    confidence: DetectionConfidence | None = None

    def __post_init__(self) -> None:
        for name in ("target", "share", "path", "term"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty text.")
        if not isinstance(self.method, FindingMethod):
            raise TypeError("method must be a FindingMethod value.")
        if self.method is FindingMethod.ARTIFACT:
            if self.line_number is not None or self.full_line is not None:
                raise ValueError("Artifact findings cannot contain decoded line content.")
        else:
            if isinstance(self.line_number, bool) or not isinstance(self.line_number, int):
                raise TypeError("line_number must be an integer.")
            if self.line_number < 1:
                raise ValueError("line_number must be at least one.")
            if not isinstance(self.full_line, str):
                raise TypeError("full_line must be text.")
        pattern_metadata = (self.rule_id, self.category, self.confidence)
        if self.method is FindingMethod.WORDLIST:
            if any(value is not None for value in pattern_metadata):
                raise ValueError("Wordlist findings cannot contain pattern metadata.")
        elif (
            not isinstance(self.rule_id, str)
            or not self.rule_id
            or not isinstance(self.category, str)
            or not self.category
            or not isinstance(self.confidence, DetectionConfidence)
        ):
            raise ValueError("Structured findings require rule metadata.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(context=<redacted>, "
            f"line_number={self.line_number!r}, method={self.method.value!r}, "
            f"rule_id={self.rule_id!r}, content=<redacted>)"
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
    operation_cleanup_failed: bool = False


TargetCallback = Callable[[InspectionTargetEvent], None]
InventoryCallback = Callable[[InventoryEntry], None]
FindingCallback = Callable[[ContentFinding], None]


def inspect_target(
    *,
    target: str,
    connect_request: ConnectRequest,
    credential: Credential,
    kerberos_hostname: str | None,
    search_terms: Iterable[str],
    max_depth: int,
    connector: Connector,
    authenticator: CredentialAuthenticator,
    file_adapter: FileAdapter,
    cancellation: CancellationToken,
    share_discoverer: ShareDiscoverer,
    detect_patterns: bool = True,
    pattern_rules: tuple[DetectionRule, ...] | None = None,
    detect_credential_artifacts: bool = True,
    test_write_access: bool = False,
    on_target: TargetCallback | None = None,
    on_inventory: InventoryCallback | None = None,
    on_finding: FindingCallback | None = None,
) -> InspectionResult:
    """Inspect one target through content scanning with one live session.

    Shares come solely from SRVSVC enumeration; there is no known-share
    fallback list.  Results retain counters and normalized protocol metadata
    only.  Inventory entries and content findings are delivered as they are
    encountered and are not accumulated by the orchestrator.
    """

    _validate_inputs(target, connect_request, credential, max_depth)
    if not isinstance(detect_patterns, bool):
        raise TypeError("detect_patterns must be a boolean.")
    if pattern_rules is None:
        selected_pattern_rules = DEFAULT_DETECTION_RULES
    elif isinstance(pattern_rules, tuple) and all(
        isinstance(rule, DetectionRule) for rule in pattern_rules
    ):
        selected_pattern_rules = pattern_rules
    else:
        raise TypeError("pattern_rules must be DetectionRule values.")
    if not isinstance(detect_credential_artifacts, bool):
        raise TypeError("detect_credential_artifacts must be a boolean.")
    if not isinstance(test_write_access, bool):
        raise TypeError("test_write_access must be a boolean.")
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
        negotiation = _negotiation_with_session_state(negotiation, session)
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

        last_stage = TargetStage.SHARE_ENUMERATION
        publish_target(
            InspectionTargetEvent(
                kind=InspectionEventKind.DISCOVERING_SHARES,
                target=target,
                stage=TargetStage.SHARE_ENUMERATION,
                negotiation=negotiation,
                authentication=authentication,
            )
        )
        shares_to_probe: tuple[str, ...] = ()
        enumeration_error: SmbErrorDetail | None = None
        try:
            discovered = share_discoverer.discover(
                target=target,
                credential=credential,
                kerberos_hostname=kerberos_hostname,
                mechanism=authentication.selected_mechanism,
                timeout_seconds=connect_request.timeout_seconds,
                cancellation=cancellation,
            )
        except ScanCancelled:
            raise
        except Exception as exception:
            # Without a known-share fallback, a failed enumeration must stay
            # visible: an empty share list means "this server exposes none",
            # which is not the same answer as "the list could not be read".
            detail = _share_discovery_error_detail(exception, target=target)
            enumeration_error = detail
            publish_target(
                _stage_error(
                    target,
                    TargetStage.SHARE_ENUMERATION,
                    status=detail.status,
                    error=detail,
                )
            )
        else:
            shares_to_probe = _normalize_share_names(discovered.names)

        if enumeration_error is not None:
            result = _result_from_outcome(
                target,
                TargetOutcome(
                    target=target,
                    stage=enumeration_error.stage,
                    status=enumeration_error.status,
                    error=enumeration_error,
                ),
                negotiation,
                authentication,
                counts,
            )
        else:
            last_stage = TargetStage.AUTHORIZATION
            publish_target(
                InspectionTargetEvent(
                    kind=InspectionEventKind.PROBING_SHARES,
                    target=target,
                    stage=TargetStage.AUTHORIZATION,
                    negotiation=negotiation,
                    authentication=authentication,
                )
            )
            try:
                probe_arguments = {
                    "target": target,
                    "share_names": shares_to_probe,
                    "cancellation": cancellation,
                }
                if test_write_access:
                    probe_arguments["test_write_access"] = True
                probes = file_adapter.probe_known_shares(session, **probe_arguments)
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
                        if probe.inventory.write_access in {
                            WriteAccessStatus.ERROR,
                            WriteAccessStatus.CLEANUP_FAILED,
                        }:
                            partial = True
                        if (
                            probe.inventory.write_access
                            is WriteAccessStatus.CLEANUP_FAILED
                        ):
                            counts.operation_cleanup_failed = True
                    if not share.content_walkable:
                        continue
                    if _walk_share(
                        target=target,
                        session=session,
                        share=share,
                        search_terms=normalized_terms,
                        detect_patterns=detect_patterns,
                        pattern_rules=selected_pattern_rules,
                        detect_credential_artifacts=detect_credential_artifacts,
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
            except Exception as exception:
                partial = True
                detail = _operation_error_detail(
                    exception,
                    stage=TargetStage.AUTHORIZATION,
                    status=TargetStatus.SHARE_CONNECT_ERROR,
                    operation="discovered_share_probe",
                    symbolic_name="SHARE_PROBE_FAILED",
                    message="Share probing could not complete.",
                )
                publish_target(
                    _stage_error(
                        target,
                        detail.stage,
                        status=detail.status,
                        error=detail,
                    )
                )

            terminal_status = TargetStatus.PARTIAL_ACCESS if partial else TargetStatus.COMPLETED
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
    except _StageCancelled as exception:
        result = _result_from_outcome(
            target,
            TargetOutcome(
                target=target,
                stage=exception.stage,
                status=TargetStatus.CANCELLED,
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
        cleanup_failed = counts.operation_cleanup_failed
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
    detect_patterns: bool,
    pattern_rules: tuple[DetectionRule, ...],
    detect_credential_artifacts: bool,
    max_depth: int,
    file_adapter: FileAdapter,
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
                detect_patterns=detect_patterns,
                pattern_rules=pattern_rules,
                detect_credential_artifacts=detect_credential_artifacts,
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
    except _StageCancelled:
        raise
    except ScanCancelled:
        raise _StageCancelled(TargetStage.TREE_WALK) from None
    except Exception as exception:
        partial = True
        detail = _operation_error_detail(
            exception,
            stage=TargetStage.TREE_WALK,
            status=TargetStatus.DIRECTORY_LIST_ERROR,
            operation="tree_walk",
            symbolic_name="TREE_WALK_FAILED",
            message="The share tree could not be inspected completely.",
        )
        _publish(
            on_target,
            _stage_error(
                target,
                detail.stage,
                share=share.name,
                status=detail.status,
                error=detail,
            ),
        )
    return partial


def _scan_file(
    *,
    target: str,
    session: SessionHandle,
    entry: InventoryEntry,
    search_terms: tuple[str, ...],
    detect_patterns: bool,
    pattern_rules: tuple[DetectionRule, ...],
    detect_credential_artifacts: bool,
    file_adapter: FileAdapter,
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
    document_stream: RemoteRangeIO | None = None
    partial = False
    active_path = entry.relative_path

    def publish_wordlist_match(match: LineMatch) -> None:
        counts.findings += 1
        _publish(
            on_finding,
            ContentFinding(
                target=target,
                share=entry.share_name,
                path=active_path,
                line_number=match.line_number,
                term=match.term,
                full_line=match.line,
                method=FindingMethod.WORDLIST,
            ),
        )

    def publish_pattern_matches(line_number: int, line: str) -> None:
        if not detect_patterns:
            return
        for match in detect_line_patterns(line, line_number, rules=pattern_rules):
            publish_pattern_match(match)

    def publish_pattern_match(match: PatternMatch) -> None:
        counts.findings += 1
        _publish(
            on_finding,
            ContentFinding(
                target=target,
                share=entry.share_name,
                path=active_path,
                line_number=match.line_number,
                term=match.title,
                full_line=match.line,
                method=FindingMethod.PATTERN,
                rule_id=match.rule_id,
                category=match.category,
                confidence=match.confidence,
            ),
        )

    def publish_artifact_match(match: CredentialArtifactMatch, path: str) -> None:
        counts.findings += 1
        _publish(
            on_finding,
            ContentFinding(
                target=target,
                share=entry.share_name,
                path=path,
                line_number=None,
                term=match.title,
                full_line=None,
                method=FindingMethod.ARTIFACT,
                rule_id=match.rule_id,
                category=match.category,
                confidence=match.confidence,
            ),
        )

    def scan_content(
        content_chunks: Iterable[bytes | bytearray | memoryview],
        *,
        finding_path: str,
    ) -> ContentScanStatus:
        nonlocal active_path
        active_path = finding_path
        return scan_text(
            content_chunks,
            search_terms,
            options=MatchOptions(case_sensitive=False),
            on_line=publish_pattern_matches,
            on_match=publish_wordlist_match,
            retain_matches=False,
            legacy_detection_sample_bytes=256 * 1024,
        ).status

    def mark_content_incomplete(
        status: ContentScanStatus,
        *,
        path: str,
        size: int | None,
    ) -> None:
        nonlocal partial
        counts.content_incomplete += 1
        partial = True
        detail = _content_result_error_detail(status)
        _publish(
            on_inventory,
            InventoryEntry(
                target=entry.target,
                share_name=entry.share_name,
                relative_path=path,
                kind=InventoryEntryKind.FILE,
                status=InventoryStatus.READ_ERROR,
                size=size,
                modified_at=entry.modified_at if path == entry.relative_path else None,
                error=detail,
            ),
        )
        _publish(
            on_target,
            _stage_error(
                target,
                TargetStage.FILE_READ,
                share=entry.share_name,
                path=path,
                status=detail.status,
                error=detail,
            ),
        )

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
        kind = document_kind(entry.relative_path)
        if kind is DocumentKind.PLAIN:
            header = b""
            if detect_patterns and detect_credential_artifacts:
                header = reader.read_range(
                    0,
                    min(
                        credential_artifact_header_bytes(),
                        reader.max_read_size,
                        reader.size,
                    ),
                    cancellation=cancellation,
                )
                artifact = detect_credential_artifact(entry.relative_path, header)
                if artifact is not None:
                    publish_artifact_match(artifact, entry.relative_path)
                    counts.files_scanned += 1
                    return partial
            status = scan_content(
                chain(
                    (header,),
                    reader.iter_chunks(
                        chunk_size=chunk_size,
                        cancellation=cancellation,
                        start_offset=len(header),
                    ),
                ),
                finding_path=entry.relative_path,
            )
            counts.files_scanned += 1
            if status is not ContentScanStatus.COMPLETE:
                mark_content_incomplete(
                    status,
                    path=entry.relative_path,
                    size=entry.size,
                )
        elif kind in {
            DocumentKind.ZIP_ARCHIVE,
            DocumentKind.TAR_ARCHIVE,
            DocumentKind.GZIP_ARCHIVE,
        }:
            document_stream = RemoteRangeIO(reader, cancellation=cancellation)
            for member in iter_archive_members(document_stream, entry.relative_path):
                cancellation.raise_if_cancelled()
                counts.inventory_items += 1
                counts.files_seen += 1
                _publish(
                    on_inventory,
                    InventoryEntry(
                        target=entry.target,
                        share_name=entry.share_name,
                        relative_path=member.path,
                        kind=InventoryEntryKind.FILE,
                        status=InventoryStatus.FILE_READABLE,
                        size=member.size,
                    ),
                )
                if member.kind is DocumentKind.PLAIN:
                    header = b""
                    if detect_patterns and detect_credential_artifacts:
                        header = member.stream.read(credential_artifact_header_bytes())
                        if not isinstance(header, bytes):
                            raise TypeError("Archive member reads must return bytes.")
                        artifact = detect_credential_artifact(member.path, header)
                        if artifact is not None:
                            publish_artifact_match(artifact, member.path)
                            counts.files_scanned += 1
                            continue
                    content_chunks = chain(
                        (header,),
                        _iter_binary_stream(member.stream, cancellation),
                    )
                else:
                    content_chunks = encoded_document_lines(
                        _cancelled_lines(
                            iter_document_lines(member.stream, member.path),
                            cancellation,
                        )
                    )
                status = scan_content(content_chunks, finding_path=member.path)
                counts.files_scanned += 1
                if status is not ContentScanStatus.COMPLETE:
                    mark_content_incomplete(
                        status,
                        path=member.path,
                        size=member.size,
                    )
        else:
            document_stream = RemoteRangeIO(reader, cancellation=cancellation)
            status = scan_content(
                encoded_document_lines(
                    _cancelled_lines(
                        iter_document_lines(document_stream, entry.relative_path),
                        cancellation,
                    )
                ),
                finding_path=entry.relative_path,
            )
            counts.files_scanned += 1
            if status is not ContentScanStatus.COMPLETE:
                mark_content_incomplete(
                    status,
                    path=entry.relative_path,
                    size=entry.size,
                )
    except _StageCancelled:
        raise
    except ScanCancelled:
        raise _StageCancelled(TargetStage.FILE_READ) from None
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
        if document_stream is not None:
            with suppress(Exception):
                document_stream.close()
        if reader is not None and _close_handle(reader):
            partial = True
            counts.operation_cleanup_failed = True
            detail = _safe_detail(
                TargetStage.FILE_READ,
                TargetStatus.FILE_READ_ERROR,
                operation="file_reader_cleanup",
                raw_code=errno.EIO,
                symbolic_name="FILE_READER_CLEANUP_FAILED",
                message="The remote file reader could not be closed cleanly.",
            )
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
    return partial


def _iter_binary_stream(
    source: BinaryIO,
    cancellation: CancellationToken,
) -> Iterator[bytes]:
    while True:
        cancellation.raise_if_cancelled()
        chunk = source.read(_STREAM_CHUNK_SIZE)
        if not chunk:
            return
        if not isinstance(chunk, bytes):
            raise TypeError("Archive member reads must return bytes.")
        yield chunk


def _cancelled_lines(
    lines: Iterable[str],
    cancellation: CancellationToken,
) -> Iterator[str]:
    for line in lines:
        cancellation.raise_if_cancelled()
        yield line


def _file_error_detail(exception: BaseException) -> SmbErrorDetail:
    if isinstance(exception, DocumentExtractionError):
        if exception.code is DocumentExtractionCode.ENCRYPTED_CONTAINER:
            raw_code = errno.EACCES
            symbolic_name = "DOCUMENT_ENCRYPTED"
        elif exception.code in {
            DocumentExtractionCode.ENTRY_LIMIT,
            DocumentExtractionCode.EXPANDED_SIZE_LIMIT,
            DocumentExtractionCode.TEXT_LIMIT,
            DocumentExtractionCode.PARSER_READ_LIMIT,
            DocumentExtractionCode.PDF_PAGE_LIMIT,
        }:
            raw_code = errno.EFBIG
            symbolic_name = "DOCUMENT_LIMIT_REACHED"
        else:
            raw_code = errno.EILSEQ
            symbolic_name = "DOCUMENT_PARSE_FAILED"
        return _safe_detail(
            TargetStage.FILE_READ,
            TargetStatus.FILE_READ_ERROR,
            operation="structured_document_scan",
            raw_code=raw_code,
            symbolic_name=symbolic_name,
            message=exception.safe_message,
        )
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


def _content_result_error_detail(status: ContentScanStatus) -> SmbErrorDetail:
    if status is ContentScanStatus.ENCODING_UNDETERMINED:
        raw_code = errno.EILSEQ
        symbolic_name = "TEXT_ENCODING_UNDETERMINED"
        message = "Metin encoding'i güvenilir biçimde belirlenemedi."
    elif status is ContentScanStatus.DECODING_ERROR:
        raw_code = errno.EILSEQ
        symbolic_name = "TEXT_DECODING_FAILED"
        message = "Dosya bildirilen Unicode encoding ile çözümlenemedi."
    else:
        raw_code = errno.EFBIG
        symbolic_name = "TEXT_LINE_LIMIT_REACHED"
        message = "Dosyadaki bir metin satırı güvenli tarama sınırını aşıyor."
    return _safe_detail(
        TargetStage.FILE_READ,
        TargetStatus.FILE_READ_ERROR,
        operation="text_content_scan",
        raw_code=raw_code,
        symbolic_name=symbolic_name,
        message=message,
    )


def _share_discovery_error_detail(
    exception: BaseException,
    *,
    target: str,
) -> SmbErrorDetail:
    detail = getattr(exception, "detail", None)
    if (
        isinstance(detail, SmbErrorDetail)
        and detail.stage is TargetStage.SHARE_ENUMERATION
        and detail.status
        in {
            TargetStatus.SHARE_ENUM_DENIED,
            TargetStatus.SHARE_ENUM_UNAVAILABLE,
            TargetStatus.SHARE_ENUM_FAILED,
        }
    ):
        return detail
    return SmbErrorDetail(
        stage=TargetStage.SHARE_ENUMERATION,
        status=TargetStatus.SHARE_ENUM_FAILED,
        operation="srvsvc_netr_share_enum",
        raw_code=errno.EPROTO,
        safe_message="Sunucudaki share listesi SRVSVC üzerinden alınamadı.",
        retryable=False,
        symbolic_name="SHARE_ENUM_FAILED",
        target=target,
    )


def _operation_error_detail(
    exception: BaseException,
    *,
    stage: TargetStage,
    status: TargetStatus,
    operation: str,
    symbolic_name: str,
    message: str,
) -> SmbErrorDetail:
    detail = getattr(exception, "detail", None)
    if isinstance(detail, SmbErrorDetail):
        return detail
    return _safe_detail(
        stage,
        status,
        operation=operation,
        raw_code=errno.EIO,
        symbolic_name=symbolic_name,
        message=message,
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


def _negotiation_with_session_state(
    negotiation: NegotiationInfo,
    session: SessionHandle,
) -> NegotiationInfo:
    signing_active = getattr(session, "signing_active", None)
    encryption_active = getattr(session, "encryption_active", None)
    signing = negotiation.security.signing
    encryption = negotiation.security.encryption
    if isinstance(signing_active, bool):
        signing = replace(signing, active=signing_active)
    if isinstance(encryption_active, bool):
        encryption = replace(encryption, active=encryption_active)
    return replace(
        negotiation,
        security=replace(
            negotiation.security,
            signing=signing,
            encryption=encryption,
        ),
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
        if not candidate:
            continue
        if any(character in candidate for character in ("/", "\\", "\x00", "\r", "\n")):
            raise ValueError("Share names cannot contain path separators or control bytes.")
        if candidate in {".", ".."}:
            raise ValueError("Share name is invalid.")
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
