"""Framework-neutral result models for the read-only SMB adapter.

These objects deliberately contain no third-party SMB types.  Adapter code may
translate library-specific state into these values while the orchestrator and
web layer remain independent of the selected SMB implementation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class TargetStage(StrEnum):
    """The last meaningful stage reached for one expanded target."""

    NETWORK = "network"
    NEGOTIATION = "negotiation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SHARE_ENUMERATION = "share_enumeration"
    TREE_WALK = "tree_walk"
    FILE_READ = "file_read"
    COMPLETE = "complete"


class TargetStatus(StrEnum):
    """Stable status values exposed to the orchestrator and live UI."""

    TIMEOUT_NO_RESPONSE = "timeout_no_response"
    CONNECTION_REFUSED = "connection_refused"
    NETWORK_UNREACHABLE = "network_unreachable"
    PORT_OPEN = "port_open"
    NEGOTIATION_FAILED = "negotiation_failed"
    SMB1_ONLY_UNSUPPORTED = "smb1_only_unsupported"
    AUTH_FAILED = "auth_failed"
    AUTHENTICATED = "authenticated"
    ACCESS_DENIED = "access_denied"
    SHARE_ENUM_DENIED = "share_enum_denied"
    SHARE_ENUM_UNAVAILABLE = "share_enum_unavailable"
    SHARE_ENUM_FAILED = "share_enum_failed"
    SHARE_NOT_FOUND = "share_not_found"
    SHARE_CONNECT_ERROR = "share_connect_error"
    FILE_READ_DENIED = "file_read_denied"
    FILE_READ_ERROR = "file_read_error"
    DIRECTORY_LIST_DENIED = "directory_list_denied"
    DIRECTORY_LIST_ERROR = "directory_list_error"
    SHARING_VIOLATION = "sharing_violation"
    PARTIAL_ACCESS = "partial_access"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


_STATUS_STAGES: dict[TargetStatus, frozenset[TargetStage]] = {
    TargetStatus.TIMEOUT_NO_RESPONSE: frozenset({TargetStage.NETWORK}),
    TargetStatus.CONNECTION_REFUSED: frozenset({TargetStage.NETWORK}),
    TargetStatus.NETWORK_UNREACHABLE: frozenset({TargetStage.NETWORK}),
    TargetStatus.PORT_OPEN: frozenset({TargetStage.NETWORK}),
    TargetStatus.NEGOTIATION_FAILED: frozenset({TargetStage.NEGOTIATION}),
    TargetStatus.SMB1_ONLY_UNSUPPORTED: frozenset({TargetStage.NEGOTIATION}),
    TargetStatus.AUTH_FAILED: frozenset({TargetStage.AUTHENTICATION}),
    TargetStatus.AUTHENTICATED: frozenset({TargetStage.AUTHENTICATION}),
    TargetStatus.ACCESS_DENIED: frozenset(
        {
            TargetStage.AUTHORIZATION,
            TargetStage.SHARE_ENUMERATION,
            TargetStage.TREE_WALK,
            TargetStage.FILE_READ,
        }
    ),
    TargetStatus.SHARE_ENUM_DENIED: frozenset({TargetStage.SHARE_ENUMERATION}),
    TargetStatus.SHARE_ENUM_UNAVAILABLE: frozenset({TargetStage.SHARE_ENUMERATION}),
    TargetStatus.SHARE_ENUM_FAILED: frozenset({TargetStage.SHARE_ENUMERATION}),
    TargetStatus.SHARE_NOT_FOUND: frozenset({TargetStage.AUTHORIZATION}),
    TargetStatus.SHARE_CONNECT_ERROR: frozenset({TargetStage.AUTHORIZATION}),
    TargetStatus.FILE_READ_DENIED: frozenset({TargetStage.FILE_READ}),
    TargetStatus.FILE_READ_ERROR: frozenset({TargetStage.FILE_READ}),
    TargetStatus.DIRECTORY_LIST_DENIED: frozenset({TargetStage.TREE_WALK}),
    TargetStatus.DIRECTORY_LIST_ERROR: frozenset({TargetStage.TREE_WALK}),
    TargetStatus.SHARING_VIOLATION: frozenset({TargetStage.FILE_READ}),
    TargetStatus.PARTIAL_ACCESS: frozenset({TargetStage.COMPLETE}),
    TargetStatus.COMPLETED: frozenset({TargetStage.COMPLETE}),
    TargetStatus.CANCELLED: frozenset(TargetStage),
}


@dataclass(frozen=True, slots=True, repr=False)
class SmbErrorDetail:
    """A lossless numeric error plus context-free text suitable for the UI.

    Context fields are retained in memory for routing, but omitted from
    ``repr`` so tracebacks and debug summaries do not leak targets, paths, or
    account identities.  ``safe_message`` must be prepared by the adapter and
    must not contain those values; its content is also omitted from ``repr`` as
    defence in depth.
    """

    stage: TargetStage
    status: TargetStatus
    operation: str
    raw_code: int
    safe_message: str
    retryable: bool = False
    symbolic_name: str | None = None
    target: str | None = field(default=None, repr=False, compare=False)
    path: str | None = field(default=None, repr=False, compare=False)
    identity: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.stage not in _STATUS_STAGES[self.status]:
            raise ValueError(
                f"Status {self.status.value!r} is not valid at stage {self.stage.value!r}."
            )
        if not isinstance(self.operation, str) or not self.operation.strip():
            raise ValueError("operation must be non-empty text.")
        if isinstance(self.raw_code, bool) or not isinstance(self.raw_code, int):
            raise TypeError("raw_code must be an integer.")
        if not isinstance(self.safe_message, str) or not self.safe_message.strip():
            raise ValueError("safe_message must be non-empty text.")
        if "\n" in self.safe_message or "\r" in self.safe_message:
            raise ValueError("safe_message must be a single line.")
        if not isinstance(self.retryable, bool):
            raise TypeError("retryable must be a boolean.")
        if self.symbolic_name is not None and (
            not isinstance(self.symbolic_name, str) or not self.symbolic_name.strip()
        ):
            raise ValueError("symbolic_name must be non-empty text when supplied.")

    def __str__(self) -> str:
        return self.safe_message

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(stage={self.stage.value!r}, "
            f"status={self.status.value!r}, operation={self.operation!r}, "
            f"raw_code={self.raw_code!r}, symbolic_name={self.symbolic_name!r}, "
            f"retryable={self.retryable!r}, message=<redacted>, context=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TargetOutcome:
    """Current or terminal outcome for one expanded target."""

    target: str = field(repr=False)
    stage: TargetStage
    status: TargetStatus
    elapsed_seconds: float | None = None
    error: SmbErrorDetail | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")
        if self.stage not in _STATUS_STAGES[self.status]:
            raise ValueError(
                f"Status {self.status.value!r} is not valid at stage {self.stage.value!r}."
            )
        if self.elapsed_seconds is not None and (
            isinstance(self.elapsed_seconds, bool)
            or not isinstance(self.elapsed_seconds, (int, float))
            or not math.isfinite(self.elapsed_seconds)
            or self.elapsed_seconds < 0
        ):
            raise ValueError("elapsed_seconds must be a finite, non-negative number.")
        if self.error is not None and (
            self.error.stage is not self.stage or self.error.status is not self.status
        ):
            raise ValueError("error stage and status must match the target outcome.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target=<redacted>, stage={self.stage.value!r}, "
            f"status={self.status.value!r}, elapsed_seconds={self.elapsed_seconds!r}, "
            f"error={self.error!r})"
        )


class AuthMechanism(StrEnum):
    KERBEROS = "kerberos"
    NTLM = "ntlm"


class AuthAttemptOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FallbackReason(StrEnum):
    """Why Auto mode left Kerberos or could not perform its NTLM fallback."""

    KERBEROS_HOSTNAME_UNRESOLVED = "kerberos_hostname_unresolved"
    KDC_UNREACHABLE = "kdc_unreachable"
    SPN_NOT_FOUND = "spn_not_found"
    CLOCK_SKEW = "clock_skew"
    REALM_MISMATCH = "realm_mismatch"
    UNSUPPORTED_MECHANISM = "unsupported_mechanism"
    NTLM_FALLBACK_UNAVAILABLE = "ntlm_fallback_unavailable"


@dataclass(frozen=True, slots=True)
class AuthAttempt:
    mechanism: AuthMechanism
    outcome: AuthAttemptOutcome
    elapsed_seconds: float | None = None
    error: SmbErrorDetail | None = None

    def __post_init__(self) -> None:
        if self.elapsed_seconds is not None and (
            isinstance(self.elapsed_seconds, bool)
            or not isinstance(self.elapsed_seconds, (int, float))
            or not math.isfinite(self.elapsed_seconds)
            or self.elapsed_seconds < 0
        ):
            raise ValueError("elapsed_seconds must be a finite, non-negative number.")
        if self.outcome is AuthAttemptOutcome.SUCCEEDED and self.error is not None:
            raise ValueError("A successful authentication attempt cannot contain an error.")
        if self.outcome is AuthAttemptOutcome.FAILED and self.error is None:
            raise ValueError("A failed authentication attempt must contain an error.")
        if self.error is not None and self.error.stage is not TargetStage.AUTHENTICATION:
            raise ValueError("Authentication attempt errors must use the authentication stage.")


@dataclass(frozen=True, slots=True)
class AuthenticationHistory:
    """Ordered, explicit record of Kerberos and NTLM authentication attempts."""

    attempts: tuple[AuthAttempt, ...]
    selected_mechanism: AuthMechanism | None
    fallback_reason: FallbackReason | None = None

    def __post_init__(self) -> None:
        if not self.attempts:
            raise ValueError("Authentication history must contain at least one attempt.")
        mechanisms = tuple(attempt.mechanism for attempt in self.attempts)
        if len(set(mechanisms)) != len(mechanisms):
            raise ValueError("Each authentication mechanism may be attempted at most once.")
        if AuthMechanism.KERBEROS in mechanisms and AuthMechanism.NTLM in mechanisms:
            if mechanisms != (AuthMechanism.KERBEROS, AuthMechanism.NTLM):
                raise ValueError("Kerberos must precede NTLM when both are attempted.")
            if self.fallback_reason is None:
                raise ValueError("A Kerberos-to-NTLM fallback must record its reason.")

        succeeded = tuple(
            attempt.mechanism
            for attempt in self.attempts
            if attempt.outcome is AuthAttemptOutcome.SUCCEEDED
        )
        if len(succeeded) > 1:
            raise ValueError("At most one authentication attempt may succeed.")
        if succeeded:
            if self.selected_mechanism is not succeeded[0]:
                raise ValueError("selected_mechanism must identify the successful attempt.")
        elif self.selected_mechanism is not None:
            raise ValueError("selected_mechanism requires a successful attempt.")

        if self.fallback_reason is not None:
            if mechanisms[0] is not AuthMechanism.KERBEROS:
                raise ValueError("Fallback metadata requires a Kerberos attempt first.")
            kerberos = self.attempts[0]
            if kerberos.outcome is AuthAttemptOutcome.SUCCEEDED:
                raise ValueError("A successful Kerberos attempt cannot have a fallback reason.")
            if self.fallback_reason is FallbackReason.NTLM_FALLBACK_UNAVAILABLE:
                if AuthMechanism.NTLM in mechanisms:
                    raise ValueError("Unavailable NTLM fallback cannot contain an NTLM attempt.")
            elif AuthMechanism.NTLM not in mechanisms:
                raise ValueError("A recorded fallback reason requires an NTLM attempt.")

    @property
    def authenticated(self) -> bool:
        return self.selected_mechanism is not None

    def attempt_for(self, mechanism: AuthMechanism) -> AuthAttempt | None:
        return next(
            (attempt for attempt in self.attempts if attempt.mechanism is mechanism),
            None,
        )


class SmbDialect(StrEnum):
    SMB1 = "1.0"
    SMB_2_0_2 = "2.0.2"
    SMB_2_1 = "2.1"
    SMB_3_0 = "3.0"
    SMB_3_0_2 = "3.0.2"
    SMB_3_1_1 = "3.1.1"


class AlgorithmSource(StrEnum):
    NEGOTIATED = "negotiated"
    DIALECT_INFERRED = "dialect_inferred"


class RequirementSource(StrEnum):
    SERVER = "server"
    SESSION = "session"
    SHARE = "share"
    SERVER_AND_SHARE = "server_and_share"


@dataclass(frozen=True, slots=True)
class SecurityFeatureState:
    """Independent support, policy requirement, and active-session state."""

    supported: bool | None
    required: bool | None
    active: bool | None
    algorithm: str | None = None
    algorithm_source: AlgorithmSource | None = None
    requirement_source: RequirementSource | None = None

    def __post_init__(self) -> None:
        for name in ("supported", "required", "active"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, bool):
                raise TypeError(f"{name} must be a boolean or None.")
        if self.supported is False and (self.required is True or self.active is True):
            raise ValueError("An unsupported feature cannot be required or active.")
        if self.algorithm is not None and (
            not isinstance(self.algorithm, str) or not self.algorithm.strip()
        ):
            raise ValueError("algorithm must be non-empty text when supplied.")
        if (self.algorithm is None) is not (self.algorithm_source is None):
            raise ValueError("algorithm and algorithm_source must be supplied together.")
        if self.algorithm is not None and self.supported is False:
            raise ValueError("An unsupported feature cannot have a selected algorithm.")
        if self.requirement_source is not None and self.required is not True:
            raise ValueError("requirement_source is only valid when required is true.")


@dataclass(frozen=True, slots=True)
class TransportSecurity:
    """Signing and encryption are intentionally represented separately."""

    signing: SecurityFeatureState
    encryption: SecurityFeatureState


@dataclass(frozen=True, slots=True)
class NegotiationInfo:
    dialect: SmbDialect
    security: TransportSecurity
    max_read_size: int

    def __post_init__(self) -> None:
        if isinstance(self.max_read_size, bool) or not isinstance(self.max_read_size, int):
            raise TypeError("max_read_size must be an integer.")
        if self.max_read_size < 1:
            raise ValueError("max_read_size must be at least one byte.")
        if self.dialect is SmbDialect.SMB1:
            raise ValueError("SMB1 is probe-only and cannot produce a usable negotiation.")


class ShareKind(StrEnum):
    DISK = "disk"
    NAMED_PIPE = "named_pipe"
    PRINT_QUEUE = "print_queue"
    DEVICE = "device"
    UNKNOWN = "unknown"


class ShareAccessStatus(StrEnum):
    CONNECTED = "connected"
    ACCESS_DENIED = "access_denied"
    NOT_FOUND = "not_found"
    ERROR = "error"


@dataclass(frozen=True, slots=True, repr=False)
class ShareInfo:
    target: str = field(repr=False)
    name: str = field(repr=False)
    kind: ShareKind
    access_status: ShareAccessStatus
    error: SmbErrorDetail | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("share name must be non-empty text.")
        if self.access_status is ShareAccessStatus.CONNECTED and self.error is not None:
            raise ValueError("A connected share cannot contain an error.")
        if self.access_status is not ShareAccessStatus.CONNECTED and self.error is None:
            raise ValueError("An inaccessible share must contain an error.")
        if self.error is not None:
            expected_status = {
                ShareAccessStatus.ACCESS_DENIED: TargetStatus.ACCESS_DENIED,
                ShareAccessStatus.NOT_FOUND: TargetStatus.SHARE_NOT_FOUND,
                ShareAccessStatus.ERROR: TargetStatus.SHARE_CONNECT_ERROR,
            }[self.access_status]
            if self.error.status is not expected_status:
                raise ValueError("Share access status and error status must agree.")

    @property
    def content_walkable(self) -> bool:
        return self.kind is ShareKind.DISK and self.access_status is ShareAccessStatus.CONNECTED

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target=<redacted>, name=<redacted>, "
            f"kind={self.kind.value!r}, access_status={self.access_status.value!r}, "
            f"error={self.error!r})"
        )


@dataclass(frozen=True, slots=True)
class ShareEnumerationResult:
    shares: tuple[ShareInfo, ...]
    complete: bool
    error: SmbErrorDetail | None = None

    def __post_init__(self) -> None:
        if self.complete and self.error is not None:
            raise ValueError("A complete share enumeration cannot contain an error.")
        if not self.complete and self.error is None:
            raise ValueError("An incomplete share enumeration must contain an error.")
        if self.error is not None and self.error.stage is not TargetStage.SHARE_ENUMERATION:
            raise ValueError("Share enumeration errors must use the share-enumeration stage.")


class InventoryEntryKind(StrEnum):
    SHARE = "share"
    DIRECTORY = "directory"
    FILE = "file"


class InventoryStatus(StrEnum):
    SHARE_CONNECTED = "share_connected"
    SHARE_ACCESS_DENIED = "share_access_denied"
    NON_FILE_SHARE = "non_file_share"
    DIRECTORY_LISTABLE = "directory_listable"
    DIRECTORY_LIST_DENIED = "directory_list_denied"
    DEPTH_LIMIT_REACHED = "depth_limit_reached"
    FILE_READABLE = "file_readable"
    FILE_READ_DENIED = "file_read_denied"
    SHARING_VIOLATION = "sharing_violation"
    READ_ERROR = "read_error"


_INVENTORY_STATUSES: dict[InventoryEntryKind, frozenset[InventoryStatus]] = {
    InventoryEntryKind.SHARE: frozenset(
        {
            InventoryStatus.SHARE_CONNECTED,
            InventoryStatus.SHARE_ACCESS_DENIED,
            InventoryStatus.NON_FILE_SHARE,
        }
    ),
    InventoryEntryKind.DIRECTORY: frozenset(
        {
            InventoryStatus.DIRECTORY_LISTABLE,
            InventoryStatus.DIRECTORY_LIST_DENIED,
            InventoryStatus.DEPTH_LIMIT_REACHED,
        }
    ),
    InventoryEntryKind.FILE: frozenset(
        {
            InventoryStatus.FILE_READABLE,
            InventoryStatus.FILE_READ_DENIED,
            InventoryStatus.SHARING_VIOLATION,
            InventoryStatus.READ_ERROR,
        }
    ),
}

_INVENTORY_ERROR_STATUSES = frozenset(
    {
        InventoryStatus.SHARE_ACCESS_DENIED,
        InventoryStatus.DIRECTORY_LIST_DENIED,
        InventoryStatus.FILE_READ_DENIED,
        InventoryStatus.SHARING_VIOLATION,
        InventoryStatus.READ_ERROR,
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class InventoryEntry:
    """A visible share, directory, or file, including inaccessible entries."""

    target: str = field(repr=False)
    share_name: str = field(repr=False)
    relative_path: str = field(default="", repr=False)
    kind: InventoryEntryKind = InventoryEntryKind.FILE
    status: InventoryStatus = InventoryStatus.FILE_READABLE
    share_kind: ShareKind | None = None
    size: int | None = None
    modified_at: datetime | None = None
    error: SmbErrorDetail | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")
        if not isinstance(self.share_name, str) or not self.share_name.strip():
            raise ValueError("share_name must be non-empty text.")
        if not isinstance(self.relative_path, str):
            raise TypeError("relative_path must be text.")
        if self.status not in _INVENTORY_STATUSES[self.kind]:
            raise ValueError(
                f"Status {self.status.value!r} is not valid for {self.kind.value!r}."
            )
        if self.size is not None and (
            isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0
        ):
            raise ValueError("size must be a non-negative integer when supplied.")
        if self.kind is not InventoryEntryKind.FILE and self.size is not None:
            raise ValueError("Only file entries may have a size.")
        if self.kind is InventoryEntryKind.SHARE:
            if self.relative_path:
                raise ValueError("Share entries cannot have a relative path.")
            if self.share_kind is None:
                raise ValueError("Share entries must identify their share kind.")
            if self.status is InventoryStatus.NON_FILE_SHARE and self.share_kind is ShareKind.DISK:
                raise ValueError("A disk share cannot be marked as a non-file share.")
            if (
                self.status is not InventoryStatus.NON_FILE_SHARE
                and self.share_kind is not ShareKind.DISK
            ):
                raise ValueError("Non-disk shares must use NON_FILE_SHARE status.")
        elif self.share_kind is not None:
            raise ValueError("Only share entries may carry share_kind.")

        needs_error = self.status in _INVENTORY_ERROR_STATUSES
        if needs_error and self.error is None:
            raise ValueError(f"Status {self.status.value!r} requires an error detail.")
        if not needs_error and self.error is not None:
            raise ValueError(f"Status {self.status.value!r} cannot contain an error detail.")

        if self.error is not None:
            expected = {
                InventoryStatus.SHARE_ACCESS_DENIED: TargetStatus.ACCESS_DENIED,
                InventoryStatus.DIRECTORY_LIST_DENIED: TargetStatus.DIRECTORY_LIST_DENIED,
                InventoryStatus.FILE_READ_DENIED: TargetStatus.FILE_READ_DENIED,
                InventoryStatus.SHARING_VIOLATION: TargetStatus.SHARING_VIOLATION,
                InventoryStatus.READ_ERROR: TargetStatus.FILE_READ_ERROR,
            }[self.status]
            if self.error.status is not expected:
                raise ValueError("Inventory status and error status must agree.")

    @property
    def readable(self) -> bool:
        return self.status in {
            InventoryStatus.SHARE_CONNECTED,
            InventoryStatus.DIRECTORY_LISTABLE,
            InventoryStatus.FILE_READABLE,
        }

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target=<redacted>, share_name=<redacted>, "
            f"relative_path=<redacted>, kind={self.kind.value!r}, "
            f"status={self.status.value!r}, size={self.size!r}, error={self.error!r})"
        )
