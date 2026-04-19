"""SMB 2/3 negotiation adapter backed by ``smbprotocol`` 1.17.

Only the transport connection and SMB negotiate exchange live here.  Session
authentication, tree connections, and file operations are deliberately absent.
The returned handle exposes normalized negotiation metadata and ``close`` only;
it does not expose smbprotocol's mutating primitives.
"""

from __future__ import annotations

import errno
import math
import socket
import time
import uuid
from collections.abc import Callable, Iterator
from threading import Lock
from typing import Any, Protocol

from smbprotocol.connection import Connection, SecurityMode

from .cancellation import CancellationToken, ScanCancelled
from .contracts import ConnectRequest
from .models import (
    AlgorithmSource,
    NegotiationInfo,
    RequirementSource,
    SecurityFeatureState,
    SmbDialect,
    SmbErrorDetail,
    TargetOutcome,
    TargetStage,
    TargetStatus,
    TransportSecurity,
)

_DIALECTS: dict[int, SmbDialect] = {
    0x0202: SmbDialect.SMB_2_0_2,
    0x0210: SmbDialect.SMB_2_1,
    0x0300: SmbDialect.SMB_3_0,
    0x0302: SmbDialect.SMB_3_0_2,
    0x0311: SmbDialect.SMB_3_1_1,
}

_SIGNING_ALGORITHMS = {
    0x0000: "HMAC-SHA256",
    0x0001: "AES-128-CMAC",
    0x0002: "AES-128-GMAC",
}

_ENCRYPTION_ALGORITHMS = {
    0x0001: "AES-128-CCM",
    0x0002: "AES-128-GCM",
    0x0003: "AES-256-CCM",
    0x0004: "AES-256-GCM",
}

_UNREACHABLE_ERRNOS = frozenset(
    code
    for code in (
        getattr(errno, "ENETUNREACH", None),
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ENETDOWN", None),
        getattr(errno, "EHOSTDOWN", None),
    )
    if code is not None
)


class _NativeConnection(Protocol):
    dialect: int | None
    max_read_size: int | None
    server_security_mode: int | None
    supports_encryption: bool | None
    signing_algorithm_id: int | None
    cipher_id: int | None
    transport: Any

    def connect(self, dialect: int | None = None, timeout: float = 60, **kwargs: Any) -> None: ...

    def disconnect(self, close: bool = True, timeout: float | None = None) -> None: ...


class _ConnectionFactory(Protocol):
    def __call__(
        self,
        guid: uuid.UUID,
        server_name: str,
        port: int = 445,
        require_signing: bool = True,
    ) -> _NativeConnection: ...


class NegotiationMetadataError(RuntimeError):
    """Raised when a successful native call did not yield usable SMB metadata."""

    def __init__(self, safe_message: str = "SMB negotiation metadata was invalid.") -> None:
        self.safe_message = safe_message
        super().__init__(safe_message)


class SmbProtocolConnectError(ConnectionError):
    """Safe exception wrapper carrying the normalized in-memory outcome."""

    def __init__(self, outcome: TargetOutcome) -> None:
        self.outcome = outcome
        message = (
            outcome.error.safe_message
            if outcome.error is not None
            else "The SMB connection attempt failed."
        )
        super().__init__(message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(outcome={self.outcome!r})"


class SmbProtocolCloseError(ConnectionError):
    """Context-free cleanup error that does not expose the native exception."""

    def __init__(self) -> None:
        super().__init__("The SMB transport could not be closed cleanly.")


class SmbProtocolConnectionHandle:
    """Narrow, read-only view over one successfully negotiated connection."""

    __slots__ = (
        "_closed",
        "_close_lock",
        "_native",
        "_negotiation",
        "_require_encryption",
        "_require_secure_negotiate",
    )

    def __init__(
        self,
        native: _NativeConnection,
        negotiation: NegotiationInfo,
        *,
        require_encryption: bool,
        require_secure_negotiate: bool,
    ) -> None:
        self._native = native
        self._negotiation = negotiation
        self._require_encryption = require_encryption
        self._require_secure_negotiate = require_secure_negotiate
        self._closed = False
        self._close_lock = Lock()

    @property
    def negotiation(self) -> NegotiationInfo:
        return self._negotiation

    @property
    def require_encryption(self) -> bool:
        """Session policy retained for the later authentication adapter."""

        return self._require_encryption

    @property
    def require_secure_negotiate(self) -> bool:
        """Tree-connect policy retained for the later authorization adapter."""

        return self._require_secure_negotiate

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def _native_connection(self) -> _NativeConnection:
        """Internal bridge for later adapters in this package."""

        if self.closed:
            raise ValueError("The SMB connection handle is closed.")
        return self._native

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            try:
                self._native.disconnect(close=True)
            except Exception:
                raise SmbProtocolCloseError() from None
            finally:
                self._closed = True

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(negotiation={self.negotiation!r}, "
            f"require_encryption={self.require_encryption!r}, "
            f"require_secure_negotiate={self.require_secure_negotiate!r}, "
            f"closed={self.closed!r}, native=<redacted>)"
        )


class SmbProtocolConnector:
    """Create an SMB transport and complete an SMB 2/3 negotiate exchange."""

    __slots__ = ("_clock", "_connection_factory", "_guid_factory")

    def __init__(
        self,
        *,
        connection_factory: _ConnectionFactory = Connection,
        guid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._connection_factory = connection_factory
        self._guid_factory = guid_factory
        self._clock = clock

    def connect(
        self,
        request: ConnectRequest,
        *,
        cancellation: CancellationToken,
    ) -> SmbProtocolConnectionHandle:
        cancellation.raise_if_cancelled()
        started = self._clock()
        native: _NativeConnection | None = None
        try:
            native = self._connection_factory(
                self._guid_factory(),
                request.target,
                port=request.port,
                require_signing=request.require_signing,
            )
            native.connect(timeout=request.timeout_seconds)
            cancellation.raise_if_cancelled()
            negotiation = negotiation_info_from_native(native)
            if request.require_signing and negotiation.security.signing.supported is not True:
                raise NegotiationMetadataError(
                    "The server does not support the required SMB signing policy."
                )
            if request.require_encryption and negotiation.security.encryption.supported is not True:
                raise NegotiationMetadataError(
                    "The server does not support the required SMB encryption policy."
                )
        except ScanCancelled:
            if native is not None:
                _discard_native_connection(native)
            raise
        except Exception as exc:
            elapsed = _elapsed(self._clock(), started)
            tcp_connected = native is not None and _transport_connected(native)
            if native is not None:
                _discard_native_connection(native)
            outcome = classify_connect_exception(
                request,
                exc,
                tcp_connected=tcp_connected,
                elapsed_seconds=elapsed,
            )
            raise SmbProtocolConnectError(outcome) from None

        return SmbProtocolConnectionHandle(
            native,
            negotiation,
            require_encryption=request.require_encryption,
            require_secure_negotiate=request.require_secure_negotiate,
        )


def negotiation_info_from_native(native: _NativeConnection) -> NegotiationInfo:
    """Normalize public ``smbprotocol.Connection`` negotiation state."""

    dialect_value = _required_integer(native.dialect, "dialect")
    try:
        dialect = _DIALECTS[dialect_value]
    except KeyError as exc:
        raise NegotiationMetadataError("The server selected an unsupported SMB dialect.") from exc

    max_read_size = _required_integer(native.max_read_size, "max_read_size")
    if max_read_size < 1:
        raise NegotiationMetadataError("The negotiated SMB read size was invalid.")

    security_mode = _required_integer(native.server_security_mode, "server_security_mode")
    signing_required = bool(
        security_mode & SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED
    )
    signing_supported = signing_required or bool(
        security_mode & SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED
    )
    signing_algorithm, signing_source = _signing_algorithm(
        native,
        dialect_value,
        supported=signing_supported,
    )
    signing = SecurityFeatureState(
        supported=signing_supported,
        required=signing_required,
        active=None,
        algorithm=signing_algorithm,
        algorithm_source=signing_source,
        requirement_source=RequirementSource.SERVER if signing_required else None,
    )

    encryption_supported = _encryption_supported(native, dialect_value)
    encryption_algorithm, encryption_source = _encryption_algorithm(
        native,
        dialect_value,
        supported=encryption_supported,
    )
    encryption = SecurityFeatureState(
        supported=encryption_supported,
        required=None,
        active=None,
        algorithm=encryption_algorithm,
        algorithm_source=encryption_source,
    )

    return NegotiationInfo(
        dialect=dialect,
        security=TransportSecurity(signing=signing, encryption=encryption),
        max_read_size=max_read_size,
    )


def classify_connect_exception(
    request: ConnectRequest,
    exception: BaseException,
    *,
    tcp_connected: bool,
    elapsed_seconds: float | None = None,
) -> TargetOutcome:
    """Convert native TCP/negotiate failures without copying exception text."""

    chain = tuple(_exception_chain(exception))
    os_error = next((item for item in chain if isinstance(item, OSError)), None)
    error_number = _os_error_number(os_error)

    if error_number == errno.ECONNREFUSED:
        stage = TargetStage.NETWORK
        status = TargetStatus.CONNECTION_REFUSED
        safe_message = "The target refused the TCP connection."
        raw_code = error_number
        retryable = False
    elif error_number in _UNREACHABLE_ERRNOS:
        stage = TargetStage.NETWORK
        status = TargetStatus.NETWORK_UNREACHABLE
        safe_message = "The local network stack reported that the target is unreachable."
        raw_code = error_number
        retryable = True
    elif not tcp_connected and (
        error_number == errno.ETIMEDOUT
        or any(isinstance(item, (TimeoutError, socket.timeout)) for item in chain)
    ):
        stage = TargetStage.NETWORK
        status = TargetStatus.TIMEOUT_NO_RESPONSE
        safe_message = "No TCP response was received before the configured timeout."
        raw_code = error_number or errno.ETIMEDOUT
        retryable = True
    else:
        stage = TargetStage.NEGOTIATION
        status = TargetStatus.NEGOTIATION_FAILED
        safe_message = _negotiation_safe_message(exception)
        negotiation_timed_out = any(
            isinstance(item, (TimeoutError, socket.timeout)) for item in chain
        )
        raw_code = (
            _native_status_code(chain)
            or error_number
            or (errno.ETIMEDOUT if negotiation_timed_out else errno.EPROTO)
        )
        retryable = _negotiation_retryable(chain, error_number)

    symbolic_name = errno.errorcode.get(raw_code)
    if symbolic_name is None and _native_status_code(chain) is not None:
        symbolic_name = "SMB_NEGOTIATION_ERROR"

    error = SmbErrorDetail(
        stage=stage,
        status=status,
        operation="connect" if stage is TargetStage.NETWORK else "negotiate",
        raw_code=raw_code,
        symbolic_name=symbolic_name,
        safe_message=safe_message,
        retryable=retryable,
        target=request.target,
    )
    return TargetOutcome(
        target=request.target,
        stage=stage,
        status=status,
        elapsed_seconds=elapsed_seconds,
        error=error,
    )


def make_smb1_only_outcome(
    request: ConnectRequest,
    *,
    raw_code: int = errno.EPROTONOSUPPORT,
    elapsed_seconds: float | None = None,
) -> TargetOutcome:
    """Normalize a positive result from a future, isolated SMB1-only probe."""

    error = SmbErrorDetail(
        stage=TargetStage.NEGOTIATION,
        status=TargetStatus.SMB1_ONLY_UNSUPPORTED,
        operation="negotiate_probe",
        raw_code=raw_code,
        symbolic_name=errno.errorcode.get(raw_code, "SMB1_ONLY"),
        safe_message="The target offers SMB1 only; file access was not attempted.",
        retryable=False,
        target=request.target,
    )
    return TargetOutcome(
        target=request.target,
        stage=TargetStage.NEGOTIATION,
        status=TargetStatus.SMB1_ONLY_UNSUPPORTED,
        elapsed_seconds=elapsed_seconds,
        error=error,
    )


def _signing_algorithm(
    native: _NativeConnection,
    dialect: int,
    *,
    supported: bool,
) -> tuple[str | None, AlgorithmSource | None]:
    if not supported:
        return None, None
    if dialect == 0x0311:
        algorithm_id = _required_integer(native.signing_algorithm_id, "signing_algorithm_id")
        try:
            return _SIGNING_ALGORITHMS[algorithm_id], AlgorithmSource.NEGOTIATED
        except KeyError as exc:
            raise NegotiationMetadataError(
                "The negotiated SMB signing algorithm was unsupported."
            ) from exc
    if dialect >= 0x0300:
        return "AES-128-CMAC", AlgorithmSource.DIALECT_INFERRED
    return "HMAC-SHA256", AlgorithmSource.DIALECT_INFERRED


def _encryption_supported(native: _NativeConnection, dialect: int) -> bool:
    if dialect < 0x0300:
        return False
    if native.supports_encryption is None:
        raise NegotiationMetadataError("SMB encryption capability metadata was missing.")
    if not isinstance(native.supports_encryption, bool):
        raise NegotiationMetadataError("SMB encryption capability metadata was invalid.")
    return native.supports_encryption


def _encryption_algorithm(
    native: _NativeConnection,
    dialect: int,
    *,
    supported: bool,
) -> tuple[str | None, AlgorithmSource | None]:
    if not supported:
        return None, None
    if dialect == 0x0311:
        algorithm_id = _required_integer(native.cipher_id, "cipher_id")
        try:
            return _ENCRYPTION_ALGORITHMS[algorithm_id], AlgorithmSource.NEGOTIATED
        except KeyError as exc:
            raise NegotiationMetadataError(
                "The negotiated SMB encryption algorithm was unsupported."
            ) from exc
    return "AES-128-CCM", AlgorithmSource.DIALECT_INFERRED


def _required_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise NegotiationMetadataError(f"Negotiated {name} metadata was missing or invalid.")
    return value


def _exception_chain(exception: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = exception
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _os_error_number(error: OSError | None) -> int | None:
    if error is None or isinstance(error.errno, bool) or not isinstance(error.errno, int):
        return None
    return error.errno


def _native_status_code(chain: tuple[BaseException, ...]) -> int | None:
    for exception in chain:
        value = getattr(exception, "status", None)
        if not isinstance(value, bool) and isinstance(value, int):
            return value
    return None


def _negotiation_retryable(
    chain: tuple[BaseException, ...],
    error_number: int | None,
) -> bool:
    return error_number == errno.ETIMEDOUT or any(
        isinstance(item, (TimeoutError, socket.timeout)) for item in chain
    )


def _negotiation_safe_message(exception: BaseException) -> str:
    if isinstance(exception, NegotiationMetadataError):
        return exception.safe_message
    return "TCP connected, but SMB negotiation did not complete."


def _transport_connected(native: _NativeConnection) -> bool:
    transport = getattr(native, "transport", None)
    return bool(getattr(transport, "connected", False))


def _discard_native_connection(native: _NativeConnection) -> None:
    try:
        native.disconnect(close=True)
    except Exception:
        # A failed connection is never handed to another component.  Cleanup
        # errors are secondary and must not replace or leak the original cause.
        return


def _elapsed(finished: float, started: float) -> float:
    elapsed = finished - started
    return elapsed if math.isfinite(elapsed) and elapsed >= 0 else 0.0
