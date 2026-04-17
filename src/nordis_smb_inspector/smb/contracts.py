"""Read-only SMB adapter ports and validated remote range reads.

The protocols contain discovery and read operations only.  They expose no
create, write, rename, delete, permission-change, or download/materialization
method.  Concrete network adapters are deliberately implemented elsewhere.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from nordis_smb_inspector.core.credentials import AuthMode, Credential, CredentialKind

from .cancellation import CancellationToken
from .models import (
    AuthenticationHistory,
    AuthMechanism,
    InventoryEntry,
    NegotiationInfo,
    ShareEnumerationResult,
    ShareInfo,
)


@dataclass(frozen=True, slots=True, repr=False)
class ConnectRequest:
    """TCP/SMB negotiation settings for exactly one expanded target."""

    target: str = field(repr=False)
    port: int = 445
    timeout_seconds: float = 5.0
    require_signing: bool = True
    require_encryption: bool = False
    require_secure_negotiate: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be non-empty text.")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("port must be an integer.")
        if not 1 <= self.port <= 65_535:
            raise ValueError("port must be between 1 and 65535.")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite, positive number.")
        for field_name in (
            "require_signing",
            "require_encryption",
            "require_secure_negotiate",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be a boolean.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target=<redacted>, port={self.port!r}, "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"require_signing={self.require_signing!r}, "
            f"require_encryption={self.require_encryption!r}, "
            f"require_secure_negotiate={self.require_secure_negotiate!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticationRequest:
    """One explicit mechanism attempt; Auto fallback creates two requests."""

    credential: Credential = field(repr=False)
    mechanism: AuthMechanism
    spn_hostname: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.credential, Credential):
            raise TypeError("credential must be a Credential instance.")
        if self.mechanism is AuthMechanism.KERBEROS:
            if not isinstance(self.spn_hostname, str) or not self.spn_hostname.strip():
                raise ValueError("Kerberos authentication requires a verified SPN hostname.")
            if self.credential.kind is CredentialKind.NT_HASH:
                raise ValueError("NT hash credentials cannot be used for Kerberos.")
        elif self.credential.kind is CredentialKind.CCACHE:
            raise ValueError("CCache credentials cannot be used for NTLM.")
        if (
            self.credential.auth_mode is AuthMode.KERBEROS_ONLY
            and self.mechanism is not AuthMechanism.KERBEROS
        ):
            raise ValueError("A Kerberos-only credential cannot request NTLM.")
        if (
            self.credential.auth_mode is AuthMode.NTLM_ONLY
            and self.mechanism is not AuthMechanism.NTLM
        ):
            raise ValueError("An NTLM-only credential cannot request Kerberos.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(credential=<redacted>, "
            f"mechanism={self.mechanism.value!r}, spn_hostname=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class TreeWalkRequest:
    """A bounded tree walk rooted inside one connected disk share."""

    share: ShareInfo
    start_path: str = field(default="", repr=False)
    max_depth: int = 1
    follow_reparse_points: bool = False

    def __post_init__(self) -> None:
        if not self.share.content_walkable:
            raise ValueError("Only connected disk shares can be walked.")
        if not isinstance(self.start_path, str):
            raise TypeError("start_path must be text.")
        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int):
            raise TypeError("max_depth must be an integer.")
        if self.max_depth < 0:
            raise ValueError("max_depth cannot be negative.")
        if not isinstance(self.follow_reparse_points, bool):
            raise TypeError("follow_reparse_points must be a boolean.")


@dataclass(frozen=True, slots=True, repr=False)
class OpenFileRequest:
    """Request a read-only handle for a previously inventoried remote file."""

    target: str = field(repr=False)
    share_name: str = field(repr=False)
    relative_path: str = field(repr=False)
    expected_size: int | None = None

    def __post_init__(self) -> None:
        for name in ("target", "share_name", "relative_path"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty text.")
        if self.expected_size is not None and (
            isinstance(self.expected_size, bool)
            or not isinstance(self.expected_size, int)
            or self.expected_size < 0
        ):
            raise ValueError("expected_size must be a non-negative integer when supplied.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(target=<redacted>, share_name=<redacted>, "
            f"relative_path=<redacted>, expected_size={self.expected_size!r})"
        )


@runtime_checkable
class ConnectionHandle(Protocol):
    """Opaque negotiated connection owned by one adapter."""

    @property
    def negotiation(self) -> NegotiationInfo: ...

    @property
    def closed(self) -> bool: ...

    def close(self) -> None: ...


@runtime_checkable
class SessionHandle(Protocol):
    """Opaque authenticated session; identity is intentionally not exposed."""

    @property
    def authentication(self) -> AuthenticationHistory: ...

    @property
    def closed(self) -> bool: ...

    def close(self) -> None: ...


@runtime_checkable
class ReadOnlyConnector(Protocol):
    def connect(
        self,
        request: ConnectRequest,
        *,
        cancellation: CancellationToken,
    ) -> ConnectionHandle: ...


@runtime_checkable
class ReadOnlyAuthenticator(Protocol):
    def authenticate(
        self,
        connection: ConnectionHandle,
        request: AuthenticationRequest,
        *,
        cancellation: CancellationToken,
    ) -> SessionHandle: ...


@runtime_checkable
class ReadOnlyShareEnumerator(Protocol):
    def enumerate_shares(
        self,
        session: SessionHandle,
        *,
        cancellation: CancellationToken,
    ) -> ShareEnumerationResult: ...


@runtime_checkable
class ReadOnlyTreeWalker(Protocol):
    def walk_tree(
        self,
        session: SessionHandle,
        request: TreeWalkRequest,
        *,
        cancellation: CancellationToken,
    ) -> Iterator[InventoryEntry]: ...


@runtime_checkable
class ReadOnlyFileOpener(Protocol):
    def open_reader(
        self,
        session: SessionHandle,
        request: OpenFileRequest,
        *,
        cancellation: CancellationToken,
    ) -> ValidatedRangeReader: ...


class ValidatedRangeReader(ABC):
    """Validated byte-range access to one remote file.

    Only the requested range is returned to the caller.  This interface has no
    local path, temporary-file, whole-file download, or write operation; a
    concrete adapter implements each range as a remote SMB read.
    """

    __slots__ = ("_closed", "_max_read_size", "_size")

    def __init__(self, *, size: int, max_read_size: int) -> None:
        if isinstance(size, bool) or not isinstance(size, int):
            raise TypeError("size must be an integer.")
        if size < 0:
            raise ValueError("size cannot be negative.")
        if isinstance(max_read_size, bool) or not isinstance(max_read_size, int):
            raise TypeError("max_read_size must be an integer.")
        if max_read_size < 1:
            raise ValueError("max_read_size must be at least one byte.")
        self._size = size
        self._max_read_size = max_read_size
        self._closed = False

    @property
    def size(self) -> int:
        return self._size

    @property
    def max_read_size(self) -> int:
        return self._max_read_size

    @property
    def closed(self) -> bool:
        return self._closed

    def read_range(
        self,
        offset: int,
        length: int,
        *,
        cancellation: CancellationToken,
    ) -> bytes:
        """Read at most ``length`` bytes beginning at zero-based ``offset``."""

        if self.closed:
            raise ValueError("Cannot read from a closed range reader.")
        _validate_range_number(offset, "offset")
        _validate_range_number(length, "length")
        if offset > self.size:
            raise ValueError("offset cannot be beyond the remote file size.")
        if length > self.max_read_size:
            raise ValueError("length exceeds the negotiated maximum range size.")
        cancellation.raise_if_cancelled()
        if length == 0 or offset == self.size:
            return b""

        requested = min(length, self.size - offset)
        raw = self._read_remote_range(offset, requested, cancellation=cancellation)
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise TypeError("The range adapter must return a bytes-like object.")
        result = bytes(raw)
        if len(result) > requested:
            raise RuntimeError("The range adapter returned more bytes than requested.")
        cancellation.raise_if_cancelled()
        return result

    def iter_chunks(
        self,
        *,
        chunk_size: int,
        cancellation: CancellationToken,
        start_offset: int = 0,
    ) -> Iterator[bytes]:
        """Stream forward without retaining or materializing the remote file."""

        _validate_range_number(start_offset, "start_offset")
        _validate_range_number(chunk_size, "chunk_size")
        if chunk_size == 0:
            raise ValueError("chunk_size must be at least one byte.")
        if chunk_size > self.max_read_size:
            raise ValueError("chunk_size exceeds the negotiated maximum range size.")
        if start_offset > self.size:
            raise ValueError("start_offset cannot be beyond the remote file size.")

        offset = start_offset
        while offset < self.size:
            chunk = self.read_range(offset, chunk_size, cancellation=cancellation)
            if not chunk:
                break
            yield chunk
            offset += len(chunk)

    @abstractmethod
    def _read_remote_range(
        self,
        offset: int,
        length: int,
        *,
        cancellation: CancellationToken,
    ) -> bytes | bytearray | memoryview:
        """Perform exactly one remote read; implemented by a network adapter."""

    def close(self) -> None:
        if not self._closed:
            try:
                self._close_remote()
            finally:
                self._closed = True

    def _close_remote(self) -> None:
        """Release the remote handle; adapters may override."""

        return None

    def __enter__(self) -> ValidatedRangeReader:
        if self.closed:
            raise ValueError("Cannot enter a closed range reader.")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _validate_range_number(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer.")
    if value < 0:
        raise ValueError(f"{name} cannot be negative.")
