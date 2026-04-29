"""Password, NT-hash, and RAM-backed ccache authentication.

Authentication attempts are explicit: Kerberos and NTLM are never hidden in a
single SPNEGO negotiation.  Auto mode closes the failed Kerberos connection and
requires a caller-supplied reconnect hook before one eligible NTLM fallback.
CCache bytes are exposed to GSSAPI only through a Linux ``memfd`` and its procfs
descriptor path; there is no disk or temporary-file fallback.
"""

from __future__ import annotations

import errno
import logging
import math
import os
import socket
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from threading import Lock
from typing import Protocol

import spnego
from smbprotocol.session import Session
from spnego.exceptions import (
    BadMechanismError,
    BadNameError,
    CredentialsExpiredError,
    InvalidCredentialError,
    OperationNotAvailableError,
)

from nordis_smb_inspector.core.credentials import (
    AuthMode,
    Credential,
    CredentialKind,
)

from .cancellation import CancellationToken, ScanCancelled
from .contracts import AuthenticationRequest, ConnectionHandle
from .models import (
    AuthAttempt,
    AuthAttemptOutcome,
    AuthenticationHistory,
    AuthMechanism,
    FallbackReason,
    SmbErrorDetail,
    TargetStage,
    TargetStatus,
)

_DEPENDENCY_LOGGERS = (
    "smbprotocol.connection",
    "smbprotocol.session",
    "smbprotocol.transport",
    "spnego._gss",
    "spnego._negotiate",
    "spnego._ntlm",
    "spnego._sspi",
)

_ACCOUNT_STATUS: dict[int, tuple[str, str]] = {
    0xC000006D: ("LOGON_FAILURE", "The account was not accepted."),
    0xC000006E: ("ACCOUNT_RESTRICTION", "The account is restricted from logging on."),
    0xC000006F: ("INVALID_LOGON_HOURS", "The account is outside its permitted logon hours."),
    0xC0000070: ("INVALID_WORKSTATION", "The account cannot log on from this system."),
    0xC0000071: ("PASSWORD_EXPIRED", "The account password has expired."),
    0xC0000072: ("ACCOUNT_DISABLED", "The account is disabled."),
    0xC0000193: ("ACCOUNT_EXPIRED", "The account has expired."),
    0xC0000224: ("PASSWORD_MUST_CHANGE", "The account password must be changed."),
    0xC0000234: ("ACCOUNT_LOCKED_OUT", "The account is locked."),
}

# MIT krb5 com_err values, represented as signed 32-bit values.  GSSAPI often
# exposes the same value as an unsigned ``min_code``; both forms are normalized.
_KRB_SPNS = frozenset({-1765328377, -1765328240, -1765328229})
_KRB_CLOCK = frozenset({-1765328347, -1765328236})
_KRB_REALM = frozenset({-1765328316, -1765328235, -1765328230})
_KRB_KDC = frozenset({-1765328355, -1765328299, -1765328298, -1765328228})

_SEC_E_TARGET_UNKNOWN = 0x80090303
_SEC_E_SECPKG_NOT_FOUND = 0x80090305
_SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311
_SEC_E_TIME_SKEW = 0x80090324
_STATUS_NO_LOGON_SERVERS = 0xC000005E
_MEMFD_FLAGS = getattr(os, "MFD_CLOEXEC", 0)
_CCACHE_MEMFD_NAME = "nordis-smb-ccache"

_NETWORK_ERRNOS = frozenset(
    code
    for code in (
        getattr(errno, "ENETUNREACH", None),
        getattr(errno, "EHOSTUNREACH", None),
        getattr(errno, "ETIMEDOUT", None),
        getattr(errno, "ECONNREFUSED", None),
    )
    if code is not None
)


class _NativeSession(Protocol):
    username: object
    password: object
    signing_required: bool | None
    encrypt_data: bool | None

    def connect(self) -> None: ...

    def disconnect(self, close: bool = True, timeout: float | None = None) -> None: ...


class _SessionFactory(Protocol):
    def __call__(
        self,
        connection: object,
        username: object = None,
        password: object = None,
        require_encryption: bool = True,
        hostname_override: str | None = None,
        auth_protocol: str = "negotiate",
    ) -> _NativeSession: ...


class _PasswordFactory(Protocol):
    def __call__(self, username: str, password: str) -> object: ...


class _NtHashFactory(Protocol):
    def __call__(
        self,
        username: str,
        lm_hash: str | None = None,
        nt_hash: str | None = None,
    ) -> object: ...


class _CcacheFactory(Protocol):
    def __call__(self, ccache: str, principal: str | None = None) -> object: ...


class _MemfdCreate(Protocol):
    def __call__(self, name: str, flags: int = 0) -> int: ...


class _FdWrite(Protocol):
    def __call__(self, fd: int, data: bytes | memoryview) -> int: ...


class _FdSeek(Protocol):
    def __call__(self, fd: int, offset: int, whence: int) -> int: ...


class _FdClose(Protocol):
    def __call__(self, fd: int) -> None: ...


class _ProcFdExists(Protocol):
    def __call__(self, path: str) -> bool: ...


class NtlmReconnect(Protocol):
    """Create a fresh negotiated connection after closing failed Kerberos."""

    def __call__(self, *, cancellation: CancellationToken) -> ConnectionHandle: ...


@dataclass(frozen=True, slots=True)
class AuthenticationFailure:
    """Normalized failure plus an optional, explicitly safe Auto transition."""

    detail: SmbErrorDetail
    fallback_reason: FallbackReason | None


class UnsupportedAuthenticationCredential(ValueError):
    """Safe fail-closed error for an unavailable credential backend."""

    def __init__(self) -> None:
        super().__init__("The selected credential backend is unavailable on this system.")


class _ProviderCredentialLease:
    """Own an optional descriptor until the native session consumes a credential."""

    __slots__ = ("_close_fd", "_fd", "credential")

    def __init__(
        self,
        credential: object,
        *,
        fd: int | None = None,
        close_fd: _FdClose | None = None,
    ) -> None:
        self.credential = credential
        self._fd = fd
        self._close_fd = close_fd

    def close(self) -> None:
        fd = self._fd
        close_fd = self._close_fd
        self._fd = None
        self._close_fd = None
        if fd is None or close_fd is None:
            return
        try:
            close_fd(fd)
        except Exception:
            raise UnsupportedAuthenticationCredential() from None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(credential=<redacted>, fd=<redacted>)"


class SmbProtocolAuthenticationError(PermissionError):
    """Safe authentication exception with attempt history and no native cause."""

    def __init__(
        self,
        *,
        history: AuthenticationHistory,
        detail: SmbErrorDetail,
        fallback_reason: FallbackReason | None = None,
    ) -> None:
        self.history = history
        self.detail = detail
        self.fallback_reason = fallback_reason
        super().__init__(detail.safe_message)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(history={self.history!r}, detail={self.detail!r}, "
            f"fallback_reason={self.fallback_reason!r})"
        )


class SmbProtocolSessionCloseError(ConnectionError):
    def __init__(self) -> None:
        super().__init__("The SMB session could not be closed cleanly.")


class SmbProtocolFallbackConnectionError(ConnectionError):
    """An Auto fallback could not obtain its required fresh connection."""

    def __init__(self, kerberos_history: AuthenticationHistory) -> None:
        self.kerberos_history = kerberos_history
        super().__init__("NTLM fallback could not establish a fresh SMB connection.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(kerberos_history={self.kerberos_history!r}, "
            "connection_error=<redacted>)"
        )


class SmbProtocolSessionHandle:
    """Authenticated session with a narrow lifecycle and redacted representation."""

    __slots__ = ("_authentication", "_closed", "_close_lock", "_connection", "_native")

    def __init__(
        self,
        native: _NativeSession,
        connection: ConnectionHandle,
        authentication: AuthenticationHistory,
    ) -> None:
        self._native = native
        self._connection = connection
        self._authentication = authentication
        self._closed = False
        self._close_lock = Lock()

    @property
    def authentication(self) -> AuthenticationHistory:
        return self._authentication

    @property
    def connection(self) -> ConnectionHandle:
        """Connection in use; it can differ after a successful Auto fallback."""

        return self._connection

    @property
    def signing_active(self) -> bool | None:
        value = getattr(self._native, "signing_required", None)
        return value if isinstance(value, bool) else None

    @property
    def encryption_active(self) -> bool | None:
        value = getattr(self._native, "encrypt_data", None)
        return value if isinstance(value, bool) else None

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def _native_session(self) -> _NativeSession:
        if self.closed:
            raise ValueError("The SMB session handle is closed.")
        return self._native

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            try:
                _disconnect_session(self._native)
            except Exception:
                raise SmbProtocolSessionCloseError() from None
            finally:
                self._closed = True

    def _replace_authentication(self, history: AuthenticationHistory) -> None:
        """Attach combined Auto history before this private handle is published."""

        self._authentication = history

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(authentication={self.authentication!r}, "
            f"signing_active={self.signing_active!r}, "
            f"encryption_active={self.encryption_active!r}, closed={self.closed!r}, "
            "connection=<redacted>, native=<redacted>)"
        )


def _create_memfd(name: str, flags: int = 0) -> int:
    create = getattr(os, "memfd_create", None)
    if create is None:
        raise UnsupportedAuthenticationCredential()
    try:
        return create(name, flags)
    except Exception:
        raise UnsupportedAuthenticationCredential() from None


class SmbProtocolAuthenticator:
    """Authenticate one explicit mechanism or an auditable password Auto flow."""

    __slots__ = (
        "_ccache_factory",
        "_clock",
        "_fd_close",
        "_fd_seek",
        "_fd_write",
        "_memfd_create",
        "_nt_hash_factory",
        "_password_factory",
        "_proc_fd_exists",
        "_session_factory",
    )

    def __init__(
        self,
        *,
        session_factory: _SessionFactory = Session,
        password_factory: _PasswordFactory = spnego.Password,
        nt_hash_factory: _NtHashFactory = spnego.NTLMHash,
        ccache_factory: _CcacheFactory = spnego.KerberosCCache,
        memfd_create: _MemfdCreate = _create_memfd,
        fd_write: _FdWrite = os.write,
        fd_seek: _FdSeek = os.lseek,
        fd_close: _FdClose = os.close,
        proc_fd_exists: _ProcFdExists = os.path.exists,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        suppress_sensitive_dependency_logging()
        self._session_factory = session_factory
        self._password_factory = password_factory
        self._nt_hash_factory = nt_hash_factory
        self._ccache_factory = ccache_factory
        self._memfd_create = memfd_create
        self._fd_write = fd_write
        self._fd_seek = fd_seek
        self._fd_close = fd_close
        self._proc_fd_exists = proc_fd_exists
        self._clock = clock

    def authenticate(
        self,
        connection: ConnectionHandle,
        request: AuthenticationRequest,
        *,
        cancellation: CancellationToken,
    ) -> SmbProtocolSessionHandle:
        """Perform exactly the mechanism in ``request``; never silently fall back."""

        return self._authenticate_one(connection, request, cancellation=cancellation)

    def authenticate_credential(
        self,
        connection: ConnectionHandle,
        credential: Credential,
        *,
        kerberos_hostname: str | None,
        cancellation: CancellationToken,
        reconnect_for_ntlm: NtlmReconnect | None = None,
    ) -> SmbProtocolSessionHandle:
        """Route explicit auth modes and implement visible password Auto mode."""

        if not isinstance(credential, Credential):
            raise TypeError("credential must be a Credential instance.")
        if credential.auth_mode is AuthMode.AUTO:
            if reconnect_for_ntlm is None:
                raise ValueError("Auto authentication requires a fresh NTLM reconnect hook.")
            return self.authenticate_auto(
                connection,
                credential,
                kerberos_hostname=kerberos_hostname,
                reconnect_for_ntlm=reconnect_for_ntlm,
                cancellation=cancellation,
            )

        if credential.auth_mode is AuthMode.KERBEROS_ONLY:
            if not kerberos_hostname or not kerberos_hostname.strip():
                raise _hostname_failure_exception()
            request = AuthenticationRequest(
                credential=credential,
                mechanism=AuthMechanism.KERBEROS,
                spn_hostname=kerberos_hostname,
            )
        else:
            request = AuthenticationRequest(
                credential=credential,
                mechanism=AuthMechanism.NTLM,
            )
        return self.authenticate(connection, request, cancellation=cancellation)

    def authenticate_auto(
        self,
        connection: ConnectionHandle,
        credential: Credential,
        *,
        kerberos_hostname: str | None,
        reconnect_for_ntlm: NtlmReconnect,
        cancellation: CancellationToken,
    ) -> SmbProtocolSessionHandle:
        """Kerberos first, then at most one eligible NTLM attempt on a new connection."""

        if (
            credential.kind is not CredentialKind.PASSWORD
            or credential.auth_mode is not AuthMode.AUTO
        ):
            raise ValueError("Auto authentication requires an Auto-mode password credential.")

        kerberos_failure: SmbProtocolAuthenticationError
        if kerberos_hostname and kerberos_hostname.strip():
            request = AuthenticationRequest(
                credential=credential,
                mechanism=AuthMechanism.KERBEROS,
                spn_hostname=kerberos_hostname,
            )
            try:
                return self.authenticate(connection, request, cancellation=cancellation)
            except SmbProtocolAuthenticationError as caught:
                if caught.fallback_reason is None:
                    raise
                kerberos_failure = caught
        else:
            kerberos_failure = _hostname_failure_exception(
                fallback_reason=FallbackReason.KERBEROS_HOSTNAME_UNRESOLVED
            )

        cancellation.raise_if_cancelled()
        try:
            connection.close()
            replacement = reconnect_for_ntlm(cancellation=cancellation)
            if replacement is connection or replacement.closed:
                raise ValueError("The reconnect hook did not return a fresh open connection.")
        except ScanCancelled:
            raise
        except Exception:
            raise SmbProtocolFallbackConnectionError(kerberos_failure.history) from None

        cancellation.raise_if_cancelled()
        ntlm_request = AuthenticationRequest(
            credential=credential,
            mechanism=AuthMechanism.NTLM,
        )
        try:
            ntlm_handle = self.authenticate(
                replacement,
                ntlm_request,
                cancellation=cancellation,
            )
        except ScanCancelled:
            _close_connection_safely(replacement)
            raise
        except SmbProtocolAuthenticationError as ntlm_error:
            _close_connection_safely(replacement)
            history = AuthenticationHistory(
                attempts=kerberos_failure.history.attempts + ntlm_error.history.attempts,
                selected_mechanism=None,
                fallback_reason=kerberos_failure.fallback_reason,
            )
            raise SmbProtocolAuthenticationError(
                history=history,
                detail=ntlm_error.detail,
            ) from None

        history = AuthenticationHistory(
            attempts=kerberos_failure.history.attempts + ntlm_handle.authentication.attempts,
            selected_mechanism=AuthMechanism.NTLM,
            fallback_reason=kerberos_failure.fallback_reason,
        )
        ntlm_handle._replace_authentication(history)
        return ntlm_handle

    def _authenticate_one(
        self,
        connection: ConnectionHandle,
        request: AuthenticationRequest,
        *,
        cancellation: CancellationToken,
    ) -> SmbProtocolSessionHandle:
        cancellation.raise_if_cancelled()
        started = self._clock()
        native_session: _NativeSession | None = None
        provider_lease: _ProviderCredentialLease | None = None
        try:
            native_connection = connection._native_connection
            provider_lease = self._provider_credential(request)
            try:
                native_session = self._session_factory(
                    native_connection,
                    username=None,
                    password=None,
                    require_encryption=bool(getattr(connection, "require_encryption", False)),
                    hostname_override=(
                        request.spn_hostname
                        if request.mechanism is AuthMechanism.KERBEROS
                        else None
                    ),
                    auth_protocol=request.mechanism.value,
                )
                # Passing None to Session.__init__ prevents smbprotocol's INFO log
                # from formatting the account identity.  Session.connect consumes
                # the pyspnego credential assigned immediately afterwards.
                native_session.username = provider_lease.credential
                native_session.password = None
                native_session.connect()
                cancellation.raise_if_cancelled()
                if request.credential.kind is CredentialKind.CCACHE:
                    # The GSSAPI context has consumed the provider by this
                    # point.  Do not retain its procfs path or principal on the
                    # long-lived SMB session handle.
                    native_session.username = None
            finally:
                lease = provider_lease
                provider_lease = None
                lease.close()
        except UnsupportedAuthenticationCredential:
            if native_session is not None:
                _discard_session(native_session)
            raise
        except ScanCancelled:
            if native_session is not None:
                _discard_session(native_session)
            raise
        except Exception as exception:
            if native_session is not None:
                _discard_session(native_session)
            failure = classify_authentication_exception(request.mechanism, exception)
            attempt = AuthAttempt(
                mechanism=request.mechanism,
                outcome=AuthAttemptOutcome.FAILED,
                elapsed_seconds=_elapsed(self._clock(), started),
                error=failure.detail,
            )
            history = AuthenticationHistory(
                attempts=(attempt,),
                selected_mechanism=None,
            )
            raise SmbProtocolAuthenticationError(
                history=history,
                detail=failure.detail,
                fallback_reason=failure.fallback_reason,
            ) from None
        attempt = AuthAttempt(
            mechanism=request.mechanism,
            outcome=AuthAttemptOutcome.SUCCEEDED,
            elapsed_seconds=_elapsed(self._clock(), started),
        )
        history = AuthenticationHistory(
            attempts=(attempt,),
            selected_mechanism=request.mechanism,
        )
        return SmbProtocolSessionHandle(native_session, connection, history)

    def _provider_credential(
        self,
        request: AuthenticationRequest,
    ) -> _ProviderCredentialLease:
        credential = request.credential
        if credential.kind is CredentialKind.PASSWORD:
            if credential.password is None:
                raise ValueError("Password credential data was missing.")
            return _ProviderCredentialLease(
                self._password_factory(
                    _credential_identity(credential, request.mechanism),
                    credential.password,
                )
            )
        if credential.kind is CredentialKind.NT_HASH:
            if credential.nt_hash is None:
                raise ValueError("NT hash credential data was missing.")
            return _ProviderCredentialLease(
                self._nt_hash_factory(
                    _credential_identity(credential, request.mechanism),
                    nt_hash=credential.nt_hash,
                )
            )
        if credential.kind is CredentialKind.CCACHE:
            return self._ccache_provider_credential(credential)
        raise UnsupportedAuthenticationCredential()

    def _ccache_provider_credential(
        self,
        credential: Credential,
    ) -> _ProviderCredentialLease:
        data = credential.ccache_data
        if data is None:
            raise UnsupportedAuthenticationCredential()

        fd: int | None = None
        try:
            fd = self._memfd_create(_CCACHE_MEMFD_NAME, _MEMFD_FLAGS)
            if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
                raise UnsupportedAuthenticationCredential()
            _write_all(fd, data, self._fd_write)
            self._fd_seek(fd, 0, os.SEEK_SET)
            path = f"/proc/self/fd/{fd}"
            if not self._proc_fd_exists(path):
                raise UnsupportedAuthenticationCredential()
            provider = self._ccache_factory(
                f"FILE:{path}",
                principal=_ccache_principal(credential),
            )
        except Exception:
            if fd is not None:
                _close_fd_safely(fd, self._fd_close)
            raise UnsupportedAuthenticationCredential() from None
        return _ProviderCredentialLease(
            provider,
            fd=fd,
            close_fd=self._fd_close,
        )


def suppress_sensitive_dependency_logging() -> None:
    """Disable dependency loggers that can emit targets, identities, or auth tokens."""

    for logger_name in _DEPENDENCY_LOGGERS:
        logging.getLogger(logger_name).disabled = True


def classify_authentication_exception(
    mechanism: AuthMechanism,
    exception: BaseException,
) -> AuthenticationFailure:
    """Classify structured error types/codes without inspecting exception text."""

    chain = tuple(_exception_chain(exception))
    raw_code = _native_auth_code(chain)
    signed_minor_codes = frozenset(
        _signed_32(value)
        for item in chain
        if (value := getattr(item, "min_code", None)) is not None
        and not isinstance(value, bool)
        and isinstance(value, int)
    )
    os_error = next((item for item in chain if isinstance(item, OSError)), None)
    os_error_number = (
        os_error.errno
        if os_error is not None
        and not isinstance(os_error.errno, bool)
        and isinstance(os_error.errno, int)
        else None
    )

    fallback_reason: FallbackReason | None = None
    symbolic_name = "AUTH_FAILED"
    safe_message = "SMB authentication failed."
    retryable = False

    if any(isinstance(item, BadNameError) for item in chain) or signed_minor_codes & _KRB_SPNS:
        symbolic_name = "KERBEROS_SPN_NOT_FOUND"
        safe_message = "The Kerberos service principal could not be resolved."
        fallback_reason = FallbackReason.SPN_NOT_FOUND
    elif signed_minor_codes & _KRB_CLOCK or raw_code == _SEC_E_TIME_SKEW:
        symbolic_name = "KERBEROS_CLOCK_SKEW"
        safe_message = "Kerberos rejected the request because the clocks differ too much."
        fallback_reason = FallbackReason.CLOCK_SKEW
    elif signed_minor_codes & _KRB_REALM:
        symbolic_name = "KERBEROS_REALM_MISMATCH"
        safe_message = "The Kerberos realm did not match the requested account or service."
        fallback_reason = FallbackReason.REALM_MISMATCH
    elif (
        signed_minor_codes & _KRB_KDC
        or raw_code in {_SEC_E_NO_AUTHENTICATING_AUTHORITY, _STATUS_NO_LOGON_SERVERS}
        or os_error_number in _NETWORK_ERRNOS
        or any(isinstance(item, (TimeoutError, socket.timeout)) for item in chain)
    ):
        symbolic_name = "KERBEROS_KDC_UNREACHABLE"
        safe_message = "A Kerberos domain controller could not be reached."
        fallback_reason = FallbackReason.KDC_UNREACHABLE
        retryable = True
    elif any(
        isinstance(item, (BadMechanismError, OperationNotAvailableError)) for item in chain
    ) or raw_code == _SEC_E_SECPKG_NOT_FOUND:
        symbolic_name = "KERBEROS_MECHANISM_UNAVAILABLE"
        safe_message = "Kerberos is unavailable in the local authentication stack."
        fallback_reason = FallbackReason.UNSUPPORTED_MECHANISM
    elif raw_code in _ACCOUNT_STATUS:
        symbolic_name, safe_message = _ACCOUNT_STATUS[raw_code]
    elif any(isinstance(item, CredentialsExpiredError) for item in chain):
        symbolic_name = "CREDENTIAL_EXPIRED"
        safe_message = "The supplied credential has expired."
    elif any(isinstance(item, InvalidCredentialError) for item in chain):
        symbolic_name = "LOGON_FAILURE"
        safe_message = "The supplied credential was not accepted."

    if mechanism is not AuthMechanism.KERBEROS:
        fallback_reason = None
        if symbolic_name.startswith("KERBEROS_"):
            symbolic_name = "AUTH_INFRASTRUCTURE_ERROR"
            safe_message = "The authentication service could not complete the request."

    effective_code = raw_code or os_error_number or errno.EACCES
    detail = SmbErrorDetail(
        stage=TargetStage.AUTHENTICATION,
        status=TargetStatus.AUTH_FAILED,
        operation=f"authenticate_{mechanism.value}",
        raw_code=effective_code,
        symbolic_name=symbolic_name,
        safe_message=safe_message,
        retryable=retryable,
    )
    return AuthenticationFailure(detail=detail, fallback_reason=fallback_reason)


def _hostname_failure_exception(
    *,
    fallback_reason: FallbackReason | None = None,
) -> SmbProtocolAuthenticationError:
    detail = SmbErrorDetail(
        stage=TargetStage.AUTHENTICATION,
        status=TargetStatus.AUTH_FAILED,
        operation="authenticate_kerberos",
        raw_code=errno.EDESTADDRREQ,
        symbolic_name="KERBEROS_HOSTNAME_UNRESOLVED",
        safe_message="A verified hostname is required to construct the Kerberos CIFS SPN.",
        retryable=False,
    )
    attempt = AuthAttempt(
        mechanism=AuthMechanism.KERBEROS,
        outcome=AuthAttemptOutcome.FAILED,
        error=detail,
    )
    return SmbProtocolAuthenticationError(
        history=AuthenticationHistory(attempts=(attempt,), selected_mechanism=None),
        detail=detail,
        fallback_reason=fallback_reason,
    )


def _credential_identity(
    credential: Credential,
    mechanism: AuthMechanism,
) -> str:
    if not credential.username:
        raise ValueError("A username is required for this authentication adapter.")
    if mechanism is AuthMechanism.KERBEROS:
        principal = _kerberos_principal(credential)
        if principal is None:  # pragma: no cover - guarded by the username check above
            raise ValueError("A username is required for this authentication adapter.")
        return principal
    return _ntlm_identity(credential)


def _ntlm_identity(credential: Credential) -> str:
    username = credential.username
    if not username:  # pragma: no cover - guarded by _credential_identity
        raise ValueError("A username is required for this authentication adapter.")
    if "@" in username:
        _validate_upn(username)
        return username
    if "\\" in username:
        _split_downlevel_identity(username)
        return username
    if credential.domain:
        return f"{credential.domain}\\{username}"
    return username


def _ccache_principal(credential: Credential) -> str | None:
    """Return an optional UPN-shaped selector for ``KerberosCCache``."""

    return _kerberos_principal(credential)


def _kerberos_principal(credential: Credential) -> str | None:
    username = credential.username
    if not username:
        return None
    if "@" in username:
        _validate_upn(username)
        return username

    account = username
    downlevel_realm: str | None = None
    if "\\" in username:
        downlevel_realm, account = _split_downlevel_identity(username)

    realm = credential.domain or downlevel_realm
    if realm:
        return f"{account}@{_normalize_realm(realm)}"
    return account


def _validate_upn(username: str) -> None:
    if username.count("@") != 1:
        raise ValueError("A UPN must contain one account and one realm.")
    account, realm = username.split("@", 1)
    if not account or not realm or "\\" in account or "\\" in realm:
        raise ValueError("A UPN must contain one account and one realm.")


def _split_downlevel_identity(username: str) -> tuple[str, str]:
    if username.count("\\") != 1:
        raise ValueError("A down-level identity must contain one domain and one account.")
    realm, account = username.split("\\", 1)
    if not realm or not account or "@" in realm or "@" in account:
        raise ValueError("A down-level identity must contain one domain and one account.")
    return realm, account


def _normalize_realm(realm: str) -> str:
    candidate = realm.rstrip(".")
    if not candidate or "@" in candidate or "\\" in candidate:
        raise ValueError("A Kerberos realm cannot contain identity separators.")
    return candidate.upper()


def _write_all(fd: int, data: bytes, write: _FdWrite) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = write(fd, view[offset:])
        except InterruptedError:
            continue
        except Exception:
            raise UnsupportedAuthenticationCredential() from None
        if (
            isinstance(written, bool)
            or not isinstance(written, int)
            or written <= 0
            or written > len(view) - offset
        ):
            raise UnsupportedAuthenticationCredential()
        offset += written


def _close_fd_safely(fd: int, close: _FdClose) -> None:
    try:
        close(fd)
    except Exception:
        return


def _exception_chain(exception: BaseException) -> Iterator[BaseException]:
    pending: list[BaseException] = [exception]
    seen: set[int] = set()
    while pending:
        current = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        for related in (
            current.__cause__,
            current.__context__,
            getattr(current, "base_error", None),
        ):
            if isinstance(related, BaseException) and id(related) not in seen:
                pending.append(related)


def _native_auth_code(chain: tuple[BaseException, ...]) -> int | None:
    for exception in chain:
        for attribute in ("status", "nt_status"):
            value = getattr(exception, attribute, None)
            if not isinstance(value, bool) and isinstance(value, int):
                normalized = value & 0xFFFFFFFF
                if normalized != 0xFFFFFFFF:
                    return normalized
    for exception in chain:
        value = getattr(exception, "min_code", None)
        if not isinstance(value, bool) and isinstance(value, int):
            return value & 0xFFFFFFFF
    return None


def _signed_32(value: int) -> int:
    normalized = value & 0xFFFFFFFF
    return normalized - 0x1_0000_0000 if normalized >= 0x8000_0000 else normalized


def _discard_session(native: _NativeSession) -> None:
    try:
        _disconnect_session(native)
    except Exception:
        return


def _disconnect_session(native: _NativeSession) -> None:
    # smbprotocol logs ``Session.username`` during logoff.  Clear the provider
    # credential first so neither identity nor its secret-bearing object is
    # formatted by dependency logging.
    native.username = None
    native.password = None
    native.disconnect(close=True)


def _close_connection_safely(connection: ConnectionHandle) -> None:
    try:
        connection.close()
    except Exception:
        return


def _elapsed(finished: float, started: float) -> float:
    elapsed = finished - started
    return elapsed if math.isfinite(elapsed) and elapsed >= 0 else 0.0
