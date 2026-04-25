"""Read-only SRVSVC share discovery through a short-lived Impacket session."""

from __future__ import annotations

import errno
import logging
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Protocol

from nordis_smb_inspector.core.credentials import Credential, CredentialKind

from .cancellation import CancellationToken, ScanCancelled
from .models import AuthMechanism, SmbErrorDetail, TargetStage, TargetStatus

_STATUS_ACCESS_DENIED = 0xC0000022
_STATUS_LOGON_FAILURE = 0xC000006D
_STATUS_ACCOUNT_RESTRICTION = 0xC000006E
_STATUS_WRONG_PASSWORD = 0xC000006A
_DENIED_CODES = frozenset(
    {
        _STATUS_ACCESS_DENIED,
        _STATUS_LOGON_FAILURE,
        _STATUS_ACCOUNT_RESTRICTION,
        _STATUS_WRONG_PASSWORD,
    }
)


class _ImpacketConnection(Protocol):
    def login(
        self,
        user: str,
        password: str,
        domain: str = "",
        lmhash: str = "",
        nthash: str = "",
        ntlmFallback: bool = True,
    ) -> object: ...

    def kerberosLogin(
        self,
        user: str,
        password: str,
        domain: str = "",
        lmhash: str = "",
        nthash: str = "",
        aesKey: str = "",
        kdcHost: str | None = None,
        TGT: object | None = None,
        TGS: object | None = None,
        useCache: bool = True,
    ) -> object: ...

    def listShares(self) -> Iterable[object]: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class ShareDiscoveryResult:
    names: tuple[str, ...] = field(repr=False)
    mechanism: AuthMechanism

    def __post_init__(self) -> None:
        if not isinstance(self.names, tuple) or not all(
            isinstance(name, str) and name for name in self.names
        ):
            raise ValueError("Discovered share names must be non-empty text.")
        if not isinstance(self.mechanism, AuthMechanism):
            raise TypeError("Discovery mechanism must be an AuthMechanism value.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(names=<redacted {len(self.names)} entries>, "
            f"mechanism={self.mechanism.value!r})"
        )


class ImpacketShareDiscoveryError(RuntimeError):
    __slots__ = ("detail",)

    def __init__(self, detail: SmbErrorDetail) -> None:
        super().__init__(detail.safe_message)
        self.detail = detail

    def __repr__(self) -> str:
        return f"{type(self).__name__}(detail={self.detail!r})"


class ImpacketShareDiscoverer:
    """Enumerate SRVSVC share names and immediately close the second session."""

    def __init__(
        self,
        *,
        connection_factory: Callable[..., _ImpacketConnection] | None = None,
        ccache_factory: Callable[[bytes], object] | None = None,
    ) -> None:
        logging.getLogger("impacket").disabled = True
        self._connection_factory = connection_factory or _default_connection_factory
        self._ccache_factory = ccache_factory or _default_ccache_factory

    def discover(
        self,
        *,
        target: str,
        credential: Credential,
        kerberos_hostname: str | None,
        mechanism: AuthMechanism,
        timeout_seconds: float,
        cancellation: CancellationToken,
    ) -> ShareDiscoveryResult:
        _validate_request(target, credential, kerberos_hostname, mechanism, timeout_seconds)
        cancellation.raise_if_cancelled()
        remote_name = kerberos_hostname if mechanism is AuthMechanism.KERBEROS else target
        connection: _ImpacketConnection | None = None
        try:
            connection = self._connection_factory(
                remoteName=remote_name,
                remoteHost=target,
                sess_port=445,
                timeout=timeout_seconds,
            )
            cancellation.raise_if_cancelled()
            if mechanism is AuthMechanism.KERBEROS:
                self._authenticate_kerberos(
                    connection,
                    credential,
                    kerberos_hostname=kerberos_hostname,
                )
            else:
                self._authenticate_ntlm(connection, credential)
            cancellation.raise_if_cancelled()
            names = _share_names(connection.listShares())
            cancellation.raise_if_cancelled()
            return ShareDiscoveryResult(names=names, mechanism=mechanism)
        except ScanCancelled:
            raise
        except ImpacketShareDiscoveryError:
            raise
        except Exception as exception:
            raise ImpacketShareDiscoveryError(
                _discovery_error(exception, target=target)
            ) from None
        finally:
            if connection is not None:
                _close_connection(connection)

    def _authenticate_ntlm(
        self,
        connection: _ImpacketConnection,
        credential: Credential,
    ) -> None:
        if credential.kind is CredentialKind.CCACHE:
            raise ImpacketShareDiscoveryError(_unsupported_credential())
        username, domain = _identity_parts(credential)
        if credential.kind is CredentialKind.NT_HASH:
            connection.login(
                username,
                "",
                domain,
                "",
                credential.nt_hash or "",
                False,
            )
            return
        connection.login(username, credential.password or "", domain, "", "", False)

    def _authenticate_kerberos(
        self,
        connection: _ImpacketConnection,
        credential: Credential,
        *,
        kerberos_hostname: str | None,
    ) -> None:
        if kerberos_hostname is None:
            raise ImpacketShareDiscoveryError(_missing_spn_hostname())
        username, domain = _identity_parts(credential)
        if credential.kind is CredentialKind.PASSWORD:
            connection.kerberosLogin(
                username,
                credential.password or "",
                domain,
                useCache=False,
            )
            return
        if credential.kind is CredentialKind.CCACHE:
            cache = self._ccache_factory(credential.ccache_data or b"")
            domain, username, tgt, tgs = _ccache_material(
                cache,
                domain=domain,
                username=username,
                hostname=kerberos_hostname,
            )
            connection.kerberosLogin(
                username,
                "",
                domain,
                TGT=tgt,
                TGS=tgs,
                useCache=False,
            )
            return
        raise ImpacketShareDiscoveryError(_unsupported_credential())


def _default_connection_factory(**kwargs: object) -> _ImpacketConnection:
    from impacket.smbconnection import SMBConnection

    return SMBConnection(**kwargs)


def _default_ccache_factory(data: bytes) -> object:
    from impacket.krb5.ccache import CCache

    return CCache(data)


def _identity_parts(credential: Credential) -> tuple[str, str]:
    username = credential.username or ""
    domain = credential.domain or ""
    if "@" in username:
        user_part, realm = username.rsplit("@", 1)
        if user_part and realm:
            username = user_part
            if not domain:
                domain = realm
    elif "\\" in username:
        domain_part, user_part = username.split("\\", 1)
        if domain_part and user_part:
            username = user_part
            if not domain:
                domain = domain_part
    return username, domain


def _ccache_material(
    cache: object,
    *,
    domain: str,
    username: str,
    hostname: str,
) -> tuple[str, str, object | None, object | None]:
    principal = getattr(cache, "principal", None)
    if principal is None:
        raise ImpacketShareDiscoveryError(_invalid_ccache())
    try:
        if not domain:
            domain = principal.realm["data"].decode("utf-8")
        if not username and principal.components:
            username = principal.components[0]["data"].decode("utf-8")
        service_principal = f"cifs/{hostname}@{domain}".upper()
        credential = cache.getCredential(service_principal)
        tgt = None
        tgs = None
        if credential is not None:
            tgs = credential.toTGS(service_principal)
        else:
            tgt_principal = f"krbtgt/{domain}@{domain}".upper()
            credential = cache.getCredential(tgt_principal)
            if credential is not None:
                tgt = credential.toTGT()
    except ImpacketShareDiscoveryError:
        raise
    except Exception:
        raise ImpacketShareDiscoveryError(_invalid_ccache()) from None
    if not domain or not username or (tgt is None and tgs is None):
        raise ImpacketShareDiscoveryError(_invalid_ccache())
    return domain, username, tgt, tgs


def _share_names(entries: Iterable[object]) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        try:
            value = entry["shi1_netname"]  # type: ignore[index]
        except (KeyError, TypeError):
            continue
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeError:
                continue
        if not isinstance(value, str):
            continue
        candidate = value.rstrip("\x00").strip()
        if not candidate or candidate in {".", ".."}:
            continue
        if any(character in candidate for character in ("/", "\\", "\x00", "\r", "\n")):
            continue
        folded = candidate.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        names.append(candidate)
    return tuple(names)


def _validate_request(
    target: str,
    credential: Credential,
    kerberos_hostname: str | None,
    mechanism: AuthMechanism,
    timeout_seconds: float,
) -> None:
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be non-empty text.")
    if not isinstance(credential, Credential):
        raise TypeError("credential must be a Credential instance.")
    if not isinstance(mechanism, AuthMechanism):
        raise TypeError("mechanism must be an AuthMechanism value.")
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive.")
    if mechanism is AuthMechanism.KERBEROS and (
        not isinstance(kerberos_hostname, str) or not kerberos_hostname.strip()
    ):
        raise ImpacketShareDiscoveryError(_missing_spn_hostname())


def _discovery_error(exception: BaseException, *, target: str) -> SmbErrorDetail:
    raw_code = _raw_error_code(exception)
    if raw_code in _DENIED_CODES:
        status = TargetStatus.SHARE_ENUM_DENIED
        symbolic_name = "SHARE_ENUM_ACCESS_DENIED"
        safe_message = "Share listesi için kullanılan ikinci oturum kabul edilmedi."
    elif raw_code in {errno.ETIMEDOUT, errno.EAGAIN}:
        status = TargetStatus.SHARE_ENUM_UNAVAILABLE
        symbolic_name = "SHARE_ENUM_TIMEOUT"
        safe_message = "Share listeleme isteği zaman aşımına uğradı."
    else:
        status = TargetStatus.SHARE_ENUM_FAILED
        symbolic_name = "SHARE_ENUM_FAILED"
        safe_message = "Sunucudaki share listesi SRVSVC üzerinden alınamadı."
    return SmbErrorDetail(
        stage=TargetStage.SHARE_ENUMERATION,
        status=status,
        operation="srvsvc_netr_share_enum",
        raw_code=raw_code,
        safe_message=safe_message,
        retryable=status is TargetStatus.SHARE_ENUM_UNAVAILABLE,
        symbolic_name=symbolic_name,
        target=target,
    )


def _raw_error_code(exception: BaseException) -> int:
    get_error_code = getattr(exception, "getErrorCode", None)
    if callable(get_error_code):
        try:
            value = get_error_code()
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        except Exception:
            pass
    current: BaseException | None = exception
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, "errno", None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        current = current.__cause__ or current.__context__
    return errno.EPROTO


def _missing_spn_hostname() -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=TargetStage.SHARE_ENUMERATION,
        status=TargetStatus.SHARE_ENUM_UNAVAILABLE,
        operation="srvsvc_kerberos_preflight",
        raw_code=errno.EDESTADDRREQ,
        safe_message="Kerberos share keşfi için doğrulanmış hedef hostname bulunamadı.",
        retryable=False,
        symbolic_name="KERBEROS_HOSTNAME_REQUIRED",
    )


def _unsupported_credential() -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=TargetStage.SHARE_ENUMERATION,
        status=TargetStatus.SHARE_ENUM_UNAVAILABLE,
        operation="srvsvc_authentication",
        raw_code=errno.ENOTSUP,
        safe_message="Seçilen kimlik yöntemi share keşfi oturumunda kullanılamıyor.",
        retryable=False,
        symbolic_name="SHARE_ENUM_CREDENTIAL_UNSUPPORTED",
    )


def _invalid_ccache() -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=TargetStage.SHARE_ENUMERATION,
        status=TargetStatus.SHARE_ENUM_FAILED,
        operation="srvsvc_ccache_parse",
        raw_code=errno.EINVAL,
        safe_message="CCache içinde hedef için kullanılabilir Kerberos bileti bulunamadı.",
        retryable=False,
        symbolic_name="CCACHE_TICKET_UNAVAILABLE",
    )


def _close_connection(connection: _ImpacketConnection) -> None:
    with suppress(Exception):
        connection.close()
