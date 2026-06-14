"""Small Impacket LDAP adapter with explicit authentication and safe records."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Protocol

from nordis_smb_inspector.core.credentials import AuthMode, Credential, CredentialKind


class AdInspectionError(RuntimeError):
    """Normalized error safe to return to the local UI."""

    def __init__(self, code: str, safe_message: str) -> None:
        self.code = code
        self.safe_message = safe_message
        super().__init__(safe_message)


@dataclass(frozen=True, slots=True, repr=False)
class DirectoryRecord:
    distinguished_name: str
    attributes: Mapping[str, tuple[bytes, ...]] = field(repr=False)

    def values(self, name: str) -> tuple[bytes, ...]:
        folded = name.casefold()
        return next(
            (values for key, values in self.attributes.items() if key.casefold() == folded),
            (),
        )

    def text_values(self, name: str) -> tuple[str, ...]:
        decoded: list[str] = []
        for value in self.values(name):
            try:
                decoded.append(value.decode("utf-8"))
            except UnicodeError:
                continue
        return tuple(decoded)

    def first_text(self, name: str) -> str | None:
        values = self.text_values(name)
        return values[0] if values else None

    def has_nonempty(self, name: str) -> bool:
        return any(bool(value) for value in self.values(name))

    def __repr__(self) -> str:
        return (
            f"DirectoryRecord(distinguished_name={self.distinguished_name!r}, "
            f"attribute_names={tuple(self.attributes)!r})"
        )


class DirectoryClient(Protocol):
    authentication_method: str
    bound_username: str

    def search(
        self,
        search_filter: str,
        attributes: Sequence[str],
        *,
        search_base: str | None = None,
        base_object: bool = False,
    ) -> tuple[DirectoryRecord, ...]: ...

    def close(self) -> None: ...


DirectoryClientFactory = Callable[..., DirectoryClient]


class ImpacketLdapClient:
    """Signed LDAP connection; it never logs returned attribute values."""

    def __init__(
        self,
        controller: str,
        domain: str,
        credential: Credential,
        kerberos_hostname: str | None = None,
    ) -> None:
        controller = controller.strip()
        domain = domain.strip()
        if not valid_directory_host(controller) or not valid_domain_name(domain):
            raise AdInspectionError(
                "INVALID_DIRECTORY_TARGET",
                "Domain controller ve FQDN biçiminde domain gereklidir.",
            )
        if credential.auth_mode is AuthMode.AUTO:
            raise AdInspectionError(
                "EXPLICIT_AUTH_REQUIRED",
                "AD incelemesi için Kerberos veya NTLM açıkça seçilmelidir.",
            )
        spn_hostname = (kerberos_hostname or controller).strip()
        if credential.auth_mode is AuthMode.KERBEROS_ONLY and (
            not valid_directory_host(spn_hostname) or _is_ip(spn_hostname)
        ):
            raise AdInspectionError(
                "KERBEROS_HOSTNAME_REQUIRED",
                "IP ile Kerberos kullanırken domain controller hostname gereklidir.",
            )

        from impacket.ldap import ldap

        logging.getLogger("impacket").disabled = True
        self._domain = domain
        self._controller = controller
        self._kerberos_hostname = spn_hostname
        self._base_dn = domain_to_base_dn(domain)
        ldap_hostname = (
            spn_hostname
            if credential.auth_mode is AuthMode.KERBEROS_ONLY
            else controller
        )
        self._connection = ldap.LDAPConnection(
            f"ldap://{ldap_hostname}", self._base_dn, dstIp=controller, signing=True
        )
        try:
            self._authenticate(credential)
        except AdInspectionError:
            self.close()
            raise
        except Exception:
            self.close()
            raise AdInspectionError(
                "LDAP_AUTHENTICATION_FAILED",
                "LDAP kimlik doğrulaması başarısız oldu.",
            ) from None

    @property
    def authentication_method(self) -> str:
        return "kerberos" if self._auth_mode is AuthMode.KERBEROS_ONLY else "ntlm"

    def _authenticate(self, credential: Credential) -> None:
        self._auth_mode = credential.auth_mode
        username, domain = identity_parts(credential)
        if credential.auth_mode is AuthMode.NTLM_ONLY:
            if credential.kind is CredentialKind.CCACHE:
                raise AdInspectionError("UNSUPPORTED_CREDENTIAL", "CCache NTLM ile kullanılamaz.")
            self._connection.login(
                username,
                credential.password or "",
                domain,
                "",
                credential.nt_hash or "",
                authenticationChoice="sasl",
            )
            self.bound_username = username
            return

        if credential.kind is CredentialKind.NT_HASH:
            raise AdInspectionError(
                "UNSUPPORTED_CREDENTIAL", "NT hash Kerberos ile kullanılamaz."
            )
        if credential.kind is CredentialKind.CCACHE:
            cache = _ccache_from_bytes(credential.ccache_data or b"")
            domain, username, tgt, tgs = ccache_material(
                cache,
                domain=domain,
                username=username,
                hostname=self._kerberos_hostname,
            )
            self._connection.kerberosLogin(
                username,
                "",
                domain,
                kdcHost=self._controller,
                TGT=tgt,
                TGS=tgs,
                useCache=False,
            )
            self.bound_username = username
            return
        self._connection.kerberosLogin(
            username,
            credential.password or "",
            domain,
            kdcHost=self._controller,
            useCache=False,
        )
        self.bound_username = username

    def search(
        self,
        search_filter: str,
        attributes: Sequence[str],
        *,
        search_base: str | None = None,
        base_object: bool = False,
    ) -> tuple[DirectoryRecord, ...]:
        from impacket.ldap import ldap, ldapasn1

        controls = None if base_object else [ldap.SimplePagedResultsControl(size=200)]
        scope = ldapasn1.Scope("baseObject") if base_object else None
        try:
            response = self._connection.search(
                searchBase=search_base,
                scope=scope,
                searchFilter=search_filter,
                attributes=list(attributes),
                sizeLimit=0,
                searchControls=controls,
            )
        except Exception:
            raise AdInspectionError(
                "LDAP_QUERY_FAILED", "LDAP sorgusu tamamlanamadı."
            ) from None
        records: list[DirectoryRecord] = []
        for item in response:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            mapped: dict[str, tuple[bytes, ...]] = {}
            for attribute in item["attributes"]:
                name = str(attribute["type"])
                mapped[name] = tuple(value.asOctets() for value in attribute["vals"])
            records.append(DirectoryRecord(str(item["objectName"]), mapped))
        return tuple(records)

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is None:
            return
        with suppress(Exception):
            connection.close()
        self._connection = None


def domain_to_base_dn(domain: str) -> str:
    domain = domain.strip()
    if not valid_domain_name(domain):
        raise AdInspectionError("INVALID_DOMAIN", "Domain FQDN biçiminde olmalıdır.")
    labels = domain.rstrip(".").split(".")
    return ",".join(f"DC={escape_dn_component(label)}" for label in labels)


def valid_domain_name(value: str) -> bool:
    return "." in value.rstrip(".") and valid_directory_host(value)


def valid_directory_host(value: str) -> bool:
    candidate = value.strip()
    if (
        not candidate
        or candidate.endswith(".")
        or not candidate.isascii()
        or len(candidate) > 253
        or any(
        character in candidate for character in ("/", "\\", ":", " ", "\t", "\r", "\n")
        )
    ):
        return False
    labels = candidate.rstrip(".").split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def escape_filter(value: str) -> str:
    return "".join(
        {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}.get(
            character, character
        )
        for character in value
    )


def escape_dn_component(value: str) -> str:
    escaped = value.replace("\\", r"\\").replace(",", r"\,").replace("+", r"\+")
    escaped = escaped.replace('"', r'\"').replace("<", r"\<").replace(">", r"\>")
    if escaped.startswith((" ", "#")):
        escaped = "\\" + escaped
    if escaped.endswith(" "):
        escaped = escaped[:-1] + r"\ "
    return escaped


def identity_parts(credential: Credential) -> tuple[str, str]:
    username = credential.username or ""
    domain = credential.domain or ""
    if "@" in username:
        user_part, realm = username.rsplit("@", 1)
        if user_part and realm:
            return user_part, domain or realm
    if "\\" in username:
        realm, user_part = username.split("\\", 1)
        if realm and user_part:
            return user_part, domain or realm
    return username, domain


def ccache_material(
    cache: object, *, domain: str, username: str, hostname: str
) -> tuple[str, str, object | None, object | None]:
    principal = getattr(cache, "principal", None)
    try:
        if principal is None:
            raise ValueError
        if not domain:
            domain = principal.realm["data"].decode("utf-8")
        if not username and principal.components:
            username = principal.components[0]["data"].decode("utf-8")
        service = f"ldap/{hostname}@{domain}".upper()
        found = cache.getCredential(service)
        tgt = None
        tgs = found.toTGS(service) if found is not None else None
        if found is None:
            target = f"krbtgt/{domain}@{domain}".upper()
            found = cache.getCredential(target)
            tgt = found.toTGT() if found is not None else None
    except Exception:
        raise AdInspectionError("INVALID_CCACHE", "CCache LDAP bileti içermiyor.") from None
    if not domain or not username or (tgt is None and tgs is None):
        raise AdInspectionError("INVALID_CCACHE", "CCache LDAP bileti içermiyor.")
    return domain, username, tgt, tgs


def _ccache_from_bytes(data: bytes) -> object:
    from impacket.krb5.ccache import CCache

    try:
        return CCache(data)
    except Exception:
        raise AdInspectionError("INVALID_CCACHE", "CCache dosyası okunamadı.") from None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
