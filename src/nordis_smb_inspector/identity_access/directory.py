"""Bounded, signed LDAP access for principal-scoped capability checks."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Protocol

from nordis_smb_inspector.core.credentials import AuthMode, Credential, CredentialKind

_DEFAULT_RECORD_LIMIT = 20_000


class DirectoryAccessError(RuntimeError):
    """Normalized directory error whose message is safe for the local UI."""

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


@dataclass(frozen=True, slots=True, repr=False)
class DirectoryQuery:
    records: tuple[DirectoryRecord, ...] = field(default_factory=tuple, repr=False)
    complete: bool = True

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __repr__(self) -> str:
        return f"DirectoryQuery(records={len(self.records)!r}, complete={self.complete!r})"


class DirectoryClient(Protocol):
    authentication_method: str
    bound_username: str
    base_dn: str
    configuration_dn: str
    schema_dn: str
    domain: str

    def search(
        self,
        search_filter: str,
        attributes: Sequence[str],
        *,
        search_base: str | None = None,
        base_object: bool = False,
        security_descriptor_flags: int | None = None,
        record_limit: int = _DEFAULT_RECORD_LIMIT,
    ) -> DirectoryQuery: ...

    def close(self) -> None: ...


DirectoryClientFactory = Callable[..., DirectoryClient]


class ImpacketDirectoryClient:
    """Authenticate once, discover naming contexts, and issue signed LDAP queries."""

    def __init__(
        self,
        controller: str,
        credential: Credential,
        kerberos_hostname: str | None = None,
        *,
        connection_factory: Callable[..., Any] | None = None,
    ) -> None:
        controller = controller.strip()
        kerberos_hostname = (kerberos_hostname or "").strip() or None
        if not valid_directory_target(controller):
            raise DirectoryAccessError(
                "INVALID_DIRECTORY_TARGET",
                "Directory hedefi IP veya hostname biçiminde olmalıdır.",
            )
        if kerberos_hostname is not None and not valid_dns_name(
            kerberos_hostname, require_fqdn=True
        ):
            raise DirectoryAccessError(
                "INVALID_KERBEROS_HOSTNAME",
                "Kerberos hostname FQDN biçiminde olmalıdır.",
            )
        if (
            credential.auth_mode is AuthMode.KERBEROS_ONLY
            and kerberos_hostname is None
            and not valid_dns_name(controller, require_fqdn=True)
        ):
            raise DirectoryAccessError(
                "KERBEROS_HOSTNAME_REQUIRED",
                "IP veya kısa hostname ile Kerberos için DC FQDN değeri gereklidir.",
            )

        if connection_factory is None:
            from impacket.ldap.ldap import LDAPConnection

            connection_factory = LDAPConnection

        self._controller = controller
        self._kerberos_hostname = kerberos_hostname
        self._connection_factory = connection_factory
        self._connection: Any | None = None
        self.authentication_method = ""
        self.bound_username = ""
        self.base_dn = ""
        self.configuration_dn = ""
        self.schema_dn = ""
        self.domain = ""

        try:
            self._authenticate(credential)
            self._load_naming_contexts(credential)
        except DirectoryAccessError:
            self.close()
            raise
        except Exception:
            self.close()
            raise DirectoryAccessError(
                "DIRECTORY_AUTHENTICATION_FAILED",
                "Directory kimlik doğrulaması tamamlanamadı.",
            ) from None

    def _authenticate(self, credential: Credential) -> None:
        attempts = _authentication_attempts(
            credential,
            controller=self._controller,
            kerberos_hostname=self._kerberos_hostname,
        )
        for method, ldap_hostname, username, domain in attempts:
            connection = self._new_connection(ldap_hostname)
            try:
                if method == "kerberos":
                    bound_username = self._login_kerberos(
                        connection, credential, username, domain
                    )
                else:
                    self._login_ntlm(connection, credential, username, domain)
                    bound_username = username
            except Exception:
                _close_connection(connection)
                continue
            self._connection = connection
            self.authentication_method = method
            self.bound_username = bound_username
            return
        raise DirectoryAccessError(
            "DIRECTORY_AUTHENTICATION_FAILED",
            "Directory kimlik doğrulaması tamamlanamadı.",
        )

    def _new_connection(self, ldap_hostname: str) -> Any:
        return self._connection_factory(
            f"ldap://{url_host(ldap_hostname)}",
            "",
            dstIp=self._controller,
            signing=True,
        )

    def _login_ntlm(
        self,
        connection: Any,
        credential: Credential,
        username: str,
        domain: str,
    ) -> None:
        if credential.kind is CredentialKind.CCACHE:
            raise ValueError("CCache cannot be used for NTLM.")
        connection.login(
            username,
            credential.password or "",
            domain,
            "",
            credential.nt_hash or "",
            authenticationChoice="sasl",
        )

    def _login_kerberos(
        self,
        connection: Any,
        credential: Credential,
        username: str,
        domain: str,
    ) -> str:
        if credential.kind is CredentialKind.NT_HASH:
            raise ValueError("An NT hash cannot be used for Kerberos LDAP.")
        if credential.kind is CredentialKind.CCACHE:
            cache = _ccache_from_bytes(credential.ccache_data or b"")
            domain, username, tgt, tgs = ccache_material(
                cache,
                domain=domain,
                username=username,
                hostname=self._kerberos_target(),
            )
            connection.kerberosLogin(
                username,
                "",
                domain,
                kdcHost=self._controller,
                TGT=tgt,
                TGS=tgs,
                useCache=False,
            )
            return username
        connection.kerberosLogin(
            username,
            credential.password or "",
            domain,
            kdcHost=self._controller,
            useCache=False,
        )
        return username

    def _kerberos_target(self) -> str:
        return self._kerberos_hostname or self._controller

    def _load_naming_contexts(self, credential: Credential) -> None:
        response = self._raw_search(
            search_base="",
            base_object=True,
            search_filter="(objectClass=*)",
            attributes=(
                "defaultNamingContext",
                "configurationNamingContext",
                "schemaNamingContext",
            ),
            record_limit=1,
        )
        if not response.records:
            raise DirectoryAccessError(
                "DIRECTORY_CONTEXT_UNAVAILABLE",
                "Directory naming context bilgisi okunamadı.",
            )
        root = response.records[0]
        self.base_dn = root.first_text("defaultNamingContext") or ""
        self.configuration_dn = root.first_text("configurationNamingContext") or ""
        self.schema_dn = root.first_text("schemaNamingContext") or ""
        if not self.base_dn:
            raise DirectoryAccessError(
                "DIRECTORY_CONTEXT_UNAVAILABLE",
                "Directory naming context bilgisi okunamadı.",
            )
        self.domain = base_dn_to_domain(self.base_dn) or _credential_dns_domain(
            credential,
            self._kerberos_target(),
        )

    def search(
        self,
        search_filter: str,
        attributes: Sequence[str],
        *,
        search_base: str | None = None,
        base_object: bool = False,
        security_descriptor_flags: int | None = None,
        record_limit: int = _DEFAULT_RECORD_LIMIT,
    ) -> DirectoryQuery:
        if not isinstance(search_filter, str) or not search_filter:
            raise TypeError("search_filter must be non-empty text.")
        if not isinstance(record_limit, int) or isinstance(record_limit, bool):
            raise TypeError("record_limit must be an integer.")
        if record_limit <= 0:
            raise ValueError("record_limit must be greater than zero.")
        return self._raw_search(
            search_base=self.base_dn if search_base is None else search_base,
            base_object=base_object,
            search_filter=search_filter,
            attributes=attributes,
            security_descriptor_flags=security_descriptor_flags,
            record_limit=record_limit,
        )

    def _raw_search(
        self,
        *,
        search_base: str,
        base_object: bool,
        search_filter: str,
        attributes: Sequence[str],
        record_limit: int,
        security_descriptor_flags: int | None = None,
    ) -> DirectoryQuery:
        from impacket.ldap import ldap, ldapasn1

        connection = self._connection
        if connection is None:
            raise DirectoryAccessError(
                "DIRECTORY_CONNECTION_CLOSED",
                "Directory bağlantısı kapalı.",
            )
        controls: list[Any] = []
        if not base_object:
            controls.append(ldap.SimplePagedResultsControl(size=500))
        if security_descriptor_flags is not None:
            controls.append(ldapasn1.SDFlagsControl(flags=security_descriptor_flags))
        scope = ldapasn1.Scope("baseObject") if base_object else None
        complete = True
        try:
            response = connection.search(
                searchBase=search_base,
                scope=scope,
                searchFilter=search_filter,
                attributes=list(attributes),
                sizeLimit=record_limit,
                searchControls=controls or None,
            )
        except ldap.LDAPSearchError as error:
            response = error.getAnswers()
            if not response:
                raise DirectoryAccessError(
                    "DIRECTORY_QUERY_FAILED",
                    "Directory sorgusu tamamlanamadı.",
                ) from None
            complete = False
        except Exception:
            raise DirectoryAccessError(
                "DIRECTORY_QUERY_FAILED",
                "Directory sorgusu tamamlanamadı.",
            ) from None
        records = _records_from_response(response)
        if len(records) > record_limit:
            records = records[:record_limit]
            complete = False
        return DirectoryQuery(records=tuple(records), complete=complete)

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            _close_connection(connection)


def _authentication_attempts(
    credential: Credential,
    *,
    controller: str,
    kerberos_hostname: str | None,
) -> tuple[tuple[str, str, str, str], ...]:
    username, supplied_domain = identity_parts(credential)
    kerberos_target = kerberos_hostname or controller
    kerberos_domain = _credential_dns_domain(credential, kerberos_target)
    kerberos_available = bool(
        kerberos_domain
        and valid_dns_name(kerberos_target, require_fqdn=True)
        and credential.kind is not CredentialKind.NT_HASH
    )
    ntlm_available = credential.kind is not CredentialKind.CCACHE

    if credential.auth_mode is AuthMode.KERBEROS_ONLY:
        if not kerberos_available:
            raise DirectoryAccessError(
                "KERBEROS_CONTEXT_UNAVAILABLE",
                "Kerberos için realm ve DC FQDN bilgisi çözümlenemedi.",
            )
        return (("kerberos", kerberos_target, username, kerberos_domain),)
    if credential.auth_mode is AuthMode.NTLM_ONLY:
        if not ntlm_available:
            raise DirectoryAccessError(
                "UNSUPPORTED_DIRECTORY_CREDENTIAL",
                "CCache NTLM ile kullanılamaz.",
            )
        return (("ntlm", controller, username, supplied_domain),)

    attempts: list[tuple[str, str, str, str]] = []
    if kerberos_available:
        attempts.append(("kerberos", kerberos_target, username, kerberos_domain))
    if ntlm_available:
        attempts.append(("ntlm", controller, username, supplied_domain))
    if not attempts:
        raise DirectoryAccessError(
            "UNSUPPORTED_DIRECTORY_CREDENTIAL",
            "Bu kimlik bilgisi directory erişiminde kullanılamıyor.",
        )
    return tuple(attempts)


def _credential_dns_domain(credential: Credential, kerberos_hostname: str) -> str:
    username = credential.username or ""
    if "@" in username:
        realm = username.rsplit("@", 1)[1]
        if valid_dns_name(realm, require_fqdn=True):
            return realm.rstrip(".")
    domain = credential.domain or ""
    if valid_dns_name(domain, require_fqdn=True):
        return domain.rstrip(".")
    if valid_dns_name(kerberos_hostname, require_fqdn=True):
        return kerberos_hostname.split(".", 1)[1]
    return ""


def _records_from_response(response: Sequence[Any]) -> list[DirectoryRecord]:
    from impacket.ldap import ldapasn1

    records: list[DirectoryRecord] = []
    for item in response:
        if not isinstance(item, ldapasn1.SearchResultEntry):
            continue
        mapped: dict[str, tuple[bytes, ...]] = {}
        for attribute in item["attributes"]:
            name = str(attribute["type"])
            mapped[name] = tuple(value.asOctets() for value in attribute["vals"])
        records.append(DirectoryRecord(str(item["objectName"]), mapped))
    return records


def valid_directory_target(value: str) -> bool:
    candidate = value.strip()
    if not candidate or any(character.isspace() for character in candidate):
        return False
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return valid_dns_name(candidate, require_fqdn=False)
    return True


def valid_dns_name(value: str, *, require_fqdn: bool) -> bool:
    candidate = value.strip().rstrip(".")
    if (
        not candidate
        or not candidate.isascii()
        or len(candidate) > 253
        or any(character in candidate for character in ("/", "\\", ":"))
    ):
        return False
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return False
    labels = candidate.split(".")
    if require_fqdn and len(labels) < 2:
        return False
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def url_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    return f"[{address}]" if address.version == 6 else str(address)


def base_dn_to_domain(value: str) -> str:
    labels: list[str] = []
    for component in value.split(","):
        name, separator, raw_value = component.strip().partition("=")
        if separator and name.casefold() == "dc" and raw_value:
            labels.append(raw_value.replace(r"\,", ",").replace(r"\\", "\\"))
    return ".".join(labels)


def escape_filter(value: str) -> str:
    return "".join(
        {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}.get(
            character, character
        )
        for character in value
    )


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
        raise DirectoryAccessError(
            "INVALID_CCACHE", "CCache LDAP bileti içermiyor."
        ) from None
    if not domain or not username or (tgt is None and tgs is None):
        raise DirectoryAccessError("INVALID_CCACHE", "CCache LDAP bileti içermiyor.")
    return domain, username, tgt, tgs


def _ccache_from_bytes(data: bytes) -> object:
    from impacket.krb5.ccache import CCache

    try:
        return CCache(data)
    except Exception:
        raise DirectoryAccessError(
            "INVALID_CCACHE", "CCache dosyası okunamadı."
        ) from None


def _close_connection(connection: Any) -> None:
    with suppress(Exception):
        connection.close()
