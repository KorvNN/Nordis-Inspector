"""Resolve one identity and report only its immediate, evidenced capabilities."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

from nordis_smb_inspector.core.credentials import Credential
from nordis_smb_inspector.core.detection import (
    DEFAULT_DETECTION_RULES,
    DetectionRulePack,
    detect_patterns,
)

from .directory import (
    DirectoryAccessError,
    DirectoryClient,
    DirectoryClientFactory,
    DirectoryQuery,
    DirectoryRecord,
    ImpacketDirectoryClient,
    escape_filter,
)
from .models import (
    AccessCapability,
    CapabilityKind,
    Coverage,
    CoverageState,
    DirectoryIdentity,
    DirectoryTextEntry,
    DirectoryTextSignal,
    EvidenceState,
    IdentityAccessReport,
    IdentityGroup,
)

CapabilityCallback = Callable[[AccessCapability], None]

_DIRECTORY_TEXT_ATTRIBUTES = (
    "description",
    "info",
    "comment",
    "adminDescription",
)
_DIRECTORY_TEXT_GENERAL_RULE_IDS = frozenset(
    {
        "authorization-basic",
        "authorization-bearer",
        "authorization-token-header",
        "connection-string-password",
        "cookie-secret-assignment",
        "credential-url",
        "jwt-token",
        "natural-language-secret",
        "netrc-credential",
        "recovery-secret-assignment",
        "secret-assignment",
        "slack-token-prefix",
        "url-query-secret",
    }
)
_DIRECTORY_TEXT_RULES = tuple(
    rule
    for rule in DEFAULT_DETECTION_RULES
    if rule.pack is DetectionRulePack.CLOUD_SERVICES
    or rule.rule_id in _DIRECTORY_TEXT_GENERAL_RULE_IDS
)


class IdentityAccessCancellation(Protocol):
    def raise_if_requested(self) -> None: ...


@dataclass(frozen=True, slots=True)
class _ResolvedIdentity:
    identity: DirectoryIdentity
    primary_group_id: int | None


def inspect_identity_access(
    *,
    controller: str,
    credential: Credential,
    cancellation: IdentityAccessCancellation,
    kerberos_hostname: str | None = None,
    on_capability: CapabilityCallback | None = None,
    client_factory: DirectoryClientFactory = ImpacketDirectoryClient,
) -> IdentityAccessReport:
    """Inspect immediate access and retain readable text only in the live report."""

    cancellation.raise_if_requested()
    client = client_factory(controller, credential, kerberos_hostname)
    capabilities: list[AccessCapability] = []
    coverage: list[Coverage] = []
    directory_text: tuple[DirectoryTextEntry, ...] = ()

    def add_capability(capability: AccessCapability) -> None:
        capabilities.append(capability)
        if on_capability is not None:
            on_capability(capability)

    try:
        resolved = _resolve_identity(client)
        cancellation.raise_if_requested()
        identity, group_coverage = _with_effective_groups(
            client,
            resolved,
            cancellation,
        )
        coverage.append(group_coverage)
        cancellation.raise_if_requested()
        coverage.append(
            _inspect_secret_readability(
                client,
                identity,
                cancellation,
                add_capability,
            )
        )
        cancellation.raise_if_requested()
        directory_text, directory_text_coverage = _inspect_directory_text(
            client,
            cancellation,
        )
        coverage.append(directory_text_coverage)
        cancellation.raise_if_requested()
        from .acl import inspect_direct_acl_capabilities

        coverage.append(
            inspect_direct_acl_capabilities(
                client,
                identity,
                cancellation,
                add_capability,
            )
        )
        return IdentityAccessReport(
            controller=controller,
            authentication_method=client.authentication_method,
            identity=identity,
            capabilities=tuple(capabilities),
            coverage=tuple(coverage),
            directory_text=directory_text,
        )
    finally:
        with suppress(Exception):
            client.close()


def _resolve_identity(client: DirectoryClient) -> _ResolvedIdentity:
    username = client.bound_username.strip()
    if not username:
        raise DirectoryAccessError(
            "IDENTITY_NOT_RESOLVED",
            "Bağlanan kullanıcı kimliği çözümlenemedi.",
        )
    query = client.search(
        "(&(objectCategory=person)(objectClass=user)"
        f"(sAMAccountName={escape_filter(username)}))",
        (
            "sAMAccountName",
            "userPrincipalName",
            "objectSid",
            "primaryGroupID",
        ),
        record_limit=2,
    )
    if not query.complete or len(query.records) != 1:
        raise DirectoryAccessError(
            "IDENTITY_NOT_RESOLVED",
            "Bağlanan kullanıcı dizinde tekil olarak çözümlenemedi.",
        )
    record = query.records[0]
    sid = _sid(record)
    if sid is None:
        raise DirectoryAccessError(
            "IDENTITY_SID_NOT_RESOLVED",
            "Bağlanan kullanıcının SID değeri çözümlenemedi.",
        )
    account = record.first_text("sAMAccountName") or username
    principal = record.first_text("userPrincipalName") or f"{account}@{client.domain}"
    return _ResolvedIdentity(
        identity=DirectoryIdentity(
            principal=principal,
            distinguished_name=record.distinguished_name,
            domain=client.domain,
            sid=sid,
        ),
        primary_group_id=_optional_integer(record, "primaryGroupID"),
    )


def _with_effective_groups(
    client: DirectoryClient,
    resolved: _ResolvedIdentity,
    cancellation: IdentityAccessCancellation,
) -> tuple[DirectoryIdentity, Coverage]:
    identity = resolved.identity
    queries: list[DirectoryQuery] = []
    messages: list[str] = []
    try:
        nested = client.search(
            "(&(objectCategory=group)"
            f"(member:1.2.840.113556.1.4.1941:={escape_filter(identity.distinguished_name)}))",
            ("sAMAccountName", "objectSid"),
        )
        queries.append(nested)
    except DirectoryAccessError as error:
        return (
            DirectoryIdentity(
                principal=identity.principal,
                distinguished_name=identity.distinguished_name,
                domain=identity.domain,
                sid=identity.sid,
                token_complete=False,
            ),
            Coverage(
                check_id="effective_groups",
                label="Etkin grup üyelikleri",
                state=CoverageState.NOT_CHECKED,
                message=error.safe_message,
            ),
        )

    cancellation.raise_if_requested()
    primary_group_sid = _primary_group_sid(identity.sid, resolved.primary_group_id)
    if primary_group_sid is None:
        messages.append("Primary group SID çözümlenemedi")
    else:
        try:
            primary = client.search(
                "(&(objectCategory=group)"
                f"(objectSid={escape_filter(primary_group_sid)}))",
                ("sAMAccountName", "objectSid"),
                record_limit=2,
            )
            queries.append(primary)
            if not primary.complete or len(primary.records) != 1:
                messages.append("Primary group tekil olarak çözümlenemedi")
        except DirectoryAccessError:
            messages.append("Primary group çözümlenemedi")

    records = tuple(record for query in queries for record in query.records)
    groups = tuple(
        sorted(
            {
                IdentityGroup(name=name, sid=sid)
                for record in records
                if (name := record.first_text("sAMAccountName"))
                and (sid := _sid(record))
            },
            key=lambda group: group.name.casefold(),
        )
    )
    if len(groups) != len(records):
        messages.append("Bir veya daha fazla grup SID değeri çözümlenemedi")
    if any(not query.complete for query in queries):
        messages.append("Grup sorgusu sonuç sınırına ulaştı")
    complete = not messages
    return (
        DirectoryIdentity(
            principal=identity.principal,
            distinguished_name=identity.distinguished_name,
            domain=identity.domain,
            sid=identity.sid,
            groups=groups,
            token_complete=complete,
        ),
        Coverage(
            check_id="effective_groups",
            label="Etkin grup üyelikleri",
            state=CoverageState.COMPLETED if complete else CoverageState.PARTIAL,
            records_seen=len(records),
            message="; ".join(messages) + "." if messages else None,
        ),
    )


def _inspect_secret_readability(
    client: DirectoryClient,
    identity: DirectoryIdentity,
    cancellation: IdentityAccessCancellation,
    add_capability: CapabilityCallback,
) -> Coverage:
    queries: list[DirectoryQuery] = []
    try:
        computers = client.search(
            "(objectCategory=computer)",
            (
                "sAMAccountName",
                "dNSHostName",
                "ms-Mcs-AdmPwd",
                "msLAPS-Password",
            ),
        )
        queries.append(computers)
        for record in computers:
            cancellation.raise_if_requested()
            readable_attribute = next(
                (
                    attribute
                    for attribute in ("msLAPS-Password", "ms-Mcs-AdmPwd")
                    if record.has_nonempty(attribute)
                ),
                None,
            )
            if readable_attribute is None:
                continue
            subject = (
                record.first_text("dNSHostName")
                or record.first_text("sAMAccountName")
                or _rdn(record)
            )
            add_capability(
                AccessCapability(
                    capability_id="laps_secret_read",
                    kind=CapabilityKind.SECRET_READ,
                    evidence_state=EvidenceState.VERIFIED,
                    title="LAPS parola verisi okunabiliyor",
                    summary=(
                        "Directory sorgusu bu kimliğe parola özniteliğini döndürdü. "
                        "Değer sonuçlara alınmadı."
                    ),
                    subject=subject,
                    subject_type="computer",
                    via_principal=identity.principal,
                    rights=(readable_attribute,),
                    next_step=(
                        "Host tarama kapsamındaysa yerel yönetici erişimini ayrı ve "
                        "yetkili bir adımda doğrula."
                    ),
                )
            )

        cancellation.raise_if_requested()
        managed_accounts = client.search(
            "(objectClass=msDS-GroupManagedServiceAccount)",
            ("sAMAccountName", "msDS-ManagedPassword"),
        )
        queries.append(managed_accounts)
        for record in managed_accounts:
            cancellation.raise_if_requested()
            if not record.has_nonempty("msDS-ManagedPassword"):
                continue
            subject = record.first_text("sAMAccountName") or _rdn(record)
            add_capability(
                AccessCapability(
                    capability_id="gmsa_secret_read",
                    kind=CapabilityKind.SECRET_READ,
                    evidence_state=EvidenceState.VERIFIED,
                    title="gMSA parola verisi okunabiliyor",
                    summary=(
                        "Directory sorgusu bu kimliğe yönetilen parola blob'unu "
                        "döndürdü. Değer sonuçlara alınmadı."
                    ),
                    subject=subject,
                    subject_type="gmsa",
                    via_principal=identity.principal,
                    rights=("msDS-ManagedPassword",),
                    next_step="Hesabın bağlı olduğu servisleri ve erişim kapsamını doğrula.",
                )
            )
    except DirectoryAccessError as error:
        return Coverage(
            check_id="secret_readability",
            label="LAPS ve gMSA okunabilirliği",
            state=(CoverageState.PARTIAL if queries else CoverageState.NOT_CHECKED),
            records_seen=sum(len(query) for query in queries),
            message=error.safe_message,
        )

    complete = all(query.complete for query in queries)
    return Coverage(
        check_id="secret_readability",
        label="LAPS ve gMSA okunabilirliği",
        state=CoverageState.COMPLETED if complete else CoverageState.PARTIAL,
        records_seen=sum(len(query) for query in queries),
        message=(
            None
            if complete
            else "Bir veya daha fazla sorgu sonuç sınırına ulaştı; kapsam eksik."
        ),
    )


def _inspect_directory_text(
    client: DirectoryClient,
    cancellation: IdentityAccessCancellation,
) -> tuple[tuple[DirectoryTextEntry, ...], Coverage]:
    """Inventory readable LDAP text and attach non-authoritative review signals."""

    try:
        query = client.search(
            "(|(description=*)(info=*)(comment=*)(adminDescription=*))",
            (
                "sAMAccountName",
                "dNSHostName",
                "displayName",
                "name",
                "objectClass",
                *_DIRECTORY_TEXT_ATTRIBUTES,
            ),
        )
    except DirectoryAccessError as error:
        return (
            (),
            Coverage(
                check_id="directory_text_inventory",
                label="LDAP metin alanları",
                state=CoverageState.NOT_CHECKED,
                message=error.safe_message,
            ),
        )

    entries: list[DirectoryTextEntry] = []
    for record in query:
        cancellation.raise_if_requested()
        subject = (
            record.first_text("dNSHostName")
            or record.first_text("sAMAccountName")
            or record.first_text("displayName")
            or record.first_text("name")
            or _rdn(record)
        )
        subject_type = _directory_object_type(record)
        for attribute in _DIRECTORY_TEXT_ATTRIBUTES:
            for value in record.text_values(attribute):
                signals: list[DirectoryTextSignal] = []
                seen_signals: set[tuple[str, int]] = set()
                lines = value.splitlines() or (value,)
                for line_number, line in enumerate(lines, start=1):
                    for match in detect_patterns(
                        line,
                        line_number,
                        rules=_DIRECTORY_TEXT_RULES,
                    ):
                        signal_key = (match.rule_id, line_number)
                        if signal_key in seen_signals:
                            continue
                        seen_signals.add(signal_key)
                        signals.append(
                            DirectoryTextSignal(
                                rule_id=match.rule_id,
                                title=match.title,
                                category=match.category,
                                confidence=match.confidence.value,
                                line_number=line_number,
                            )
                        )
                entries.append(
                    DirectoryTextEntry(
                        distinguished_name=record.distinguished_name,
                        subject=subject,
                        subject_type=subject_type,
                        attribute=attribute,
                        value=value,
                        signals=tuple(signals),
                    )
                )

    return (
        tuple(entries),
        Coverage(
            check_id="directory_text_inventory",
            label="LDAP metin alanları",
            state=CoverageState.COMPLETED if query.complete else CoverageState.PARTIAL,
            records_seen=len(query),
            message=(
                None
                if query.complete
                else "Sorgu sonuç sınırına ulaştı; kapsam eksik."
            ),
        ),
    )


def _directory_object_type(record: DirectoryRecord) -> str:
    classes = {value.casefold() for value in record.text_values("objectClass")}
    for class_name, label in (
        ("computer", "computer"),
        ("group", "group"),
        ("grouppolicycontainer", "gpo"),
        ("organizationalunit", "organizational_unit"),
        ("contact", "contact"),
        ("user", "user"),
        ("domaindns", "domain"),
        ("container", "container"),
    ):
        if class_name in classes:
            return label
    return "directory_object"


def _sid(record: DirectoryRecord) -> str | None:
    values = record.values("objectSid")
    if not values:
        return None
    try:
        from impacket.ldap.ldaptypes import LDAP_SID

        return LDAP_SID(data=values[0]).formatCanonical()
    except Exception:
        return None


def _optional_integer(record: DirectoryRecord, name: str) -> int | None:
    value = record.first_text(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _primary_group_sid(identity_sid: str, primary_group_id: int | None) -> str | None:
    if primary_group_id is None or "-" not in identity_sid:
        return None
    domain_sid, _separator, _rid = identity_sid.rpartition("-")
    return f"{domain_sid}-{primary_group_id}" if domain_sid else None


def _rdn(record: DirectoryRecord) -> str:
    return record.distinguished_name.partition(",")[0].partition("=")[2] or "Bilinmeyen"
