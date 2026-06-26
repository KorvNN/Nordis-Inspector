"""Principal-centric Active Directory checks over read-only LDAP queries."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from typing import Protocol

from nordis_smb_inspector.core.credentials import Credential

from .ldap_adapter import (
    AdInspectionError,
    DirectoryClient,
    DirectoryClientFactory,
    DirectoryRecord,
    ImpacketLdapClient,
    domain_to_base_dn,
    escape_filter,
)
from .models import (
    AdComputer,
    AdCoverage,
    AdCoverageState,
    AdEvidenceState,
    AdFinding,
    AdFindingLane,
    AdIdentity,
    AdInspectionReport,
    AdSeverity,
)

_UAC_DISABLED = 0x0002
_UAC_DONT_REQUIRE_PREAUTH = 0x400000
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


class AdCancellation(Protocol):
    def raise_if_requested(self) -> None: ...


FindingCallback = Callable[[AdFinding], None]
ComputerCallback = Callable[[AdComputer], None]


def inspect_directory(
    *,
    controller: str,
    domain: str,
    credential: Credential,
    kerberos_hostname: str | None = None,
    cancellation: AdCancellation,
    on_finding: FindingCallback | None = None,
    on_computer: ComputerCallback | None = None,
    client_factory: DirectoryClientFactory = ImpacketLdapClient,
) -> AdInspectionReport:
    """Inspect AD visibility without changing directory state or returning secrets."""

    cancellation.raise_if_requested()
    client = client_factory(controller, domain, credential, kerberos_hostname)
    findings: list[AdFinding] = []
    computers: list[AdComputer] = []
    coverage: list[AdCoverage] = []

    def add_finding(finding: AdFinding) -> None:
        findings.append(finding)
        if on_finding is not None:
            on_finding(finding)

    def add_computer(computer: AdComputer) -> None:
        computers.append(computer)
        if on_computer is not None:
            on_computer(computer)

    try:
        identity = _resolve_identity(client, domain)
        cancellation.raise_if_requested()
        identity = _with_effective_groups(client, identity, coverage)

        checks = (
            (
                "computers_laps",
                "Bilgisayarlar ve LAPS görünürlüğü",
                lambda: _inspect_computers(client, add_computer, add_finding),
            ),
            (
                "gmsa_passwords",
                "gMSA parola görünürlüğü",
                lambda: _inspect_gmsa(client, add_finding),
            ),
            ("kerberoast", "Kerberoast adayları", lambda: _inspect_kerberoast(client, add_finding)),
            ("asrep", "AS-REP roast adayları", lambda: _inspect_asrep(client, add_finding)),
            (
                "delegation",
                "Kerberos delegasyonu",
                lambda: _inspect_delegation(client, add_finding),
            ),
            (
                "domain_policy",
                "Domain parola ve makine hesabı ayarları",
                lambda: _inspect_domain_policy(client, identity, add_finding),
            ),
        )
        for check_id, label, check in checks:
            cancellation.raise_if_requested()
            try:
                coverage.append(check())
            except AdInspectionError as error:
                coverage.append(
                    AdCoverage(
                        check_id=check_id,
                        label=label,
                        state=AdCoverageState.NOT_CHECKED,
                        message=error.safe_message,
                    )
                )
        return AdInspectionReport(
            identity=identity,
            authentication_method=client.authentication_method,
            computers=tuple(computers),
            findings=tuple(findings),
            coverage=tuple(coverage),
        )
    finally:
        with suppress(Exception):
            client.close()


def _resolve_identity(client: DirectoryClient, domain: str) -> AdIdentity:
    username = client.bound_username.strip()
    if not username:
        raise AdInspectionError(
            "IDENTITY_NOT_RESOLVED", "CCache içindeki kullanıcı kimliği çözümlenemedi."
        )
    records = client.search(
        "(&(objectCategory=person)(objectClass=user)"
        f"(sAMAccountName={escape_filter(username)}))",
        (
            "sAMAccountName",
            "userPrincipalName",
            "objectSid",
            "primaryGroupID",
            "distinguishedName",
        ),
    )
    if len(records) != 1:
        raise AdInspectionError(
            "IDENTITY_NOT_RESOLVED", "Bağlanan kullanıcı dizinde tekil olarak çözümlenemedi."
        )
    record = records[0]
    account = record.first_text("sAMAccountName") or username
    principal = record.first_text("userPrincipalName") or f"{account}@{domain}"
    return AdIdentity(
        principal=principal,
        distinguished_name=record.distinguished_name,
        domain=domain,
        sid=_sid(record),
        primary_group_id=_optional_integer(record, "primaryGroupID"),
    )


def _with_effective_groups(
    client: DirectoryClient,
    identity: AdIdentity,
    coverage: list[AdCoverage],
) -> AdIdentity:
    try:
        records = client.search(
            "(&(objectCategory=group)"
            f"(member:1.2.840.113556.1.4.1941:={escape_filter(identity.distinguished_name)}))",
            ("sAMAccountName",),
        )
    except AdInspectionError as error:
        coverage.append(
            AdCoverage(
                check_id="effective_groups",
                label="Etkin grup üyelikleri",
                state=AdCoverageState.NOT_CHECKED,
                message=error.safe_message,
            )
        )
        return identity
    primary_records: tuple[DirectoryRecord, ...] = ()
    state = AdCoverageState.COMPLETED
    message = None
    primary_group_sid = _primary_group_sid(identity)
    if primary_group_sid is not None:
        try:
            primary_records = client.search(
                "(&(objectCategory=group)"
                f"(objectSid={escape_filter(primary_group_sid)}))",
                ("sAMAccountName",),
            )
        except AdInspectionError:
            state = AdCoverageState.PARTIAL
            message = "Primary group üyeliği çözümlenemedi."
    groups = tuple(
        sorted(
            {
                name
                for record in (*records, *primary_records)
                if (name := record.first_text("sAMAccountName"))
            },
            key=str.casefold,
        )
    )
    coverage.append(
        AdCoverage(
            check_id="effective_groups",
            label="Etkin grup üyelikleri",
            state=state,
            records_seen=len(records) + len(primary_records),
            message=message,
        )
    )
    return AdIdentity(
        principal=identity.principal,
        distinguished_name=identity.distinguished_name,
        domain=identity.domain,
        sid=identity.sid,
        primary_group_id=identity.primary_group_id,
        groups=groups,
    )


def _inspect_computers(
    client: DirectoryClient,
    add_computer: ComputerCallback,
    add_finding: FindingCallback,
) -> AdCoverage:
    records = client.search(
        "(objectCategory=computer)",
        (
            "sAMAccountName",
            "dNSHostName",
            "operatingSystem",
            "userAccountControl",
            "ms-Mcs-AdmPwd",
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
        ),
    )
    for record in records:
        account = record.first_text("sAMAccountName") or _rdn(record)
        enabled = not bool(_integer(record, "userAccountControl") & _UAC_DISABLED)
        hostname = record.first_text("dNSHostName")
        add_computer(
            AdComputer(
                account_name=account,
                hostname=hostname,
                operating_system=record.first_text("operatingSystem"),
                enabled=enabled,
            )
        )
        readable = next(
            (
                label
                for attribute, label in (
                    ("msLAPS-Password", "Windows LAPS"),
                    ("ms-Mcs-AdmPwd", "Eski LAPS"),
                )
                if record.has_nonempty(attribute)
            ),
            None,
        )
        if readable is not None:
            add_finding(
                AdFinding(
                    check_id="laps_readable",
                    lane=AdFindingLane.CAPABILITY,
                    evidence_state=AdEvidenceState.VERIFIED,
                    severity=AdSeverity.CRITICAL,
                    title="Yerel yönetici parolası okunabiliyor",
                    summary=(
                        "Bu kimliğin bilgisayar nesnesindeki LAPS parola özniteliğini "
                        "okuyabildiği doğrulandı. Parola sonuçlara alınmadı."
                    ),
                    subject=hostname or account,
                    evidence=(f"Kaynak: {readable}",),
                    next_step=(
                        "Yetkili test kapsamında bu hosttaki yerel yönetici "
                        "erişimini doğrula."
                    ),
                )
            )
    return AdCoverage(
        check_id="computers_laps",
        label="Bilgisayarlar ve LAPS görünürlüğü",
        state=AdCoverageState.COMPLETED,
        records_seen=len(records),
    )


def _inspect_gmsa(client: DirectoryClient, add_finding: FindingCallback) -> AdCoverage:
    records = client.search(
        "(objectClass=msDS-GroupManagedServiceAccount)",
        ("sAMAccountName", "msDS-ManagedPassword"),
    )
    for record in records:
        if not record.has_nonempty("msDS-ManagedPassword"):
            continue
        add_finding(
            AdFinding(
                check_id="gmsa_password_readable",
                lane=AdFindingLane.CAPABILITY,
                evidence_state=AdEvidenceState.VERIFIED,
                severity=AdSeverity.CRITICAL,
                title="gMSA parola verisi okunabiliyor",
                summary=(
                    "Bu kimliğin gMSA yönetilen parola özniteliğini okuyabildiği "
                    "doğrulandı. Parola verisi sonuçlara alınmadı."
                ),
                subject=record.first_text("sAMAccountName") or _rdn(record),
                next_step="Hesabın bağlı olduğu servisleri ve erişim kapsamını doğrula.",
            )
        )
    return AdCoverage(
        check_id="gmsa_passwords",
        label="gMSA parola görünürlüğü",
        state=AdCoverageState.COMPLETED,
        records_seen=len(records),
    )


def _inspect_kerberoast(client: DirectoryClient, add_finding: FindingCallback) -> AdCoverage:
    records = client.search(
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ("sAMAccountName", "servicePrincipalName", "adminCount", "pwdLastSet"),
    )
    for record in records:
        account = record.first_text("sAMAccountName") or _rdn(record)
        evidence = [f"SPN sayısı: {len(record.text_values('servicePrincipalName'))}"]
        if record.first_text("adminCount") == "1":
            evidence.append("Korunan/yüksek yetkili hesap göstergesi: adminCount=1")
        add_finding(
            AdFinding(
                check_id="kerberoast_candidate",
                lane=AdFindingLane.CAPABILITY,
                evidence_state=AdEvidenceState.INFERRED,
                severity=AdSeverity.HIGH,
                title="Kerberoast adayı görüldü",
                summary=(
                    "Etkin kullanıcı hesabında SPN bulundu. Bu tarama servis bileti "
                    "istemedi; kullanılabilirlik LDAP verisinden çıkarıldı."
                ),
                subject=account,
                evidence=tuple(evidence),
                next_step="Yetkili testte servis bileti isteğini ayrıca doğrula.",
            )
        )
    return AdCoverage(
        check_id="kerberoast",
        label="Kerberoast adayları",
        state=AdCoverageState.COMPLETED,
        records_seen=len(records),
    )


def _inspect_asrep(client: DirectoryClient, add_finding: FindingCallback) -> AdCoverage:
    records = client.search(
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ("sAMAccountName", "adminCount", "pwdLastSet"),
    )
    for record in records:
        add_finding(
            AdFinding(
                check_id="asrep_candidate",
                lane=AdFindingLane.CAPABILITY,
                evidence_state=AdEvidenceState.INFERRED,
                severity=AdSeverity.HIGH,
                title="AS-REP roast adayı görüldü",
                summary=(
                    "Hesapta Kerberos ön kimlik doğrulaması gerekmiyor. Bu tarama "
                    "AS-REP istemedi; kullanılabilirlik LDAP verisinden çıkarıldı."
                ),
                subject=record.first_text("sAMAccountName") or _rdn(record),
                next_step="Yetkili testte AS-REP isteğini ayrıca doğrula.",
            )
        )
    return AdCoverage(
        check_id="asrep",
        label="AS-REP roast adayları",
        state=AdCoverageState.COMPLETED,
        records_seen=len(records),
    )


def _inspect_delegation(client: DirectoryClient, add_finding: FindingCallback) -> AdCoverage:
    records = client.search(
        "(&(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
        "(msDS-AllowedToDelegateTo=*)"
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        (
            "sAMAccountName",
            "userAccountControl",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ),
    )
    for record in records:
        uac = _integer(record, "userAccountControl")
        types: list[str] = []
        if uac & _UAC_TRUSTED_FOR_DELEGATION:
            types.append("Kısıtsız delegasyon")
        if record.has_nonempty("msDS-AllowedToDelegateTo"):
            label = (
                "Protokol geçişli kısıtlı delegasyon"
                if uac & _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION
                else "Kısıtlı delegasyon"
            )
            types.append(label)
        if record.has_nonempty("msDS-AllowedToActOnBehalfOfOtherIdentity"):
            types.append("Kaynak tabanlı kısıtlı delegasyon")
        if not types:
            continue
        add_finding(
            AdFinding(
                check_id="delegation_configuration",
                lane=AdFindingLane.ENVIRONMENT,
                evidence_state=AdEvidenceState.OBSERVED,
                severity=(
                    AdSeverity.HIGH
                    if "Kısıtsız delegasyon" in types
                    else AdSeverity.MEDIUM
                ),
                title="Delegasyon yapılandırması görüldü",
                summary="Hesap veya bilgisayar nesnesinde Kerberos delegasyonu yapılandırılmış.",
                subject=record.first_text("sAMAccountName") or _rdn(record),
                evidence=tuple(types),
                next_step=(
                    "Nesnenin sahiplerini, bağlı servisleri ve delegasyon "
                    "hedeflerini incele."
                ),
            )
        )
    return AdCoverage(
        check_id="delegation",
        label="Kerberos delegasyonu",
        state=AdCoverageState.COMPLETED,
        records_seen=len(records),
    )


def _inspect_domain_policy(
    client: DirectoryClient,
    identity: AdIdentity,
    add_finding: FindingCallback,
) -> AdCoverage:
    records = client.search(
        "(objectClass=domainDNS)",
        (
            "minPwdLength",
            "pwdHistoryLength",
            "lockoutThreshold",
            "maxPwdAge",
            "ms-DS-MachineAccountQuota",
        ),
        search_base=domain_to_base_dn(identity.domain),
        base_object=True,
    )
    if not records:
        return AdCoverage(
            check_id="domain_policy",
            label="Domain parola ve makine hesabı ayarları",
            state=AdCoverageState.PARTIAL,
            message="Domain nesnesi görünür değildi.",
        )
    record = records[0]
    minimum = _integer(record, "minPwdLength")
    lockout = _integer(record, "lockoutThreshold")
    quota = _integer(record, "ms-DS-MachineAccountQuota")
    if quota > 0:
        add_finding(
            AdFinding(
                check_id="machine_account_quota",
                lane=AdFindingLane.CAPABILITY,
                evidence_state=AdEvidenceState.INFERRED,
                severity=AdSeverity.MEDIUM,
                title="Makine hesabı oluşturma kotası açık",
                summary=(
                    "Domain varsayılan makine hesabı kotası sıfırdan büyük. Bu kimlik "
                    "için nesne oluşturma işlemi yapılmadı; yetenek yapılandırmadan çıkarıldı."
                ),
                subject=identity.domain,
                evidence=(f"ms-DS-MachineAccountQuota: {quota}",),
                next_step=(
                    "Yetki yollarıyla birleşip birleşmediğini incele; üretimde "
                    "nesne oluşturma."
                ),
            )
        )
    observations: list[str] = []
    if minimum and minimum < 14:
        observations.append(f"Minimum parola uzunluğu: {minimum}")
    if lockout == 0:
        observations.append("Hesap kilitleme eşiği: 0")
    if observations:
        add_finding(
            AdFinding(
                check_id="domain_password_policy",
                lane=AdFindingLane.ENVIRONMENT,
                evidence_state=AdEvidenceState.OBSERVED,
                severity=AdSeverity.MEDIUM,
                title="Zayıf domain parola ayarı görüldü",
                summary="Domain nesnesindeki parola ilkeleri zayıf ayarlar içeriyor.",
                subject=identity.domain,
                evidence=tuple(observations),
                next_step="Fine-grained password policy nesnelerini de ayrıca karşılaştır.",
            )
        )
    return AdCoverage(
        check_id="domain_policy",
        label="Domain parola ve makine hesabı ayarları",
        state=AdCoverageState.COMPLETED,
        records_seen=1,
    )


def _integer(record: DirectoryRecord, name: str) -> int:
    try:
        return int(record.first_text(name) or "0")
    except ValueError:
        return 0


def _optional_integer(record: DirectoryRecord, name: str) -> int | None:
    value = record.first_text(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _sid(record: DirectoryRecord) -> str | None:
    values = record.values("objectSid")
    if not values:
        return None
    try:
        from impacket.ldap.ldaptypes import LDAP_SID

        return LDAP_SID(data=values[0]).formatCanonical()
    except Exception:
        return None


def _primary_group_sid(identity: AdIdentity) -> str | None:
    if identity.sid is None or identity.primary_group_id is None or "-" not in identity.sid:
        return None
    domain_sid, _separator, _rid = identity.sid.rpartition("-")
    return f"{domain_sid}-{identity.primary_group_id}" if domain_sid else None


def _rdn(record: DirectoryRecord) -> str:
    return record.distinguished_name.partition(",")[0].partition("=")[2] or "Bilinmeyen nesne"
