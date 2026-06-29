"""Conservative, single-token evaluation of immediate AD object capabilities."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_DENIED_ACE,
    ACCESS_DENIED_OBJECT_ACE,
    ACCESS_MASK,
    ACE,
    OBJECTTYPE_GUID_MAP,
    SR_SECURITY_DESCRIPTOR,
)
from impacket.msada_guids import EXTENDED_RIGHTS, SCHEMA_OBJECTS
from impacket.uuid import bin_to_string

from .directory import DirectoryAccessError, DirectoryClient, DirectoryRecord
from .inspection import CapabilityCallback, IdentityAccessCancellation
from .models import (
    AccessCapability,
    CapabilityKind,
    Coverage,
    CoverageState,
    DirectoryIdentity,
    EvidenceState,
)

_OWNER_AND_DACL_SECURITY_INFORMATION = 0x1 | 0x4
_AUTHENTICATED_USERS_SID = "S-1-5-11"
_EVERYONE_SID = "S-1-1-0"
_ALLOW_ACE_TYPES = frozenset(
    (ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE)
)
_DENY_ACE_TYPES = frozenset(
    (ACCESS_DENIED_ACE.ACE_TYPE, ACCESS_DENIED_OBJECT_ACE.ACE_TYPE)
)
_OBJECT_ACE_TYPES = frozenset(
    (ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE, ACCESS_DENIED_OBJECT_ACE.ACE_TYPE)
)
_OBJECT_CLASS_GUIDS = {
    **OBJECTTYPE_GUID_MAP,
    b"computer": "bf967a86-0de6-11d0-a285-00aa003049e2",
    b"domainDNS": "19195a5b-6da0-11d0-afd3-00c04fd930c9",
}
_DIRECTORY_WRITE_MASK = (
    ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD
    | ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD
    | ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
    | ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF
    | ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
)
_DANGEROUS_MASK = (
    ACCESS_MASK.GENERIC_ALL
    | ACCESS_MASK.GENERIC_WRITE
    | ACCESS_MASK.WRITE_DACL
    | ACCESS_MASK.WRITE_OWNER
    | ACCESS_MASK.DELETE
    | _DIRECTORY_WRITE_MASK
)
_PROPERTY_CAPABILITIES = {
    "Member": CapabilityKind.GROUP_MEMBERSHIP_WRITE,
    "Service-Principal-Name": CapabilityKind.AUTHENTICATION_MATERIAL_WRITE,
    "User-Account-Control": CapabilityKind.AUTHENTICATION_MATERIAL_WRITE,
    "ms-DS-Key-Credential-Link": CapabilityKind.AUTHENTICATION_MATERIAL_WRITE,
    "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity": (
        CapabilityKind.DELEGATION_WRITE
    ),
}
_EXTENDED_CAPABILITIES = {
    "User-Force-Change-Password": CapabilityKind.PASSWORD_RESET,
    "Self-Membership": CapabilityKind.GROUP_MEMBERSHIP_WRITE,
    "DS-Replication-Get-Changes": CapabilityKind.SECRET_READ,
    "DS-Replication-Get-Changes-All": CapabilityKind.SECRET_READ,
    "DS-Replication-Get-Changes-In-Filtered-Set": CapabilityKind.SECRET_READ,
}
_REPLICATION_REQUIRED = frozenset(
    ("DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All")
)


@dataclass(frozen=True, slots=True)
class _Right:
    kind: CapabilityKind
    label: str


def inspect_direct_acl_capabilities(
    client: DirectoryClient,
    identity: DirectoryIdentity,
    cancellation: IdentityAccessCancellation,
    add_capability: CapabilityCallback,
) -> Coverage:
    """Report direct token-matched rights; never execute a directory write."""

    if not identity.token_complete:
        return Coverage(
            check_id="direct_acl_capabilities",
            label="Doğrudan directory yetkileri",
            state=CoverageState.NOT_CHECKED,
            message=(
                "Etkin grup tokenı tamamlanamadığı için ACL yetkileri güvenli "
                "biçimde değerlendirilemedi."
            ),
        )

    sid_names = {
        identity.sid: identity.principal,
        _AUTHENTICATED_USERS_SID: "Authenticated Users",
        _EVERYONE_SID: "Everyone",
        **{group.sid: group.name for group in identity.groups},
    }
    token_sids = frozenset(sid_names)
    try:
        query = client.search(
            "(|(&(objectCategory=person)(objectClass=user))(objectCategory=group)"
            "(objectCategory=computer)(objectClass=groupPolicyContainer)"
            "(objectClass=organizationalUnit)(objectClass=domainDNS))",
            (
                "name",
                "displayName",
                "sAMAccountName",
                "dNSHostName",
                "objectClass",
                "nTSecurityDescriptor",
            ),
            security_descriptor_flags=_OWNER_AND_DACL_SECURITY_INFORMATION,
        )
    except DirectoryAccessError as error:
        return Coverage(
            check_id="direct_acl_capabilities",
            label="Doğrudan directory yetkileri",
            state=CoverageState.NOT_CHECKED,
            message=error.safe_message,
        )

    inconclusive = 0
    for record in query:
        cancellation.raise_if_requested()
        descriptor_values = record.values("nTSecurityDescriptor")
        if not descriptor_values:
            inconclusive += 1
            continue
        try:
            descriptor = SR_SECURITY_DESCRIPTOR(data=descriptor_values[0])
        except Exception:
            inconclusive += 1
            continue

        dacl = descriptor["Dacl"]
        aces = getattr(dacl, "aces", None)
        if aces is None or _has_ambiguous_deny_or_ace(aces, token_sids, record):
            inconclusive += 1
            continue

        grants: list[tuple[_Right, str]] = []
        owner_sid = _descriptor_owner_sid(descriptor)
        if owner_sid == identity.sid:
            grants.append(
                (
                    _Right(
                        CapabilityKind.OBJECT_CONTROL,
                        "Nesne sahibi (implicit WriteDACL)",
                    ),
                    owner_sid,
                )
            )
        for ace in aces:
            if ace["AceType"] not in _ALLOW_ACE_TYPES or not _ace_applies(ace, record):
                continue
            trustee_sid = _ace_sid(ace)
            if trustee_sid not in token_sids:
                continue
            grants.extend(
                (right, trustee_sid) for right in _rights_from_ace(ace, record)
            )

        _publish_record_capabilities(
            record,
            grants,
            sid_names=sid_names,
            add_capability=add_capability,
        )

    messages: list[str] = []
    if not query.complete:
        messages.append("ACL sorgusu sonuç sınırına ulaştı")
    if inconclusive:
        messages.append(
            f"{inconclusive} nesnede descriptor, deny veya conditional ACE "
            "nedeniyle etkili hak kesinleştirilemedi"
        )
    return Coverage(
        check_id="direct_acl_capabilities",
        label="Doğrudan directory yetkileri",
        state=CoverageState.PARTIAL if messages else CoverageState.COMPLETED,
        records_seen=len(query),
        message="; ".join(messages) + "." if messages else None,
    )


def _publish_record_capabilities(
    record: DirectoryRecord,
    grants: list[tuple[_Right, str]],
    *,
    sid_names: dict[str, str],
    add_capability: CapabilityCallback,
) -> None:
    grouped: dict[tuple[CapabilityKind, str], set[str]] = defaultdict(set)
    for right, trustee_sid in grants:
        grouped[(right.kind, trustee_sid)].add(right.label)

    subject = _subject(record)
    object_kind = _object_kind(record)
    for (kind, trustee_sid), labels in sorted(
        grouped.items(), key=lambda item: (item[0][0].value, item[0][1])
    ):
        if kind is CapabilityKind.SECRET_READ and not _REPLICATION_REQUIRED.issubset(
            labels
        ):
            continue
        ordered_labels = tuple(sorted(labels, key=str.casefold))
        via = sid_names.get(trustee_sid, trustee_sid)
        add_capability(
            AccessCapability(
                capability_id=_capability_id(kind),
                kind=kind,
                evidence_state=EvidenceState.INFERRED,
                title=_capability_title(kind),
                summary=(
                    f"{via} SID'siyle eşleşen allow ACE, {object_kind} nesnesinde "
                    "doğrudan kullanılabilecek bir hak gösteriyor. Hiçbir değişiklik "
                    "yapılmadı."
                ),
                subject=subject,
                via_principal=via,
                rights=ordered_labels,
                next_step=_next_step(kind, subject),
            )
        )


def _rights_from_ace(ace: object, record: DirectoryRecord) -> tuple[_Right, ...]:
    mask = _ace_mask(ace)
    object_guid = _ace_object_guid(ace)
    rights: list[_Right] = []

    if object_guid is None:
        if mask & ACCESS_MASK.GENERIC_ALL:
            return (_Right(CapabilityKind.OBJECT_CONTROL, "Tam kontrol (GenericAll)"),)
        if mask & ACCESS_MASK.GENERIC_WRITE:
            rights.append(
                _Right(CapabilityKind.OBJECT_CONTROL, "Genel yazma (GenericWrite)")
            )
        if mask & ACCESS_MASK.WRITE_DACL:
            rights.append(_Right(CapabilityKind.OBJECT_CONTROL, "DACL değiştirme"))
        if mask & ACCESS_MASK.WRITE_OWNER:
            rights.append(_Right(CapabilityKind.OBJECT_CONTROL, "Sahip değiştirme"))
        if mask & ACCESS_MASK.DELETE:
            rights.append(_Right(CapabilityKind.OBJECT_CONTROL, "Nesneyi silme"))
        if mask & ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD:
            rights.append(_Right(CapabilityKind.OBJECT_CONTROL, "Alt nesne oluşturma"))
        if mask & ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD:
            rights.append(_Right(CapabilityKind.OBJECT_CONTROL, "Alt nesne silme"))
        if mask & ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP:
            rights.append(_Right(CapabilityKind.OBJECT_CONTROL, "Tüm özellikleri yazma"))
        if mask & ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS:
            rights.append(
                _Right(CapabilityKind.OBJECT_CONTROL, "Tüm extended rights")
            )
        return tuple(rights)

    if mask & ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP:
        property_name = SCHEMA_OBJECTS.get(object_guid)
        kind = _PROPERTY_CAPABILITIES.get(property_name or "")
        if kind is not None and _property_applies(property_name or "", record):
            rights.append(_Right(kind, property_name or object_guid))
    if mask & (
        ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
        | ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF
    ):
        extended_name = EXTENDED_RIGHTS.get(object_guid)
        kind = _EXTENDED_CAPABILITIES.get(extended_name or "")
        if kind is not None and _extended_right_applies(extended_name or "", record):
            rights.append(_Right(kind, extended_name or object_guid))
    if mask & ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD:
        rights.append(
            _Right(
                CapabilityKind.OBJECT_CONTROL,
                f"Alt nesne oluşturma ({SCHEMA_OBJECTS.get(object_guid, object_guid)})",
            )
        )
    if mask & ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD:
        rights.append(
            _Right(
                CapabilityKind.OBJECT_CONTROL,
                f"Alt nesne silme ({SCHEMA_OBJECTS.get(object_guid, object_guid)})",
            )
        )
    return tuple(rights)


def _property_applies(property_name: str, record: DirectoryRecord) -> bool:
    object_classes = {value.casefold() for value in record.text_values("objectClass")}
    if property_name == "Member":
        return "group" in object_classes
    if property_name in {"Service-Principal-Name", "User-Account-Control"}:
        return "user" in object_classes or "computer" in object_classes
    if property_name == "ms-DS-Key-Credential-Link":
        return "user" in object_classes or "computer" in object_classes
    if property_name == "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity":
        return "computer" in object_classes or "domaindns" in object_classes
    return True


def _extended_right_applies(name: str, record: DirectoryRecord) -> bool:
    object_classes = {value.casefold() for value in record.text_values("objectClass")}
    if name == "Self-Membership":
        return "group" in object_classes
    if name == "User-Force-Change-Password":
        return "user" in object_classes or "computer" in object_classes
    if name.startswith("DS-Replication-"):
        return "domaindns" in object_classes or "domain" in object_classes
    return True


def _has_ambiguous_deny_or_ace(
    aces: object,
    token_sids: frozenset[str],
    record: DirectoryRecord,
) -> bool:
    for ace in aces:
        if not _ace_applies(ace, record) or _ace_sid(ace) not in token_sids:
            continue
        ace_type = ace["AceType"]
        if ace_type in _DENY_ACE_TYPES and _rights_from_ace(ace, record):
            return True
        if (
            ace_type not in _ALLOW_ACE_TYPES | _DENY_ACE_TYPES
            and _ace_mask(ace) & _DANGEROUS_MASK
        ):
            return True
    return False


def _ace_applies(ace: object, record: DirectoryRecord) -> bool:
    if ace.hasFlag(ACE.INHERIT_ONLY_ACE):
        return False
    if (
        ace["AceType"] in _OBJECT_ACE_TYPES
        and ace.hasFlag(ACE.INHERITED_ACE)
        and ace["Ace"].hasFlag(
            ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT
        )
    ):
        object_classes = record.text_values("objectClass")
        if not object_classes:
            return False
        expected = _OBJECT_CLASS_GUIDS.get(object_classes[-1].encode())
        inherited = bin_to_string(ace["Ace"]["InheritedObjectType"]).lower()
        return expected == inherited
    return True


def _descriptor_owner_sid(descriptor: SR_SECURITY_DESCRIPTOR) -> str | None:
    owner = descriptor["OwnerSid"]
    if owner in (b"", ""):
        return None
    try:
        return owner.formatCanonical()
    except Exception:
        return None


def _ace_sid(ace: object) -> str | None:
    try:
        return ace["Ace"]["Sid"].formatCanonical()
    except Exception:
        return None


def _ace_mask(ace: object) -> int:
    try:
        return int(ace["Ace"]["Mask"]["Mask"])
    except Exception:
        return 0


def _ace_object_guid(ace: object) -> str | None:
    if ace["AceType"] not in _OBJECT_ACE_TYPES:
        return None
    body = ace["Ace"]
    if not body.hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
        return None
    try:
        return bin_to_string(body["ObjectType"]).lower()
    except Exception:
        return None


def _subject(record: DirectoryRecord) -> str:
    return (
        record.first_text("dNSHostName")
        or record.first_text("sAMAccountName")
        or record.first_text("displayName")
        or record.first_text("name")
        or record.distinguished_name.partition(",")[0].partition("=")[2]
        or "Bilinmeyen"
    )


def _object_kind(record: DirectoryRecord) -> str:
    values = record.text_values("objectClass")
    return values[-1] if values else "directory"


def _capability_id(kind: CapabilityKind) -> str:
    return {
        CapabilityKind.SECRET_READ: "directory_replication_read",
        CapabilityKind.PASSWORD_RESET: "password_reset",
        CapabilityKind.GROUP_MEMBERSHIP_WRITE: "group_membership_write",
        CapabilityKind.OBJECT_CONTROL: "object_control",
        CapabilityKind.AUTHENTICATION_MATERIAL_WRITE: "authentication_material_write",
        CapabilityKind.DELEGATION_WRITE: "delegation_write",
    }[kind]


def _capability_title(kind: CapabilityKind) -> str:
    return {
        CapabilityKind.SECRET_READ: "Domain parola verisi çoğaltılabilir",
        CapabilityKind.PASSWORD_RESET: "Hesap parolası sıfırlanabilir",
        CapabilityKind.GROUP_MEMBERSHIP_WRITE: "Grup üyeliği değiştirilebilir",
        CapabilityKind.OBJECT_CONTROL: "Directory nesnesi kontrol edilebilir",
        CapabilityKind.AUTHENTICATION_MATERIAL_WRITE: (
            "Kimlik doğrulama verisi değiştirilebilir"
        ),
        CapabilityKind.DELEGATION_WRITE: "Delegasyon verisi değiştirilebilir",
    }[kind]


def _next_step(kind: CapabilityKind, subject: str) -> str:
    return {
        CapabilityKind.SECRET_READ: (
            "Yetkili kapsamda replication hakkının iki gerekli extended right ile "
            "verildiğini bağımsız olarak doğrula."
        ),
        CapabilityKind.PASSWORD_RESET: (
            f"{subject} hesabının erişim kapsamını incele; Nordis parola değiştirmedi."
        ),
        CapabilityKind.GROUP_MEMBERSHIP_WRITE: (
            f"{subject} üyeliğinin sağladığı erişimleri incele; Nordis üyelik değiştirmedi."
        ),
        CapabilityKind.OBJECT_CONTROL: (
            f"{subject} üzerindeki ACE kapsamını doğrula; Nordis nesneyi değiştirmedi."
        ),
        CapabilityKind.AUTHENTICATION_MATERIAL_WRITE: (
            f"{subject} için yazılabilen özelliğin hesap etkisini doğrula."
        ),
        CapabilityKind.DELEGATION_WRITE: (
            f"{subject} için delegasyon hedefi ve olası erişim kapsamını doğrula."
        ),
    }[kind]
