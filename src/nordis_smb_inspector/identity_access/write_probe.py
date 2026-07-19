"""Opt-in, non-persistent LDAP write probes for ACL-backed capabilities."""

from __future__ import annotations

from dataclasses import replace
from typing import Protocol
from uuid import uuid4

from .directory import DirectoryAccessError, DirectoryClient
from .models import AccessCapability, DirectoryIdentity, EvidenceState

_DIRECT_ATTRIBUTE_PROBES = {
    "spn_write": "servicePrincipalName",
    "object_full_control": "description",
    "object_property_write": "description",
}


class WriteProbeCancellation(Protocol):
    def raise_if_requested(self) -> None: ...


def verify_write_capabilities(
    client: DirectoryClient,
    identity: DirectoryIdentity,
    capabilities: tuple[AccessCapability, ...],
    cancellation: WriteProbeCancellation,
) -> tuple[AccessCapability, ...]:
    """Actively check supported writes without changing an attribute value."""

    probe_id = uuid4().hex
    results: dict[tuple[str, str, str], tuple[EvidenceState, str]] = {}
    verified: list[AccessCapability] = []
    for capability in capabilities:
        cancellation.raise_if_requested()
        if capability.evidence_state is not EvidenceState.ACL_INDICATED or not capability.target_dn:
            verified.append(capability)
            continue
        probe = _probe_for_capability(client, identity, capability, probe_id)
        if probe is None:
            verified.append(capability)
            continue
        attribute, absent_value = probe
        key = (capability.target_dn, attribute, absent_value)
        result = results.get(key)
        if result is None:
            result = _run_probe(
                client,
                capability.target_dn,
                attribute,
                absent_value,
            )
            results[key] = result
        state, summary = result
        verified.append(
            replace(
                capability,
                evidence_state=state,
                summary=summary,
            )
        )
    return tuple(verified)


def _probe_for_capability(
    client: DirectoryClient,
    identity: DirectoryIdentity,
    capability: AccessCapability,
    probe_id: str,
) -> tuple[str, str] | None:
    attribute = _DIRECT_ATTRIBUTE_PROBES.get(capability.capability_id)
    if attribute == "servicePrincipalName":
        return attribute, f"nordis-write-probe/{probe_id}"
    if attribute == "description":
        return attribute, f"nordis-write-probe-{probe_id}"
    if capability.capability_id != "group_membership_write":
        return None

    # Deleting the supplied identity DN is a safe no-op only while it is not an
    # existing direct member. Nested membership does not appear in this value.
    try:
        current = client.search(
            "(objectClass=*)",
            ("member",),
            search_base=capability.target_dn,
            base_object=True,
            record_limit=1,
        )
    except DirectoryAccessError:
        return None
    if len(current.records) != 1:
        return None
    direct_members = {value.casefold() for value in current.records[0].text_values("member")}
    if identity.distinguished_name.casefold() in direct_members:
        return None
    return "member", identity.distinguished_name


def _run_probe(
    client: DirectoryClient,
    distinguished_name: str,
    attribute: str,
    absent_value: str,
) -> tuple[EvidenceState, str]:
    try:
        accepted = client.probe_attribute_write(
            distinguished_name,
            attribute,
            absent_value,
        )
    except (DirectoryAccessError, AttributeError):
        return (
            EvidenceState.UNRESOLVED,
            "ACL bu eylemi işaret ediyor ancak LDAP yazma denemesi kesinleştirilemedi.",
        )
    if not accepted:
        return (
            EvidenceState.UNRESOLVED,
            "ACL bu eylemi işaret ediyor ancak domain controller yazma isteğini reddetti.",
        )
    return (
        EvidenceState.VERIFIED,
        "Domain controller LDAP yazma isteğini kabul etti. Kalıcı directory değişikliği yapılmadı.",
    )
