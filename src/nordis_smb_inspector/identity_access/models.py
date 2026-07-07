"""Contracts for one supplied identity's directory access and visible text."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvidenceState(StrEnum):
    """How Nordis established a capability without changing directory state."""

    VERIFIED = "verified"
    INFERRED = "inferred"


class CoverageState(StrEnum):
    """Whether a bounded capability check reached a conclusive end."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    NOT_CHECKED = "not_checked"


class CapabilityKind(StrEnum):
    """Immediate capability classes; these are not domain-health findings."""

    SECRET_READ = "secret_read"
    PASSWORD_RESET = "password_reset"
    GROUP_MEMBERSHIP_WRITE = "group_membership_write"
    OBJECT_CONTROL = "object_control"
    AUTHENTICATION_MATERIAL_WRITE = "authentication_material_write"
    DELEGATION_WRITE = "delegation_write"


@dataclass(frozen=True, slots=True)
class DirectoryTextSignal:
    """One non-authoritative marker attached to readable LDAP text."""

    rule_id: str
    title: str
    category: str
    confidence: str
    line_number: int

    def public_payload(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "confidence": self.confidence,
            "line_number": self.line_number,
        }


@dataclass(frozen=True, slots=True, repr=False)
class DirectoryTextEntry:
    """One readable LDAP text value retained only in the live server process."""

    distinguished_name: str
    subject: str
    subject_type: str
    attribute: str
    value: str = field(repr=False)
    signals: tuple[DirectoryTextSignal, ...] = field(default_factory=tuple)

    @property
    def flagged(self) -> bool:
        return bool(self.signals)

    def metadata_payload(self) -> dict[str, object]:
        """Return filterable metadata without copying the raw value."""

        return {
            "distinguished_name": self.distinguished_name,
            "subject": self.subject,
            "subject_type": self.subject_type,
            "attribute": self.attribute,
            "size": len(self.value.encode("utf-8")),
            "flagged": self.flagged,
            "signals": [signal.public_payload() for signal in self.signals],
        }

    def __repr__(self) -> str:
        return (
            f"DirectoryTextEntry(subject={self.subject!r}, "
            f"subject_type={self.subject_type!r}, attribute={self.attribute!r}, "
            f"value=<redacted {len(self.value)} chars>, signals={len(self.signals)!r})"
        )


@dataclass(frozen=True, slots=True)
class IdentityGroup:
    name: str
    sid: str

    def public_payload(self) -> dict[str, str]:
        return {"name": self.name, "sid": self.sid}


@dataclass(frozen=True, slots=True, repr=False)
class DirectoryIdentity:
    principal: str
    distinguished_name: str
    domain: str
    sid: str
    groups: tuple[IdentityGroup, ...] = field(default_factory=tuple, repr=False)
    token_complete: bool = field(default=True, repr=False)

    @property
    def token_sids(self) -> frozenset[str]:
        return frozenset((self.sid, *(group.sid for group in self.groups)))

    def public_payload(self) -> dict[str, object]:
        return {
            "principal": self.principal,
            "distinguished_name": self.distinguished_name,
            "domain": self.domain,
            "sid": self.sid,
            "groups": [group.public_payload() for group in self.groups],
        }

    def __repr__(self) -> str:
        return (
            f"DirectoryIdentity(principal={self.principal!r}, "
            f"groups={len(self.groups)!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class AccessCapability:
    capability_id: str
    kind: CapabilityKind
    evidence_state: EvidenceState
    title: str
    summary: str
    subject: str
    subject_type: str | None = None
    via_principal: str | None = None
    rights: tuple[str, ...] = field(default_factory=tuple, repr=False)
    next_step: str | None = None

    def public_payload(self) -> dict[str, object]:
        return {
            "capability_id": self.capability_id,
            "kind": self.kind.value,
            "evidence_state": self.evidence_state.value,
            "title": self.title,
            "summary": self.summary,
            "subject": self.subject,
            "subject_type": self.subject_type,
            "via_principal": self.via_principal,
            "rights": list(self.rights),
            "next_step": self.next_step,
        }

    def __repr__(self) -> str:
        return (
            f"AccessCapability(capability_id={self.capability_id!r}, "
            f"kind={self.kind.value!r}, evidence_state={self.evidence_state.value!r}, "
            f"subject={self.subject!r})"
        )


@dataclass(frozen=True, slots=True)
class Coverage:
    check_id: str
    label: str
    state: CoverageState
    records_seen: int = 0
    message: str | None = None

    def public_payload(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "state": self.state.value,
            "records_seen": self.records_seen,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True, repr=False)
class IdentityAccessReport:
    controller: str
    authentication_method: str
    identity: DirectoryIdentity
    capabilities: tuple[AccessCapability, ...] = field(default_factory=tuple, repr=False)
    coverage: tuple[Coverage, ...] = field(default_factory=tuple, repr=False)
    directory_text: tuple[DirectoryTextEntry, ...] = field(
        default_factory=tuple,
        repr=False,
    )

    @property
    def partial(self) -> bool:
        return any(item.state is not CoverageState.COMPLETED for item in self.coverage)

    def public_payload(self) -> dict[str, object]:
        return {
            "controller": self.controller,
            "authentication_method": self.authentication_method,
            "identity": self.identity.public_payload(),
            "capabilities": [item.public_payload() for item in self.capabilities],
            "coverage": [item.public_payload() for item in self.coverage],
            "directory_text_count": len(self.directory_text),
            "flagged_directory_text_count": sum(
                item.flagged for item in self.directory_text
            ),
            "partial": self.partial,
        }

    def __repr__(self) -> str:
        return (
            f"IdentityAccessReport(controller={self.controller!r}, "
            f"identity={self.identity.principal!r}, "
            f"capabilities={len(self.capabilities)!r}, partial={self.partial!r})"
        )
