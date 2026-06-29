"""Secret-free contracts for one supplied identity's directory capabilities."""

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
            "partial": self.partial,
        }

    def __repr__(self) -> str:
        return (
            f"IdentityAccessReport(controller={self.controller!r}, "
            f"identity={self.identity.principal!r}, "
            f"capabilities={len(self.capabilities)!r}, partial={self.partial!r})"
        )
