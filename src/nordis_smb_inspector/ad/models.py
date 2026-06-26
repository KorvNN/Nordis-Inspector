"""Secret-safe models for Active Directory inspection results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class AdFindingLane(StrEnum):
    CAPABILITY = "capability"
    ENVIRONMENT = "environment"


class AdEvidenceState(StrEnum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    OBSERVED = "observed"


class AdSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AdCoverageState(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    NOT_CHECKED = "not_checked"


@dataclass(frozen=True, slots=True, repr=False)
class AdIdentity:
    principal: str
    distinguished_name: str
    domain: str
    sid: str | None = None
    primary_group_id: int | None = field(default=None, repr=False)
    groups: tuple[str, ...] = field(default_factory=tuple, repr=False)

    def public_payload(self) -> dict[str, object]:
        return {
            "principal": self.principal,
            "distinguished_name": self.distinguished_name,
            "domain": self.domain,
            "sid": self.sid,
            "groups": list(self.groups),
        }

    def __repr__(self) -> str:
        return f"AdIdentity(principal={self.principal!r}, groups={len(self.groups)!r})"


@dataclass(frozen=True, slots=True)
class AdComputer:
    account_name: str
    hostname: str | None
    operating_system: str | None
    enabled: bool

    def public_payload(self) -> dict[str, object]:
        return {
            "account_name": self.account_name,
            "hostname": self.hostname,
            "operating_system": self.operating_system,
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True, repr=False)
class AdFinding:
    check_id: str
    lane: AdFindingLane
    evidence_state: AdEvidenceState
    severity: AdSeverity
    title: str
    summary: str
    subject: str | None = None
    evidence: tuple[str, ...] = field(default_factory=tuple, repr=False)
    next_step: str | None = None

    def public_payload(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "lane": self.lane.value,
            "evidence_state": self.evidence_state.value,
            "severity": self.severity.value,
            "title": self.title,
            "summary": self.summary,
            "subject": self.subject,
            "evidence": list(self.evidence),
            "next_step": self.next_step,
        }

    def __repr__(self) -> str:
        return (
            f"AdFinding(check_id={self.check_id!r}, lane={self.lane.value!r}, "
            f"evidence_state={self.evidence_state.value!r}, subject={self.subject!r})"
        )


@dataclass(frozen=True, slots=True)
class AdCoverage:
    check_id: str
    label: str
    state: AdCoverageState
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
class AdInspectionReport:
    identity: AdIdentity
    authentication_method: str
    computers: tuple[AdComputer, ...] = field(default_factory=tuple, repr=False)
    findings: tuple[AdFinding, ...] = field(default_factory=tuple, repr=False)
    coverage: tuple[AdCoverage, ...] = field(default_factory=tuple, repr=False)

    def __repr__(self) -> str:
        return (
            f"AdInspectionReport(identity={self.identity.principal!r}, "
            f"computers={len(self.computers)!r}, findings={len(self.findings)!r})"
        )
