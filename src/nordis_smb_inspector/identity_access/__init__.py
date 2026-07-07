"""Principal-scoped directory access evidence for Nordis Inspector."""

from .directory import (
    DirectoryAccessError,
    DirectoryClient,
    DirectoryQuery,
    DirectoryRecord,
    ImpacketDirectoryClient,
)
from .hostname import discover_directory_hostname
from .inspection import inspect_identity_access
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

__all__ = [
    "AccessCapability",
    "CapabilityKind",
    "Coverage",
    "CoverageState",
    "DirectoryIdentity",
    "DirectoryTextEntry",
    "DirectoryTextSignal",
    "DirectoryAccessError",
    "DirectoryClient",
    "DirectoryQuery",
    "DirectoryRecord",
    "discover_directory_hostname",
    "EvidenceState",
    "IdentityAccessReport",
    "IdentityGroup",
    "ImpacketDirectoryClient",
    "inspect_identity_access",
]
