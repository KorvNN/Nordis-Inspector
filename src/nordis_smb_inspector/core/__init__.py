"""Framework-independent scan domain models."""

from .content import (
    ContentDiagnostic,
    ContentScanResult,
    ContentScanStatus,
    LineMatch,
    MatchOptions,
    MatchSpan,
    scan_text,
)
from .credentials import AuthMode, Credential, CredentialKind, CredentialValidationError
from .progress import (
    ActiveWork,
    ProgressSnapshot,
    ProgressTracker,
    ScanPhase,
    StaleProgressUpdate,
)
from .targets import (
    ExpandedTarget,
    ResolutionFailure,
    TargetKind,
    TargetParseError,
    TargetPlan,
    parse_targets,
)

__all__ = [
    "ActiveWork",
    "AuthMode",
    "Credential",
    "CredentialKind",
    "CredentialValidationError",
    "ContentDiagnostic",
    "ContentScanResult",
    "ContentScanStatus",
    "ExpandedTarget",
    "LineMatch",
    "MatchOptions",
    "MatchSpan",
    "ProgressSnapshot",
    "ProgressTracker",
    "ResolutionFailure",
    "ScanPhase",
    "StaleProgressUpdate",
    "TargetKind",
    "TargetParseError",
    "TargetPlan",
    "parse_targets",
    "scan_text",
]
