"""Validated, immutable scan options built from the web request."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from nordis_smb_inspector.core.detection import (
    DEFAULT_DETECTION_RULE_PACKS,
    DetectionRulePack,
)

MIN_MAX_DEPTH = 1
MAX_MAX_DEPTH = 256


class ScanConfigError(ValueError):
    """A content-free validation or configuration error."""


@dataclass(frozen=True, slots=True, repr=False)
class ScanOptions:
    """All non-credential options needed by one scan.

    ``repr`` intentionally exposes only entry counts. Search terms can
    themselves be sensitive and should not be copied into incidental logs.
    """

    terms: tuple[str, ...]
    max_depth: int
    detect_patterns: bool = True
    rule_packs: tuple[DetectionRulePack, ...] = DEFAULT_DETECTION_RULE_PACKS

    def __post_init__(self) -> None:
        terms = _normalize_values(self.terms, "Search terms must be text.")
        _validate_max_depth(self.max_depth)
        if not isinstance(self.detect_patterns, bool):
            raise ScanConfigError("Pattern detection selection must be a boolean.")
        rule_packs = _validate_rule_packs(self.rule_packs)
        if self.detect_patterns and not rule_packs:
            raise ScanConfigError("At least one detection rule pack is required.")
        if not terms and not self.detect_patterns:
            raise ScanConfigError(
                "Enable pattern detection or provide at least one search term."
            )
        object.__setattr__(self, "terms", terms)
        object.__setattr__(self, "rule_packs", rule_packs)

    def __repr__(self) -> str:
        return (
            f"ScanOptions(terms=<redacted {len(self.terms)} entries>, "
            f"max_depth={self.max_depth!r}, detect_patterns={self.detect_patterns!r}, "
            f"rule_packs={len(self.rule_packs)} selected)"
        )


def parse_scan_options(search: object, max_depth: object) -> ScanOptions:
    """Parse custom literal terms and built-in pattern selections."""

    if not isinstance(search, Mapping):
        raise ScanConfigError("Search settings must be an object.")

    additional_terms = search.get("additional_terms")
    if not isinstance(additional_terms, list):
        raise ScanConfigError("Additional search terms must be an array.")
    if not all(isinstance(term, str) for term in additional_terms):
        raise ScanConfigError("Each additional search term must be text.")

    detect_patterns = search.get("detect_patterns", True)
    if not isinstance(detect_patterns, bool):
        raise ScanConfigError("Pattern detection selection must be a boolean.")
    raw_rule_packs = search.get(
        "rule_packs",
        [pack.value for pack in DEFAULT_DETECTION_RULE_PACKS],
    )
    if not isinstance(raw_rule_packs, list):
        raise ScanConfigError("Detection rule packs must be an array.")
    if not all(isinstance(pack, str) for pack in raw_rule_packs):
        raise ScanConfigError("Each detection rule pack must be text.")
    try:
        rule_packs = tuple(dict.fromkeys(DetectionRulePack(pack) for pack in raw_rule_packs))
    except ValueError:
        raise ScanConfigError("Detection rule pack is unknown.") from None

    return ScanOptions(
        terms=_normalize_values(additional_terms, "Search terms must be text."),
        max_depth=_validate_max_depth(max_depth),
        detect_patterns=detect_patterns,
        rule_packs=rule_packs,
    )


def _validate_rule_packs(
    values: tuple[DetectionRulePack, ...],
) -> tuple[DetectionRulePack, ...]:
    if not isinstance(values, tuple) or not all(
        isinstance(value, DetectionRulePack) for value in values
    ):
        raise ScanConfigError("Detection rule packs are invalid.")
    if len(values) != len(set(values)):
        raise ScanConfigError("Detection rule packs must be unique.")
    return values


def _normalize_values(values: Iterable[Any], item_error: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray, memoryview)):
        raise ScanConfigError(item_error)
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ScanConfigError(item_error) from exc

    result: list[str] = []
    seen: set[str] = set()
    for value in iterator:
        if not isinstance(value, str):
            raise ScanConfigError(item_error)
        cleaned = value.strip()
        if not cleaned:
            continue
        comparison_key = cleaned.casefold()
        if comparison_key in seen:
            continue
        seen.add(comparison_key)
        result.append(cleaned)
    return tuple(result)


def _validate_max_depth(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScanConfigError("Maximum depth must be an integer.")
    if not MIN_MAX_DEPTH <= value <= MAX_MAX_DEPTH:
        raise ScanConfigError("Maximum depth must be between 1 and 256.")
    return value
