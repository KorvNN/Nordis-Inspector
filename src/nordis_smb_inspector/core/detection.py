"""Bounded, line-oriented detection backed by versioned built-in rule packs."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from types import MappingProxyType
from typing import Any

_RULE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_IGNORED_VALUES = frozenset(
    {
        "changeme",
        "default",
        "dummy",
        "example",
        "false",
        "none",
        "null",
        "password",
        "placeholder",
        "redacted",
        "sample",
        "test",
        "true",
        "your_password",
    }
)
_MAX_MATCHES_PER_RULE_LINE = 32
_RULE_PACK_SCHEMA_VERSION = 1
_RULES_DIRECTORY = Path("rules")
_DISTRIBUTION_NAME = "nordis-smb-inspector"
_PACKAGED_RULES_SUFFIX = "share/nordis-smb-inspector/rules"


class DetectionConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"


class DetectionRulePack(StrEnum):
    GENERAL_SECRETS = "general_secrets"
    WINDOWS_AD = "windows_ad"
    PASSWORD_HASHES = "password_hashes"
    CLOUD_SERVICES = "cloud_services"
    INFRASTRUCTURE = "infrastructure"


DEFAULT_DETECTION_RULE_PACKS = tuple(DetectionRulePack)

_RULE_PACK_FILES = MappingProxyType(
    {
        DetectionRulePack.GENERAL_SECRETS: "general-secrets.toml",
        DetectionRulePack.WINDOWS_AD: "windows-ad.toml",
        DetectionRulePack.PASSWORD_HASHES: "password-hashes.toml",
        DetectionRulePack.CLOUD_SERVICES: "cloud-services.toml",
        DetectionRulePack.INFRASTRUCTURE: "infrastructure.toml",
    }
)


class RulePackError(ValueError):
    """A safe, content-free built-in rule-pack validation failure."""


@dataclass(frozen=True, slots=True, repr=False)
class DetectionRule:
    rule_id: str
    title: str
    category: str
    confidence: DetectionConfidence
    pattern: str
    pack: DetectionRulePack = DetectionRulePack.GENERAL_SECRETS
    keywords: tuple[str, ...] = ()
    secret_group: str | None = None
    ignore_common_values: bool = False
    _compiled: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not _RULE_ID.fullmatch(self.rule_id):
            raise ValueError("Detection rule ID is invalid.")
        for name in ("title", "category", "pattern"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Detection rule {name} must be non-empty text.")
        if not isinstance(self.confidence, DetectionConfidence):
            raise TypeError("Detection rule confidence is invalid.")
        if not isinstance(self.pack, DetectionRulePack):
            raise TypeError("Detection rule pack is invalid.")
        if not isinstance(self.keywords, tuple) or not all(
            isinstance(keyword, str) and keyword for keyword in self.keywords
        ):
            raise ValueError("Detection rule keywords must be non-empty text.")
        if not isinstance(self.ignore_common_values, bool):
            raise TypeError("Detection rule ignore selection is invalid.")
        try:
            compiled = re.compile(self.pattern, re.IGNORECASE | re.ASCII)
        except re.error as error:
            raise ValueError("Detection rule pattern is invalid.") from error
        if self.secret_group is not None and self.secret_group not in compiled.groupindex:
            raise ValueError("Detection rule secret group is unavailable.")
        object.__setattr__(self, "_compiled", compiled)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(rule_id={self.rule_id!r}, title={self.title!r}, "
            f"category={self.category!r}, confidence={self.confidence.value!r}, "
            f"pack={self.pack.value!r}, pattern=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class PatternMatch:
    line_number: int
    line: str = field(repr=False)
    rule_id: str
    title: str
    category: str
    confidence: DetectionConfidence
    start: int
    end: int

    def __post_init__(self) -> None:
        if isinstance(self.line_number, bool) or not isinstance(self.line_number, int):
            raise TypeError("line_number must be an integer.")
        if self.line_number < 1:
            raise ValueError("line_number must be at least one.")
        if not isinstance(self.line, str):
            raise TypeError("line must be text.")
        if self.start < 0 or self.end <= self.start or self.end > len(self.line):
            raise ValueError("Pattern match range is invalid.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(line_number={self.line_number!r}, "
            f"line=<redacted {len(self.line)} chars>, rule_id={self.rule_id!r}, "
            f"category={self.category!r}, confidence={self.confidence.value!r}, "
            f"start={self.start!r}, end={self.end!r})"
        )


@dataclass(frozen=True, slots=True)
class DetectionRulePackInfo:
    pack_id: DetectionRulePack
    title_tr: str
    title_en: str
    rules: tuple[DetectionRule, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.pack_id, DetectionRulePack):
            raise TypeError("Detection rule pack ID is invalid.")
        if not isinstance(self.title_tr, str) or not self.title_tr.strip():
            raise ValueError("Detection rule pack Turkish title is invalid.")
        if not isinstance(self.title_en, str) or not self.title_en.strip():
            raise ValueError("Detection rule pack English title is invalid.")
        if not isinstance(self.rules, tuple) or not self.rules:
            raise ValueError("Detection rule pack must contain rules.")
        if any(rule.pack is not self.pack_id for rule in self.rules):
            raise ValueError("Detection rule pack contains a mismatched rule.")


def detect_patterns(
    line: str,
    line_number: int,
    *,
    rules: tuple[DetectionRule, ...] | None = None,
) -> tuple[PatternMatch, ...]:
    """Return deterministic structured matches for one decoded physical line."""

    if not isinstance(line, str):
        raise TypeError("line must be text.")
    if isinstance(line_number, bool) or not isinstance(line_number, int):
        raise TypeError("line_number must be an integer.")
    if line_number < 1:
        raise ValueError("line_number must be at least one.")
    selected_rules = DEFAULT_DETECTION_RULES if rules is None else rules
    if not isinstance(selected_rules, tuple) or not all(
        isinstance(rule, DetectionRule) for rule in selected_rules
    ):
        raise TypeError("rules must be DetectionRule values.")

    folded_line = line.casefold()
    findings: list[PatternMatch] = []
    for rule in selected_rules:
        if rule.keywords and not any(
            keyword.casefold() in folded_line for keyword in rule.keywords
        ):
            continue
        for match_index, match in enumerate(rule._compiled.finditer(line)):
            if match_index >= _MAX_MATCHES_PER_RULE_LINE:
                break
            if rule.secret_group is not None and rule.ignore_common_values:
                value = match.group(rule.secret_group).strip("'\" ").casefold()
                if value in _IGNORED_VALUES:
                    continue
            findings.append(
                PatternMatch(
                    line_number=line_number,
                    line=line,
                    rule_id=rule.rule_id,
                    title=rule.title,
                    category=rule.category,
                    confidence=rule.confidence,
                    start=match.start(),
                    end=match.end(),
                )
            )
    return _without_redundant_matches(findings)


def detection_rules_for_packs(
    packs: tuple[DetectionRulePack, ...],
) -> tuple[DetectionRule, ...]:
    """Return built-in rules belonging to the selected immutable pack tuple."""

    if not isinstance(packs, tuple) or not all(
        isinstance(pack, DetectionRulePack) for pack in packs
    ):
        raise TypeError("packs must be DetectionRulePack values.")
    selected = frozenset(packs)
    return tuple(rule for rule in DEFAULT_DETECTION_RULES if rule.pack in selected)


def _without_redundant_matches(
    findings: list[PatternMatch],
) -> tuple[PatternMatch, ...]:
    def is_redundant(match: PatternMatch) -> bool:
        if match.rule_id == "secret-assignment":
            suppressors = (
                candidate
                for candidate in findings
                if candidate.rule_id != "secret-assignment"
            )
        elif match.rule_id == "lm-nt-hash-pair":
            suppressors = (
                candidate
                for candidate in findings
                if candidate.rule_id == "credential-dump-line"
            )
        else:
            return False
        return any(
            match.start < candidate.end and candidate.start < match.end
            for candidate in suppressors
        )

    return tuple(match for match in findings if not is_redundant(match))


def _repository_rule_pack_path(filename: str) -> Path | None:
    try:
        resolved = Path(__file__).resolve()
    except OSError:
        return None
    for candidate in (resolved.parent, *resolved.parents):
        rule_path = candidate / _RULES_DIRECTORY / filename
        if rule_path.is_file():
            return rule_path
    return None


def _installed_rule_pack_path(filename: str) -> Path:
    suffix = f"{_PACKAGED_RULES_SUFFIX}/{filename}"
    try:
        installed = distribution(_DISTRIBUTION_NAME)
        matches = [
            entry
            for entry in installed.files or ()
            if str(entry).replace("\\", "/").endswith(suffix)
        ]
        if len(matches) != 1:
            raise RulePackError("Built-in detection rule pack is unavailable.")
        return Path(installed.locate_file(matches[0]))
    except PackageNotFoundError:
        raise RulePackError("Built-in detection rule pack is unavailable.") from None
    except (OSError, TypeError, ValueError):
        raise RulePackError("Built-in detection rule pack is unavailable.") from None


def _rule_pack_document(pack: DetectionRulePack) -> Mapping[str, Any]:
    filename = _RULE_PACK_FILES[pack]
    path = _repository_rule_pack_path(filename) or _installed_rule_pack_path(filename)
    try:
        decoded = path.read_text(encoding="utf-8")
        document = tomllib.loads(decoded)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise RulePackError("Built-in detection rule pack is invalid.") from None
    if not isinstance(document, Mapping):
        raise RulePackError("Built-in detection rule pack is invalid.")
    return document


def _load_rule_pack(pack: DetectionRulePack) -> DetectionRulePackInfo:
    document = _rule_pack_document(pack)
    if document.get("schema_version") != _RULE_PACK_SCHEMA_VERSION:
        raise RulePackError("Built-in detection rule pack schema is unsupported.")
    if document.get("pack_id") != pack.value:
        raise RulePackError("Built-in detection rule pack ID is invalid.")
    title_tr = document.get("title_tr")
    title_en = document.get("title_en")
    raw_rules = document.get("rules")
    if not isinstance(title_tr, str) or not isinstance(title_en, str):
        raise RulePackError("Built-in detection rule pack title is invalid.")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RulePackError("Built-in detection rule pack rules are invalid.")
    rules = tuple(_rule_from_document(value, pack) for value in raw_rules)
    return DetectionRulePackInfo(pack, title_tr, title_en, rules)


def _rule_from_document(value: object, pack: DetectionRulePack) -> DetectionRule:
    if not isinstance(value, Mapping):
        raise RulePackError("Built-in detection rule is invalid.")
    keywords = value.get("keywords", [])
    if not isinstance(keywords, list) or not all(
        isinstance(keyword, str) for keyword in keywords
    ):
        raise RulePackError("Built-in detection rule keywords are invalid.")
    confidence_value = value.get("confidence")
    try:
        confidence = DetectionConfidence(confidence_value)
    except (TypeError, ValueError):
        raise RulePackError("Built-in detection rule confidence is invalid.") from None
    try:
        return DetectionRule(
            rule_id=value.get("rule_id"),
            title=value.get("title"),
            category=value.get("category"),
            confidence=confidence,
            pattern=value.get("pattern"),
            pack=pack,
            keywords=tuple(keywords),
            secret_group=value.get("secret_group"),
            ignore_common_values=value.get("ignore_common_values", False),
        )
    except (TypeError, ValueError):
        raise RulePackError("Built-in detection rule is invalid.") from None


def _load_default_rule_packs() -> tuple[DetectionRulePackInfo, ...]:
    packs = tuple(_load_rule_pack(pack) for pack in DEFAULT_DETECTION_RULE_PACKS)
    rule_ids = [rule.rule_id for pack in packs for rule in pack.rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise RulePackError("Built-in detection rule IDs must be unique.")
    return packs


DEFAULT_RULE_PACKS = _load_default_rule_packs()
DEFAULT_DETECTION_RULES = tuple(
    rule for pack in DEFAULT_RULE_PACKS for rule in pack.rules
)
DETECTION_RULE_PACK_TITLES = MappingProxyType(
    {pack.pack_id: (pack.title_tr, pack.title_en) for pack in DEFAULT_RULE_PACKS}
)
