"""Bounded, line-oriented detection of structured credential artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

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


class DetectionConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"


@dataclass(frozen=True, slots=True, repr=False)
class DetectionRule:
    rule_id: str
    title: str
    category: str
    confidence: DetectionConfidence
    pattern: str
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
        if not isinstance(self.keywords, tuple) or not all(
            isinstance(keyword, str) and keyword for keyword in self.keywords
        ):
            raise ValueError("Detection rule keywords must be non-empty text.")
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
            "pattern=<redacted>)"
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
    return tuple(findings)


DEFAULT_DETECTION_RULES = (
    DetectionRule(
        rule_id="cloud-access-key",
        title="Cloud access key",
        category="Cloud / SaaS",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        keywords=("AKIA", "ASIA"),
    ),
    DetectionRule(
        rule_id="jwt-token",
        title="JWT token",
        category="Oturum tokenı",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        keywords=("eyJ",),
    ),
    DetectionRule(
        rule_id="private-key-header",
        title="Private key başlangıcı",
        category="Kriptografik anahtar",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        ),
        keywords=("PRIVATE KEY",),
    ),
    DetectionRule(
        rule_id="authorization-bearer",
        title="Bearer token",
        category="Oturum tokenı",
        confidence=DetectionConfidence.MEDIUM,
        pattern=r"\bBearer[ \t]+[A-Za-z0-9._~+/=-]{16,}",
        keywords=("Bearer",),
    ),
    DetectionRule(
        rule_id="authorization-basic",
        title="Basic authentication değeri",
        category="Kimlik bilgisi",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bBasic[ \t]+[A-Za-z0-9+/]{12,}={0,2}\b",
        keywords=("Basic",),
    ),
    DetectionRule(
        rule_id="credential-url",
        title="URL içinde kimlik bilgisi",
        category="Kimlik bilgisi",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\b[a-z][a-z0-9+.-]{1,15}://[^\s/:@]+:"
            r"(?P<secret>[^\s/@]{3,})@[^\s/]+"
        ),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="connection-string-password",
        title="Connection string parolası",
        category="Veritabanı",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\b(?:Password|Pwd)[ \t]*=[ \t]*"
            r"(?P<secret>[^;\s'\"]{3,}|['\"][^'\"\r\n]{3,}['\"])"
        ),
        keywords=("password", "pwd"),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="secret-assignment",
        title="Hassas yapılandırma ataması",
        category="Yapılandırma",
        confidence=DetectionConfidence.MEDIUM,
        pattern=(
            r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|pwd|secret|token)"
            r"[ \t]*[:=][ \t]*(?P<secret>[^\s,;#]{4,}|['\"][^'\"\r\n]{4,}['\"])}?"
        ),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="gpp-cpassword",
        title="Group Policy Preferences cpassword",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bcpassword[ \t]*=[ \t]*['\"]?(?P<secret>[A-Za-z0-9+/]{16,}={0,2})",
        keywords=("cpassword",),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="kerberos-tgs-artifact",
        title="Kerberos TGS artifact",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\$krb5tgs\$(?:17|18|23)\$[^\s]{20,}",
        keywords=("$krb5tgs$",),
    ),
    DetectionRule(
        rule_id="kerberos-asrep-artifact",
        title="Kerberos AS-REP artifact",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\$krb5asrep\$(?:17|18|23)\$[^\s]{20,}",
        keywords=("$krb5asrep$",),
    ),
    DetectionRule(
        rule_id="kerberos-preauth-artifact",
        title="Kerberos pre-auth artifact",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\$krb5pa\$(?:17|18|23)\$[^\s]{20,}",
        keywords=("$krb5pa$",),
    ),
    DetectionRule(
        rule_id="lm-nt-hash-pair",
        title="LM/NT hash çifti",
        category="Credential artifact",
        confidence=DetectionConfidence.HIGH,
        pattern=r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}(?![0-9A-Fa-f])",
    ),
    DetectionRule(
        rule_id="credential-dump-line",
        title="Hesap RID ve hash satırı",
        category="Credential artifact",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"^[^:\r\n]{1,128}:[0-9]{1,10}:[0-9A-Fa-f]{32}:"
            r"[0-9A-Fa-f]{32}(?:::[^\r\n]*)?$"
        ),
    ),
    DetectionRule(
        rule_id="netntlmv2-response",
        title="NetNTLMv2 challenge-response",
        category="Credential artifact",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"^[^:\r\n]{1,128}::[^:\r\n]{1,128}:[0-9A-Fa-f]{16}:"
            r"[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32,}$"
        ),
    ),
    DetectionRule(
        rule_id="dcc2-hash",
        title="Windows cached domain credential",
        category="Credential artifact",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\$DCC2\$[0-9]+#[^#\s]{1,128}#[0-9A-Fa-f]{32}",
        keywords=("$DCC2$",),
    ),
    DetectionRule(
        rule_id="unix-password-hash",
        title="Unix password hash",
        category="Credential artifact",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\$(?:1|5|6)\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{16,}",
    ),
    DetectionRule(
        rule_id="modern-password-hash",
        title="Bcrypt veya Argon2 hash",
        category="Credential artifact",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"(?:\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}|"
            r"\$argon2(?:id|i|d)\$v=[0-9]+\$[^\s]{20,})"
        ),
    ),
)
