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
    return _without_redundant_matches(findings)


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

    return tuple(
        match
        for match in findings
        if not is_redundant(match)
    )


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
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?"
            r"PRIVATE KEY(?: BLOCK)?-----"
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
        title="Veritabanı bağlantı parolası",
        category="Veritabanı",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"^(?=[^\r\n]*\b(?:Server|Data[ \t]+Source|Host|Database|"
            r"Initial[ \t]+Catalog|User[ \t]+Id|UID)[ \t]*=)"
            r"[^\r\n]*?\b(?:Password|Pwd)[ \t]*=[ \t]*"
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
        rule_id="kerberos-db-key",
        title="Kerberos KDC database key",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\$krb5db\$(?:"
            r"17\$[^\s$]{1,256}\$[^\s$]{1,256}\$[0-9A-Fa-f]{32}|"
            r"18\$[^\s$]{1,256}\$[^\s$]{1,256}\$[0-9A-Fa-f]{64}"
            r")(?![0-9A-Fa-f])"
        ),
        keywords=("$krb5db$",),
    ),
    DetectionRule(
        rule_id="windows-nt-hash",
        title="Etiketli NTLM hash",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"(?:\$NT\$|\b(?:NTLM(?:[ \t]+Hash)?|NT[ _-]*Hash|NTHash|"
            r"Hash[ _-]*NTLM)[ \t]*[:=][ \t]*)"
            r"(?P<secret>[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
        ),
        keywords=("$nt$", "ntlm", "nt hash", "nt_hash", "nt-hash", "nthash"),
        secret_group="secret",
    ),
    DetectionRule(
        rule_id="kerberos-rc4-key",
        title="Kerberos RC4 key",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\b(?:rc4[_-](?:hmac(?:[_-](?:nt|old)(?:[_-]exp)?)?|md4)|"
            r"arcfour[_-]hmac)\b"
            r"(?:[ \t]+\([0-9]{1,5}\))?[ \t]*(?:[:=][ \t]*|[ \t]+)"
            r"(?P<secret>[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
        ),
        keywords=(
            "rc4_hmac",
            "rc4-hmac",
            "rc4_md4",
            "rc4-md4",
            "arcfour_hmac",
            "arcfour-hmac",
        ),
        secret_group="secret",
    ),
    DetectionRule(
        rule_id="kerberos-aes128-key",
        title="Kerberos AES-128 key",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\baes128(?:[_-]hmac|[_-]cts[_-]hmac[_-]sha1(?:[_-]96)?)?\b"
            r"(?:[ \t]+\([0-9]{1,5}\))?[ \t]*(?:[:=][ \t]*|[ \t]+)"
            r"(?P<secret>[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
        ),
        keywords=("aes128",),
        secret_group="secret",
    ),
    DetectionRule(
        rule_id="kerberos-aes256-key",
        title="Kerberos AES-256 key",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\baes256(?:[_-]hmac|[_-]cts[_-]hmac[_-]sha1(?:[_-]96)?)?\b"
            r"(?:[ \t]+\([0-9]{1,5}\))?[ \t]*(?:[:=][ \t]*|[ \t]+)"
            r"(?P<secret>[0-9A-Fa-f]{64})(?![0-9A-Fa-f])"
        ),
        keywords=("aes256",),
        secret_group="secret",
    ),
    DetectionRule(
        rule_id="kerberos-des-key",
        title="Kerberos DES key",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\bdes[_-]cbc[_-](?:md5|crc)\b"
            r"(?:[ \t]+\([0-9]{1,5}\))?[ \t]*(?:[:=][ \t]*|[ \t]+)"
            r"(?P<secret>[0-9A-Fa-f]{16})(?![0-9A-Fa-f])"
        ),
        keywords=("des_cbc", "des-cbc"),
        secret_group="secret",
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
        rule_id="netntlmv1-response",
        title="NetNTLMv1 challenge-response",
        category="Credential artifact",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"^[^:\r\n]{0,128}::[^:\r\n]{1,128}:"
            r"[0-9A-Fa-f]{48}:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{16}$"
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
    DetectionRule(
        rule_id="github-token-prefix",
        title="GitHub access token",
        category="Source control",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b",
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ),
    DetectionRule(
        rule_id="github-fine-grained-token",
        title="GitHub fine-grained token",
        category="Source control",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        keywords=("github_pat_",),
    ),
    DetectionRule(
        rule_id="gitlab-token-prefix",
        title="GitLab access token",
        category="Source control",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bglpat-[A-Za-z0-9_-]{20,}\b",
        keywords=("glpat-",),
    ),
    DetectionRule(
        rule_id="slack-token-prefix",
        title="Slack token",
        category="Oturum tokenı",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        keywords=("xox",),
    ),
    DetectionRule(
        rule_id="stripe-secret-key",
        title="Stripe secret key",
        category="Ödeme servisi",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        keywords=("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
    ),
    DetectionRule(
        rule_id="sendgrid-api-key",
        title="SendGrid API key",
        category="Cloud / SaaS",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bSG\.[A-Za-z0-9_-]{16,}\b",
        keywords=("SG.",),
    ),
    DetectionRule(
        rule_id="google-api-key",
        title="Google API key",
        category="Cloud / SaaS",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bAIza[0-9A-Za-z_-]{30,}\b",
        keywords=("AIza",),
    ),
    DetectionRule(
        rule_id="npm-token-prefix",
        title="npm access token",
        category="Developer tooling",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bnpm_[A-Za-z0-9]{20,}\b",
        keywords=("npm_",),
    ),
    DetectionRule(
        rule_id="pypi-token-prefix",
        title="PyPI API token",
        category="Developer tooling",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bpypi-[A-Za-z0-9_-]{16,}\b",
        keywords=("pypi-",),
    ),
    DetectionRule(
        rule_id="huggingface-token-prefix",
        title="Hugging Face token",
        category="Cloud / SaaS",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bhf_[A-Za-z0-9]{20,}\b",
        keywords=("hf_",),
    ),
    DetectionRule(
        rule_id="vault-token-prefix",
        title="Vault token",
        category="Infrastructure",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\bhvs\.[A-Za-z0-9_-]{16,}\b",
        keywords=("hvs.",),
    ),
    DetectionRule(
        rule_id="private-token-header",
        title="Private access token header",
        category="Source control",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\b(?:PRIVATE|JOB|DEPLOY|REGISTRY)-TOKEN:[ \t]*"
            r"[A-Za-z0-9._~+/=-]{16,}\b"
        ),
        keywords=("-TOKEN:",),
    ),
    DetectionRule(
        rule_id="cookie-secret-assignment",
        title="Session cookie değeri",
        category="Oturum tokenı",
        confidence=DetectionConfidence.MEDIUM,
        pattern=(
            r"\b(?:session|auth|access)[_-]?cookie[ \t]*=[ \t]*"
            r"(?P<secret>[^;\s]{16,})"
        ),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="netrc-credential",
        title="netrc kimlik bilgisi",
        category="Kimlik bilgisi",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\bmachine[ \t]+\S+[ \t]+login[ \t]+\S+[ \t]+"
            r"password[ \t]+(?P<secret>\S+)"
        ),
        keywords=("machine", "login", "password"),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="aws-secret-access-key",
        title="AWS secret access key assignment",
        category="Cloud / SaaS",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\baws[_-]?secret[_-]?access[_-]?key[ \t]*[:=][ \t]*"
            r"(?P<secret>[A-Za-z0-9/+=]{20,})"
        ),
        keywords=("aws", "secret", "access", "key"),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="docker-registry-auth",
        title="Docker registry auth değeri",
        category="Container tooling",
        confidence=DetectionConfidence.HIGH,
        pattern=r"[\"']auth[\"'][ \t]*:[ \t]*[\"'](?P<secret>[A-Za-z0-9+/=]{20,})[\"']",
        keywords=("auth",),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="ansible-vault-artifact",
        title="Ansible Vault artifact",
        category="Infrastructure",
        confidence=DetectionConfidence.HIGH,
        pattern=r"\$ANSIBLE_VAULT;[0-9.]+;AES[0-9]+;[0-9a-f]{20,}",
        keywords=("$ANSIBLE_VAULT;",),
    ),
    DetectionRule(
        rule_id="sops-encrypted-artifact",
        title="SOPS encrypted value",
        category="Infrastructure",
        confidence=DetectionConfidence.HIGH,
        pattern=r"ENC\[AES256_GCM,data:[^\]]{16,}\]",
        keywords=("ENC[AES256_GCM,data:",),
    ),
    DetectionRule(
        rule_id="windows-managed-password",
        title="Windows managed password attribute",
        category="Windows / AD",
        confidence=DetectionConfidence.HIGH,
        pattern=(
            r"\b(?:ms-Mcs-AdmPwd|msLAPS-Password|msLAPS-EncryptedPassword)"
            r"[ \t]*[:=][ \t]*(?P<secret>[^\s,;]+)"
        ),
        keywords=("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"),
        secret_group="secret",
        ignore_common_values=True,
    ),
    DetectionRule(
        rule_id="age-encrypted-file",
        title="Age encrypted file",
        category="Kriptografik anahtar",
        confidence=DetectionConfidence.HIGH,
        pattern=r"-----BEGIN AGE ENCRYPTED FILE-----",
        keywords=("BEGIN AGE ENCRYPTED FILE",),
    ),
)
