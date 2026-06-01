"""Strict extraction of offline-verifiable credential material from findings.

The content detector deliberately reports complete source lines so an operator can
review context.  Password-audit integrations must not pass those arbitrary lines to
external tools.  This module is the boundary between the two: it recognizes a finite
set of detector rule IDs, extracts only the corresponding hash material, and exposes
only allow-listed tool formats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha256

_MAX_SOURCE_LINE_CHARS = 256 * 1024
_EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
_HEX32 = r"[0-9A-Fa-f]{32}"


@dataclass(frozen=True, slots=True)
class AuditToolBinding:
    """One fixed command format supported by an offline audit tool."""

    tool_id: str
    format_name: str

    def __post_init__(self) -> None:
        if self.tool_id not in {"hashcat", "john"}:
            raise ValueError("Unsupported audit tool ID.")
        if not self.format_name or not self.format_name.isascii():
            raise ValueError("Audit tool format must be non-empty ASCII text.")


@dataclass(frozen=True, slots=True, repr=False)
class AuditMaterial:
    """One extracted hash and the finite tool formats that can verify it."""

    variant: str
    format_id: str
    material: str = field(repr=False)
    bindings: tuple[AuditToolBinding, ...]

    def __post_init__(self) -> None:
        if not self.variant or not self.variant.isascii():
            raise ValueError("Audit material variant must be non-empty ASCII text.")
        if not self.format_id or not self.format_id.isascii():
            raise ValueError("Audit material format ID must be non-empty ASCII text.")
        if not self.material or "\x00" in self.material:
            raise ValueError("Audit material must be non-empty text without NUL bytes.")
        if not self.bindings:
            raise ValueError("Audit material must support at least one tool format.")
        if len({binding.tool_id for binding in self.bindings}) != len(self.bindings):
            raise ValueError("Audit material cannot repeat a tool binding.")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(variant={self.variant!r}, "
            f"format_id={self.format_id!r}, material=<redacted>, "
            f"bindings={self.bindings!r})"
        )

    def binding_for(self, tool_id: str) -> AuditToolBinding | None:
        return next(
            (binding for binding in self.bindings if binding.tool_id == tool_id),
            None,
        )

    @property
    def candidate_id(self) -> str:
        identity = "\x00".join((self.format_id, self.variant, self.material)).encode("utf-8")
        return sha256(identity).hexdigest()

    def public_metadata(self) -> dict[str, object]:
        """Return browser-safe metadata without the extracted hash value."""

        return {
            "id": self.candidate_id,
            "variant": self.variant,
            "format": self.format_id,
            "tools": [
                {"id": binding.tool_id, "format": binding.format_name}
                for binding in self.bindings
            ],
        }


def _hashcat(mode: int) -> AuditToolBinding:
    return AuditToolBinding("hashcat", str(mode))


def _john(format_name: str) -> AuditToolBinding:
    return AuditToolBinding("john", format_name)


_NT_BINDINGS = (_hashcat(1000), _john("nt"))
_LM_BINDINGS = (_hashcat(3000), _john("lm"))

_NT_LABEL = re.compile(
    rf"(?:\$NT\$|\b(?:NTLM(?:[ \t]+Hash)?|NT[ _-]*Hash|NTHash|"
    rf"Hash[ _-]*NTLM)[ \t]*[:=][ \t]*)(?P<hash>{_HEX32})(?![0-9A-Fa-f])",
    re.IGNORECASE | re.ASCII,
)
_KERBEROS_RC4 = re.compile(
    rf"\b(?:rc4[_-](?:hmac(?:[_-](?:nt|old)(?:[_-]exp)?)?|md4)|"
    rf"arcfour[_-]hmac)\b(?:[ \t]+\([0-9]{{1,5}}\))?"
    rf"[ \t]*(?:[:=][ \t]*|[ \t]+)(?P<hash>{_HEX32})(?![0-9A-Fa-f])",
    re.IGNORECASE | re.ASCII,
)
_LM_NT_PAIR = re.compile(
    rf"(?<![0-9A-Fa-f])(?P<lm>{_HEX32}):(?P<nt>{_HEX32})(?![0-9A-Fa-f])",
    re.ASCII,
)
_CREDENTIAL_DUMP = re.compile(
    rf"^[^:\r\n]{{1,128}}:[0-9]{{1,10}}:(?P<lm>{_HEX32}):"
    rf"(?P<nt>{_HEX32})(?:::[^\r\n]*)?$",
    re.ASCII,
)
_NETNTLMV1 = re.compile(
    r"^[^:\r\n]{0,128}::[^:\r\n]{1,128}:"
    r"[0-9A-Fa-f]{48}:[0-9A-Fa-f]{48}:[0-9A-Fa-f]{16}$",
    re.ASCII,
)
_NETNTLMV2 = re.compile(
    r"^[^:\r\n]{1,128}::[^:\r\n]{1,128}:[0-9A-Fa-f]{16}:"
    r"[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32,}$",
    re.ASCII,
)
_DCC2 = re.compile(
    r"\$DCC2\$[0-9]+#[^#\s]{1,128}#[0-9A-Fa-f]{32}",
    re.IGNORECASE | re.ASCII,
)
_UNIX_HASH = re.compile(
    r"\$(?P<type>[156])\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{16,}",
    re.ASCII,
)
_BCRYPT = re.compile(r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}", re.ASCII)
_ARGON2 = re.compile(r"\$argon2(?:id|i|d)\$v=[0-9]+\$[^\s'\"]{20,}", re.ASCII)
_KERBEROS = {
    "kerberos-tgs-artifact": re.compile(
        r"\$krb5tgs\$(?P<etype>17|18|23)\$[^\s'\"]{20,}",
        re.IGNORECASE | re.ASCII,
    ),
    "kerberos-asrep-artifact": re.compile(
        r"\$krb5asrep\$(?P<etype>17|18|23)\$[^\s'\"]{20,}",
        re.IGNORECASE | re.ASCII,
    ),
    "kerberos-preauth-artifact": re.compile(
        r"\$krb5pa\$(?P<etype>17|18|23)\$[^\s'\"]{20,}",
        re.IGNORECASE | re.ASCII,
    ),
    "kerberos-db-key": re.compile(
        r"\$krb5db\$(?P<etype>17|18)\$[^\s$]{1,256}\$[^\s$]{1,256}\$"
        r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64})(?![0-9A-Fa-f])",
        re.IGNORECASE | re.ASCII,
    ),
}

_KERBEROS_BINDINGS: dict[tuple[str, str], tuple[str, int, str]] = {
    ("kerberos-tgs-artifact", "17"): ("kerberos_tgs_etype17", 19600, "krb5tgs"),
    ("kerberos-tgs-artifact", "18"): ("kerberos_tgs_etype18", 19700, "krb5tgs"),
    ("kerberos-tgs-artifact", "23"): ("kerberos_tgs_etype23", 13100, "krb5tgs"),
    ("kerberos-asrep-artifact", "17"): ("kerberos_asrep_etype17", 32100, "krb5asrep"),
    ("kerberos-asrep-artifact", "18"): ("kerberos_asrep_etype18", 32200, "krb5asrep"),
    ("kerberos-asrep-artifact", "23"): ("kerberos_asrep_etype23", 18200, "krb5asrep"),
    ("kerberos-preauth-artifact", "17"): (
        "kerberos_preauth_etype17",
        19800,
        "krb5pa-sha1",
    ),
    ("kerberos-preauth-artifact", "18"): (
        "kerberos_preauth_etype18",
        19900,
        "krb5pa-sha1",
    ),
    ("kerberos-preauth-artifact", "23"): (
        "kerberos_preauth_etype23",
        7500,
        "krb5pa-md5",
    ),
    ("kerberos-db-key", "17"): ("kerberos_db_etype17", 28800, "krb5-17"),
    ("kerberos-db-key", "18"): ("kerberos_db_etype18", 28900, "krb5-18"),
}


def classify_audit_material(
    rule_id: object,
    source_line: object,
) -> tuple[AuditMaterial, ...]:
    """Extract safe offline-audit candidates for one structured finding.

    Unknown rules, malformed values, binary artifact findings, and plaintext secret
    findings intentionally return no candidates.
    """

    if not isinstance(rule_id, str) or not isinstance(source_line, str):
        return ()
    if not source_line or len(source_line) > _MAX_SOURCE_LINE_CHARS:
        return ()

    if rule_id in {"windows-nt-hash", "kerberos-rc4-key"}:
        pattern = _NT_LABEL if rule_id == "windows-nt-hash" else _KERBEROS_RC4
        match = pattern.search(source_line)
        if match is None:
            return ()
        return (_material("nt", "ntlm", match.group("hash"), _NT_BINDINGS),)

    if rule_id in {"lm-nt-hash-pair", "credential-dump-line"}:
        pattern = _LM_NT_PAIR if rule_id == "lm-nt-hash-pair" else _CREDENTIAL_DUMP
        match = pattern.search(source_line)
        if match is None:
            return ()
        materials = [
            _material("nt", "ntlm", match.group("nt"), _NT_BINDINGS),
        ]
        lm_hash = match.group("lm")
        if lm_hash.casefold() != _EMPTY_LM_HASH:
            materials.append(_material("lm", "lm", lm_hash, _LM_BINDINGS))
        return tuple(materials)

    if rule_id == "netntlmv1-response" and _NETNTLMV1.fullmatch(source_line):
        return (
            _material(
                "response",
                "netntlmv1",
                source_line,
                (_hashcat(5500), _john("netntlm")),
            ),
        )

    if rule_id == "netntlmv2-response" and _NETNTLMV2.fullmatch(source_line):
        return (
            _material(
                "response",
                "netntlmv2",
                source_line,
                (_hashcat(5600), _john("netntlmv2")),
            ),
        )

    if rule_id == "dcc2-hash":
        match = _DCC2.search(source_line)
        if match is not None:
            return (
                _material(
                    "hash",
                    "dcc2",
                    match.group(0),
                    (_hashcat(2100), _john("mscash2")),
                ),
            )

    if rule_id == "unix-password-hash":
        match = _UNIX_HASH.search(source_line)
        if match is not None:
            format_id, hashcat_mode, john_format = {
                "1": ("md5crypt", 500, "md5crypt"),
                "5": ("sha256crypt", 7400, "sha256crypt"),
                "6": ("sha512crypt", 1800, "sha512crypt"),
            }[match.group("type")]
            return (
                _material(
                    "hash",
                    format_id,
                    match.group(0),
                    (_hashcat(hashcat_mode), _john(john_format)),
                ),
            )

    if rule_id == "modern-password-hash":
        bcrypt_match = _BCRYPT.search(source_line)
        if bcrypt_match is not None:
            return (
                _material(
                    "hash",
                    "bcrypt",
                    bcrypt_match.group(0),
                    (_hashcat(3200), _john("bcrypt")),
                ),
            )
        argon2_match = _ARGON2.search(source_line)
        if argon2_match is not None:
            return (
                _material(
                    "hash",
                    "argon2",
                    argon2_match.group(0),
                    (_hashcat(34000), _john("argon2")),
                ),
            )

    kerberos_pattern = _KERBEROS.get(rule_id)
    if kerberos_pattern is not None:
        match = kerberos_pattern.search(source_line)
        if match is None:
            return ()
        mapping = _KERBEROS_BINDINGS[(rule_id, match.group("etype"))]
        format_id, hashcat_mode, john_format = mapping
        return (
            _material(
                "artifact",
                format_id,
                match.group(0).rstrip(",;"),
                (_hashcat(hashcat_mode), _john(john_format)),
            ),
        )

    return ()


def _material(
    variant: str,
    format_id: str,
    value: str,
    bindings: tuple[AuditToolBinding, ...],
) -> AuditMaterial:
    return AuditMaterial(
        variant=variant,
        format_id=format_id,
        material=value,
        bindings=bindings,
    )
