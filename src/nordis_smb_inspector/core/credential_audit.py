"""Strict extraction of offline-verifiable credential material from findings.

The content detector deliberately reports complete source lines so an operator can
review context.  Password-audit integrations must not pass those arbitrary lines to
external tools.  This module is the boundary between the two: it recognizes a finite
set of detector rule IDs, extracts only the corresponding hash material, and exposes
only allow-listed tool formats.
"""

from __future__ import annotations

import base64
import binascii
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


_FORMAT_BINDINGS: dict[str, tuple[AuditToolBinding, ...]] = {
    "ntlm": (_hashcat(1000), _john("nt")),
    "lm": (_hashcat(3000), _john("lm")),
    "netntlmv1": (_hashcat(5500), _john("netntlm")),
    "netntlmv2": (_hashcat(5600), _john("netntlmv2")),
    "dcc2": (_hashcat(2100), _john("mscash2")),
    "md5crypt": (_hashcat(500), _john("md5crypt")),
    "sha256crypt": (_hashcat(7400), _john("sha256crypt")),
    "sha512crypt": (_hashcat(1800), _john("sha512crypt")),
    "bcrypt": (_hashcat(3200), _john("bcrypt")),
    "argon2": (_hashcat(34000), _john("argon2")),
    "phpass": (_hashcat(400),),
    "drupal7": (_hashcat(7900),),
    "apr1": (_hashcat(1600),),
    "django_pbkdf2_sha256": (_hashcat(10000),),
    "passlib_pbkdf2_sha1": (_hashcat(20400),),
    "passlib_pbkdf2_sha256": (_hashcat(20300),),
    "passlib_pbkdf2_sha512": (_hashcat(20200),),
    "ldap_sha1": (_hashcat(101),),
    "ldap_ssha1": (_hashcat(111),),
    "ldap_ssha256": (_hashcat(1411),),
    "ldap_ssha512": (_hashcat(1711),),
    "mysql_sha1": (_hashcat(300),),
    "mssql_2005": (_hashcat(132),),
    "mssql_2012": (_hashcat(1731),),
    "postgresql_scram_sha256": (_hashcat(28600),),
    "cisco_type8": (_hashcat(9200),),
    "cisco_type9": (_hashcat(9300),),
    "kerberos_tgs_etype17": (_hashcat(19600), _john("krb5tgs")),
    "kerberos_tgs_etype18": (_hashcat(19700), _john("krb5tgs")),
    "kerberos_tgs_etype23": (_hashcat(13100), _john("krb5tgs")),
    "kerberos_asrep_etype17": (_hashcat(32100), _john("krb5asrep")),
    "kerberos_asrep_etype18": (_hashcat(32200), _john("krb5asrep")),
    "kerberos_asrep_etype23": (_hashcat(18200), _john("krb5asrep")),
    "kerberos_preauth_etype17": (_hashcat(19800), _john("krb5pa-sha1")),
    "kerberos_preauth_etype18": (_hashcat(19900), _john("krb5pa-sha1")),
    "kerberos_preauth_etype23": (_hashcat(7500), _john("krb5pa-md5")),
    "kerberos_db_etype17": (_hashcat(28800), _john("krb5-17")),
    "kerberos_db_etype18": (_hashcat(28900), _john("krb5-18")),
}


def audit_tool_formats(tool_id: str) -> frozenset[str]:
    """Return every allow-listed format binding for one local audit adapter."""

    if tool_id not in {"hashcat", "john"}:
        raise ValueError("Unsupported audit tool ID.")
    return frozenset(
        binding.format_name
        for bindings in _FORMAT_BINDINGS.values()
        for binding in bindings
        if binding.tool_id == tool_id
    )


def _bindings(format_id: str) -> tuple[AuditToolBinding, ...]:
    return _FORMAT_BINDINGS[format_id]

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
_PORTABLE_PHP = re.compile(
    r"(?:(?P<phpass>\$[PH]\$[./A-Za-z0-9]{31})|"
    r"(?P<drupal>\$S\$[./A-Za-z0-9]{52}))(?![./A-Za-z0-9])",
    re.ASCII,
)
_APR1 = re.compile(
    r"\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}(?![./A-Za-z0-9])",
    re.ASCII,
)
_DJANGO_PBKDF2 = re.compile(
    r"pbkdf2_sha256\$[1-9][0-9]{0,8}\$[^\s$]{1,128}\$"
    r"[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])",
    re.ASCII,
)
_PASSLIB_PBKDF2 = re.compile(
    r"\$pbkdf2(?P<type>-sha(?:256|512))?\$[1-9][0-9]{0,8}\$"
    r"[./A-Za-z0-9]{1,256}\$(?P<digest>[./A-Za-z0-9]{27,86})"
    r"(?![./A-Za-z0-9])",
    re.ASCII,
)
_LDAP_HASH = re.compile(
    r"\{(?P<type>SHA|SSHA|SSHA256|SSHA512)\}"
    r"(?P<payload>[A-Za-z0-9+/]{20,256}={0,2})(?![A-Za-z0-9+/=])",
    re.IGNORECASE | re.ASCII,
)
_MYSQL_HASH = re.compile(
    r"(?<![0-9A-Fa-f])\*(?P<hash>[0-9A-Fa-f]{40})(?![0-9A-Fa-f])",
    re.ASCII,
)
_MSSQL_HASH = re.compile(
    r"(?<![0-9A-Fa-f])(?P<hash>0x(?P<type>0100|0200)"
    r"(?:[0-9A-Fa-f]{48}|[0-9A-Fa-f]{136}))(?![0-9A-Fa-f])",
    re.IGNORECASE | re.ASCII,
)
_POSTGRESQL_SCRAM = re.compile(
    r"SCRAM-SHA-256\$(?P<iterations>[1-9][0-9]{0,8}):"
    r"(?P<salt>[A-Za-z0-9+/]{2,256}={0,2})\$"
    r"(?P<stored>[A-Za-z0-9+/]{43}=):(?P<server>[A-Za-z0-9+/]{43}=)"
    r"(?![A-Za-z0-9+/=])",
    re.IGNORECASE | re.ASCII,
)
_CISCO_HASH = re.compile(
    r"\$(?P<type>8|9)\$[./A-Za-z0-9]{14}\$[./A-Za-z0-9]{43}"
    r"(?![./A-Za-z0-9])",
    re.ASCII,
)
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

_KERBEROS_FORMATS: dict[tuple[str, str], str] = {
    ("kerberos-tgs-artifact", "17"): "kerberos_tgs_etype17",
    ("kerberos-tgs-artifact", "18"): "kerberos_tgs_etype18",
    ("kerberos-tgs-artifact", "23"): "kerberos_tgs_etype23",
    ("kerberos-asrep-artifact", "17"): "kerberos_asrep_etype17",
    ("kerberos-asrep-artifact", "18"): "kerberos_asrep_etype18",
    ("kerberos-asrep-artifact", "23"): "kerberos_asrep_etype23",
    ("kerberos-preauth-artifact", "17"): "kerberos_preauth_etype17",
    ("kerberos-preauth-artifact", "18"): "kerberos_preauth_etype18",
    ("kerberos-preauth-artifact", "23"): "kerberos_preauth_etype23",
    ("kerberos-db-key", "17"): "kerberos_db_etype17",
    ("kerberos-db-key", "18"): "kerberos_db_etype18",
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
        return (_material("nt", "ntlm", match.group("hash"), _bindings("ntlm")),)

    if rule_id in {"lm-nt-hash-pair", "credential-dump-line"}:
        pattern = _LM_NT_PAIR if rule_id == "lm-nt-hash-pair" else _CREDENTIAL_DUMP
        match = pattern.search(source_line)
        if match is None:
            return ()
        materials = [
            _material("nt", "ntlm", match.group("nt"), _bindings("ntlm")),
        ]
        lm_hash = match.group("lm")
        if lm_hash.casefold() != _EMPTY_LM_HASH:
            materials.append(_material("lm", "lm", lm_hash, _bindings("lm")))
        return tuple(materials)

    if rule_id == "netntlmv1-response" and _NETNTLMV1.fullmatch(source_line):
        return (
            _material(
                "response",
                "netntlmv1",
                source_line,
                _bindings("netntlmv1"),
            ),
        )

    if rule_id == "netntlmv2-response" and _NETNTLMV2.fullmatch(source_line):
        return (
            _material(
                "response",
                "netntlmv2",
                source_line,
                _bindings("netntlmv2"),
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
                    _bindings("dcc2"),
                ),
            )

    if rule_id == "unix-password-hash":
        match = _UNIX_HASH.search(source_line)
        if match is not None:
            format_id = {
                "1": "md5crypt",
                "5": "sha256crypt",
                "6": "sha512crypt",
            }[match.group("type")]
            return (
                _material(
                    "hash",
                    format_id,
                    match.group(0),
                    _bindings(format_id),
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
                    _bindings("bcrypt"),
                ),
            )
        argon2_match = _ARGON2.search(source_line)
        if argon2_match is not None:
            return (
                _material(
                    "hash",
                    "argon2",
                    argon2_match.group(0),
                    _bindings("argon2"),
                ),
            )

    if rule_id == "portable-php-password-hash":
        match = _PORTABLE_PHP.search(source_line)
        if match is not None:
            format_id = "phpass" if match.group("phpass") is not None else "drupal7"
            return (
                _material(
                    "hash",
                    format_id,
                    match.group(0),
                    _bindings(format_id),
                ),
            )

    if rule_id == "apache-apr1-hash":
        match = _APR1.search(source_line)
        if match is not None:
            return (_material("hash", "apr1", match.group(0), _bindings("apr1")),)

    if rule_id == "pbkdf2-password-hash":
        django_match = _DJANGO_PBKDF2.search(source_line)
        if django_match is not None:
            format_id = "django_pbkdf2_sha256"
            return (
                _material(
                    "hash",
                    format_id,
                    django_match.group(0),
                    _bindings(format_id),
                ),
            )
        passlib_match = _PASSLIB_PBKDF2.search(source_line)
        if passlib_match is not None:
            format_id = {
                None: "passlib_pbkdf2_sha1",
                "-sha256": "passlib_pbkdf2_sha256",
                "-sha512": "passlib_pbkdf2_sha512",
            }[passlib_match.group("type")]
            expected_digest_length = {
                "passlib_pbkdf2_sha1": 27,
                "passlib_pbkdf2_sha256": 43,
                "passlib_pbkdf2_sha512": 86,
            }[format_id]
            if len(passlib_match.group("digest")) != expected_digest_length:
                return ()
            return (
                _material(
                    "hash",
                    format_id,
                    passlib_match.group(0),
                    _bindings(format_id),
                ),
            )

    if rule_id == "ldap-password-hash":
        match = _LDAP_HASH.search(source_line)
        if match is not None:
            hash_type = match.group("type").casefold()
            format_id, digest_size, salted = {
                "sha": ("ldap_sha1", 20, False),
                "ssha": ("ldap_ssha1", 20, True),
                "ssha256": ("ldap_ssha256", 32, True),
                "ssha512": ("ldap_ssha512", 64, True),
            }[hash_type]
            decoded_size = _decoded_base64_size(match.group("payload"))
            if decoded_size is None:
                return ()
            if salted and decoded_size <= digest_size:
                return ()
            if not salted and decoded_size != digest_size:
                return ()
            return (
                _material(
                    "hash",
                    format_id,
                    match.group(0),
                    _bindings(format_id),
                ),
            )

    if rule_id == "mysql-password-hash":
        match = _MYSQL_HASH.search(source_line)
        if match is not None:
            return (
                _material(
                    "hash",
                    "mysql_sha1",
                    match.group("hash"),
                    _bindings("mysql_sha1"),
                ),
            )

    if rule_id == "mssql-password-hash":
        match = _MSSQL_HASH.search(source_line)
        if match is not None:
            format_id = (
                "mssql_2005"
                if match.group("type").casefold() == "0100"
                else "mssql_2012"
            )
            expected_length = 54 if format_id == "mssql_2005" else 142
            if len(match.group("hash")) == expected_length:
                return (
                    _material(
                        "hash",
                        format_id,
                        match.group("hash"),
                        _bindings(format_id),
                    ),
                )

    if rule_id == "postgresql-scram-hash":
        match = _POSTGRESQL_SCRAM.search(source_line)
        if match is not None:
            if (
                _decoded_base64_size(match.group("salt")) in {None, 0}
                or _decoded_base64_size(match.group("stored")) != 32
                or _decoded_base64_size(match.group("server")) != 32
            ):
                return ()
            format_id = "postgresql_scram_sha256"
            return (
                _material(
                    "hash",
                    format_id,
                    match.group(0),
                    _bindings(format_id),
                ),
            )

    if rule_id == "cisco-password-hash":
        match = _CISCO_HASH.search(source_line)
        if match is not None:
            format_id = f"cisco_type{match.group('type')}"
            return (
                _material(
                    "hash",
                    format_id,
                    match.group(0),
                    _bindings(format_id),
                ),
            )

    kerberos_pattern = _KERBEROS.get(rule_id)
    if kerberos_pattern is not None:
        match = kerberos_pattern.search(source_line)
        if match is None:
            return ()
        format_id = _KERBEROS_FORMATS[(rule_id, match.group("etype"))]
        return (
            _material(
                "artifact",
                format_id,
                match.group(0).rstrip(",;"),
                _bindings(format_id),
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


def _decoded_base64_size(value: str) -> int | None:
    try:
        return len(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        return None
