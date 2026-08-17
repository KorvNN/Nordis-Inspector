"""Bounded identification of binary credential-container files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .detection import DetectionConfidence

_HEADER_BYTES = 16
_CCACHE_SUFFIXES = frozenset({".ccache"})
_KEYTAB_SUFFIXES = frozenset({".keytab", ".ktab"})
_CREDENTIAL_CONTAINER_SUFFIXES = frozenset({".kdb", ".kdbx", ".p12", ".pfx", ".ppk"})
_PRIVATE_KEY_SUFFIXES = frozenset({".key", ".pem"})
_NOISE_FILENAME_SUFFIXES = (".adml", ".admx", ".exe")
_SUSPICIOUS_FILENAME_KEYWORDS = (
    "şifre",
    "sifre",
    "parola",
    "sunucu bilgi",
    "sunucu",
    "kimlik bilgi",
    "erişim bilgi",
    "erisim bilgi",
    "giriş bilgi",
    "giris bilgi",
    "envanter",
    "yedek",
    "hesap",
    "bağlantı",
    "baglanti",
    "credential",
    "password",
    "creds",
    "secret",
    "apikey",
    "api key",
    "api-key",
    "token",
    "vault",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    "id_ecdsa",
    "server",
    "inventory",
    "backup",
    "account",
    "connection",
)


@dataclass(frozen=True, slots=True)
class CredentialArtifactMatch:
    rule_id: str
    title: str
    category: str
    confidence: DetectionConfidence


KERBEROS_CCACHE = CredentialArtifactMatch(
    rule_id="kerberos-ccache-file",
    title="Kerberos credential cache",
    category="Windows / AD",
    confidence=DetectionConfidence.HIGH,
)
KERBEROS_KEYTAB = CredentialArtifactMatch(
    rule_id="kerberos-keytab-file",
    title="Kerberos keytab",
    category="Windows / AD",
    confidence=DetectionConfidence.HIGH,
)
KERBEROS_KIRBI = CredentialArtifactMatch(
    rule_id="kerberos-kirbi-file",
    title="Kerberos ticket file",
    category="Windows / AD",
    confidence=DetectionConfidence.HIGH,
)
CREDENTIAL_CONTAINER_FILENAME = CredentialArtifactMatch(
    rule_id="credential-container-filename",
    title="Credential container filename",
    category="Credential artifact",
    confidence=DetectionConfidence.MEDIUM,
)
PRIVATE_KEY_FILENAME = CredentialArtifactMatch(
    rule_id="private-key-filename",
    title="Private-key filename",
    category="Credential artifact",
    confidence=DetectionConfidence.MEDIUM,
)
CREDENTIAL_RELATED_FILENAME = CredentialArtifactMatch(
    rule_id="credential-related-filename",
    title="Credential-related filename",
    category="Credential artifact",
    confidence=DetectionConfidence.MEDIUM,
)


def credential_artifact_header_bytes() -> int:
    return _HEADER_BYTES


def detect_credential_artifact_name(path: str) -> CredentialArtifactMatch | None:
    """Flag credential-related file names without reading remote content.

    This deliberately evaluates only the basename. Common Windows policy and
    executable extensions are excluded before broad keyword matching to avoid
    well-known noise such as ``CredentialProviders.admx``.
    """

    if not isinstance(path, str):
        raise TypeError("path must be text.")
    normalized = path.replace("\\", "/").casefold()
    name = PurePosixPath(normalized).name
    if not name or name.endswith(_NOISE_FILENAME_SUFFIXES):
        return None
    suffix = PurePosixPath(name).suffix
    if suffix in _CREDENTIAL_CONTAINER_SUFFIXES:
        return CREDENTIAL_CONTAINER_FILENAME
    if suffix in _PRIVATE_KEY_SUFFIXES:
        return PRIVATE_KEY_FILENAME
    if any(keyword in name for keyword in _SUSPICIOUS_FILENAME_KEYWORDS):
        return CREDENTIAL_RELATED_FILENAME
    return None


def detect_credential_artifact(
    path: str,
    header: bytes | bytearray | memoryview,
) -> CredentialArtifactMatch | None:
    """Identify a known credential container from its name and bounded header."""

    if not isinstance(path, str):
        raise TypeError("path must be text.")
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise TypeError("header must be bytes-like.")

    data = bytes(header)
    normalized = path.replace("\\", "/").casefold()
    name = PurePosixPath(normalized).name
    suffix = PurePosixPath(normalized).suffix

    ccache_name = suffix in _CCACHE_SUFFIXES or name.startswith("krb5cc_")
    if ccache_name and len(data) >= 4 and data[0] == 5 and data[1] in {1, 2, 3, 4}:
        return KERBEROS_CCACHE

    keytab_name = suffix in _KEYTAB_SUFFIXES or name == "krb5.keytab"
    if keytab_name and len(data) >= 6 and data[:2] in {b"\x05\x01", b"\x05\x02"}:
        return KERBEROS_KEYTAB

    if suffix == ".kirbi" and len(data) >= 4 and data[0] == 0x76:
        return KERBEROS_KIRBI

    return None
