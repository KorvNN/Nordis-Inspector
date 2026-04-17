"""Credential input models that never expose secret values through ``repr``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_HEX_32 = re.compile(r"^[0-9a-fA-F]{32}$")


class CredentialValidationError(ValueError):
    """Raised when a credential form cannot represent a valid input."""


class CredentialKind(StrEnum):
    PASSWORD = "password"
    NT_HASH = "nt_hash"
    CCACHE = "ccache"


class AuthMode(StrEnum):
    AUTO = "auto"
    KERBEROS_ONLY = "kerberos_only"
    NTLM_ONLY = "ntlm_only"


@dataclass(frozen=True, slots=True, repr=False)
class Credential:
    """One explicitly selected authentication input.

    Only the field matching :attr:`kind` may contain a value.  Passwords and
    hashes intentionally do not appear in the generated representation.
    """

    kind: CredentialKind
    auth_mode: AuthMode
    username: str | None = None
    domain: str | None = None
    password: str | None = None
    nt_hash: str | None = None
    ccache_name: str | None = None
    ccache_data: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CredentialKind):
            raise CredentialValidationError("Credential kind must be a CredentialKind value.")
        if not isinstance(self.auth_mode, AuthMode):
            raise CredentialValidationError("Authentication mode must be an AuthMode value.")

        username = _clean_optional(self.username, "Username")
        domain = _clean_optional(self.domain, "Domain")
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "domain", domain)
        if self.password is not None and not isinstance(self.password, str):
            raise CredentialValidationError("Password must be text.")
        if self.nt_hash is not None and not isinstance(self.nt_hash, str):
            raise CredentialValidationError("NT hash must be text.")
        if self.ccache_data is not None:
            if not isinstance(self.ccache_data, (bytes, bytearray, memoryview)):
                raise CredentialValidationError("CCache data must be bytes.")
            object.__setattr__(self, "ccache_data", bytes(self.ccache_data))
        if self.ccache_name is not None:
            object.__setattr__(self, "ccache_name", _safe_upload_label(self.ccache_name))

        populated = sum(
            value is not None
            for value in (self.password, self.nt_hash, self.ccache_data)
        )
        if populated != 1:
            raise CredentialValidationError(
                "Exactly one of password, NT hash, or ccache data must be supplied."
            )

        if self.kind is CredentialKind.PASSWORD:
            self._validate_password()
        elif self.kind is CredentialKind.NT_HASH:
            self._validate_nt_hash()
        elif self.kind is CredentialKind.CCACHE:
            self._validate_ccache()
        else:  # pragma: no cover - defensive for runtime enum misuse
            raise CredentialValidationError(f"Unsupported credential kind: {self.kind!r}")

    @classmethod
    def from_password(
        cls,
        *,
        username: str,
        password: str,
        domain: str | None,
        auth_mode: AuthMode = AuthMode.AUTO,
    ) -> Credential:
        return cls(
            kind=CredentialKind.PASSWORD,
            auth_mode=auth_mode,
            username=username,
            domain=domain,
            password=password,
        )

    @classmethod
    def from_nt_hash(
        cls,
        *,
        username: str,
        nt_hash: str,
        domain: str | None,
        auth_mode: AuthMode = AuthMode.NTLM_ONLY,
    ) -> Credential:
        normalized = _normalize_nt_hash(nt_hash)
        return cls(
            kind=CredentialKind.NT_HASH,
            auth_mode=auth_mode,
            username=username,
            domain=domain,
            nt_hash=normalized,
        )

    @classmethod
    def from_ccache(
        cls,
        *,
        filename: str,
        data: bytes,
        username: str | None = None,
        domain: str | None = None,
    ) -> Credential:
        return cls(
            kind=CredentialKind.CCACHE,
            auth_mode=AuthMode.KERBEROS_ONLY,
            username=username,
            domain=domain,
            ccache_name=filename,
            ccache_data=data,
        )

    @property
    def ntlm_fallback_available(self) -> bool:
        """Whether this input can be used to create an NTLM response."""

        return self.kind in {CredentialKind.PASSWORD, CredentialKind.NT_HASH}

    def _validate_password(self) -> None:
        if not self.username:
            raise CredentialValidationError("Username is required for password authentication.")
        if self.password is None:
            raise CredentialValidationError("Password input is missing.")
        if self.nt_hash is not None or self.ccache_data is not None:
            raise CredentialValidationError(
                "Password credentials cannot contain another secret type."
            )
        if self.ccache_name is not None:
            raise CredentialValidationError("Password credentials cannot contain ccache metadata.")

    def _validate_nt_hash(self) -> None:
        if not self.username:
            raise CredentialValidationError("Username is required for NT hash authentication.")
        if self.nt_hash is None or not _HEX_32.fullmatch(self.nt_hash):
            raise CredentialValidationError(
                "NT hash must contain exactly 32 hexadecimal characters."
            )
        if self.auth_mode is not AuthMode.NTLM_ONLY:
            raise CredentialValidationError("An NT hash credential can only use NTLM-only mode.")
        if self.password is not None or self.ccache_data is not None:
            raise CredentialValidationError(
                "NT hash credentials cannot contain another secret type."
            )
        if self.ccache_name is not None:
            raise CredentialValidationError("NT hash credentials cannot contain ccache metadata.")

    def _validate_ccache(self) -> None:
        if self.auth_mode is not AuthMode.KERBEROS_ONLY:
            raise CredentialValidationError("A ccache credential can only use Kerberos-only mode.")
        if not self.ccache_name or not self.ccache_name.strip():
            raise CredentialValidationError("CCache filename is required.")
        if not self.ccache_data:
            raise CredentialValidationError("CCache file is empty.")
        if self.password is not None or self.nt_hash is not None:
            raise CredentialValidationError(
                "CCache credentials cannot contain another secret type."
            )

    def __repr__(self) -> str:
        return (
            f"Credential(kind={self.kind.value!r}, auth_mode={self.auth_mode.value!r}"
            ", identity=<redacted>, secret=<redacted>)"
        )


def _clean_optional(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CredentialValidationError(f"{field_name} must be text.")
    cleaned = value.strip()
    return cleaned or None


def _normalize_nt_hash(value: str) -> str:
    if not isinstance(value, str):
        raise CredentialValidationError("NT hash must be text.")
    candidate = value.strip()
    if ":" in candidate:
        parts = candidate.split(":")
        if len(parts) != 2:
            raise CredentialValidationError("Use NTHASH or LMHASH:NTHASH format.")
        lm_hash, candidate = parts
        if lm_hash and not _HEX_32.fullmatch(lm_hash):
            raise CredentialValidationError("LM hash must contain 32 hexadecimal characters.")
    if not _HEX_32.fullmatch(candidate):
        raise CredentialValidationError("NT hash must contain exactly 32 hexadecimal characters.")
    return candidate.lower()


def _safe_upload_label(value: str) -> str:
    """Keep a browser filename as display metadata, never as a filesystem path."""

    if not isinstance(value, str):
        raise CredentialValidationError("CCache filename must be text.")
    candidate = value.replace("\\", "/").rsplit("/", 1)[-1].replace("\x00", "").strip()
    if candidate in {"", ".", ".."}:
        raise CredentialValidationError("CCache filename is invalid.")
    return candidate
