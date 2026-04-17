"""Security primitives for the loopback-only web application.

The module is deliberately framework-neutral. Route and middleware adapters can
translate :class:`SafeHttpError` into a response without ever accepting a raw
exception message as browser-visible content.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import MutableMapping
from enum import StrEnum

CSRF_HEADER_NAME = "X-CSRF-Token"
_MINIMUM_NONCE_BYTES = 32

_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)

_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Cache-Control", "no-store, max-age=0"),
    ("Pragma", "no-cache"),
    ("Expires", "0"),
    ("Content-Security-Policy", _CONTENT_SECURITY_POLICY),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "camera=(), geolocation=(), microphone=()"),
)


class HttpErrorCode(StrEnum):
    """Finite set of errors that are safe to return to the browser."""

    BAD_REQUEST = "BAD_REQUEST"
    SAME_ORIGIN_REQUIRED = "SAME_ORIGIN_REQUIRED"
    CSRF_REJECTED = "CSRF_REJECTED"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


_HTTP_ERRORS: dict[HttpErrorCode, tuple[int, str]] = {
    HttpErrorCode.BAD_REQUEST: (400, "The request is invalid."),
    HttpErrorCode.SAME_ORIGIN_REQUIRED: (403, "A same-origin request is required."),
    HttpErrorCode.CSRF_REJECTED: (403, "The request token is invalid."),
    HttpErrorCode.NOT_FOUND: (404, "The requested resource was not found."),
    HttpErrorCode.CONFLICT: (409, "The request conflicts with the current state."),
    HttpErrorCode.PAYLOAD_TOO_LARGE: (413, "The request body is too large."),
    HttpErrorCode.INTERNAL_ERROR: (500, "The request could not be completed."),
}


class SafeHttpError(Exception):
    """An HTTP error that can contain only a pre-approved public message.

    Raw exceptions, SMB status text, paths, targets, and submitted values are
    intentionally not fields on this model. The route boundary may retain such
    details in RAM elsewhere for the live UI, but must not derive an HTTP error
    body or log line from ``repr(raw_exception)``.
    """

    __slots__ = ("code",)

    def __init__(self, code: HttpErrorCode) -> None:
        if not isinstance(code, HttpErrorCode):
            raise TypeError("code must be an HttpErrorCode")
        self.code = code
        super().__init__(code.value)

    @property
    def status_code(self) -> int:
        return _HTTP_ERRORS[self.code][0]

    @property
    def public_message(self) -> str:
        return _HTTP_ERRORS[self.code][1]

    def as_payload(self) -> dict[str, dict[str, str]]:
        return {
            "error": {
                "code": self.code.value,
                "message": self.public_message,
            }
        }

    @classmethod
    def from_exception(
        cls,
        _exception: BaseException,
        *,
        code: HttpErrorCode = HttpErrorCode.INTERNAL_ERROR,
    ) -> SafeHttpError:
        """Create a safe error while deliberately discarding the raw exception."""

        return cls(code)

    def __str__(self) -> str:
        return f"{self.code.value}: {self.public_message}"

    def __repr__(self) -> str:
        return (
            f"SafeHttpError(code={self.code.value!r}, "
            f"status_code={self.status_code}, detail=<redacted>)"
        )


class CsrfNonce:
    """A process-local CSRF nonce generated from the OS CSPRNG."""

    __slots__ = ("_value",)

    def __init__(self, byte_length: int = _MINIMUM_NONCE_BYTES) -> None:
        if isinstance(byte_length, bool) or not isinstance(byte_length, int):
            raise TypeError("byte_length must be an integer")
        if byte_length < _MINIMUM_NONCE_BYTES:
            raise ValueError(f"CSRF nonces require at least {_MINIMUM_NONCE_BYTES} bytes.")
        self._value = secrets.token_urlsafe(byte_length)

    @property
    def value(self) -> str:
        """Return the value that the server-rendered page places in the DOM."""

        return self._value

    def matches(self, candidate: object) -> bool:
        """Validate a submitted nonce using a constant-time comparison."""

        if not isinstance(candidate, str) or not candidate.isascii():
            return False
        return hmac.compare_digest(self._value, candidate)

    def require(self, candidate: object) -> None:
        if not self.matches(candidate):
            raise SafeHttpError(HttpErrorCode.CSRF_REJECTED)

    def __repr__(self) -> str:
        return "CsrfNonce(value=<redacted>)"


def expected_loopback_origin(port: int) -> str:
    """Build the only origin accepted by state-changing routes."""

    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError("port must be an integer")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return f"http://127.0.0.1:{port}"


def require_same_origin(origin: object, *, port: int) -> None:
    """Reject missing, malformed, or non-loopback Origin header values.

    Exact serialized-origin matching intentionally rejects aliases such as
    ``localhost``, trailing slashes, user-info, multiple values, and HTTPS.
    """

    expected = expected_loopback_origin(port)
    if not isinstance(origin, str) or not origin.isascii():
        raise SafeHttpError(HttpErrorCode.SAME_ORIGIN_REQUIRED)
    if not hmac.compare_digest(origin, expected):
        raise SafeHttpError(HttpErrorCode.SAME_ORIGIN_REQUIRED)


def require_post_security(
    *,
    origin: object,
    csrf_candidate: object,
    csrf_nonce: CsrfNonce,
    port: int,
) -> None:
    """Apply the mandatory origin and nonce checks for a POST request."""

    if not isinstance(csrf_nonce, CsrfNonce):
        raise TypeError("csrf_nonce must be a CsrfNonce")
    require_same_origin(origin, port=port)
    csrf_nonce.require(csrf_candidate)


def security_headers() -> dict[str, str]:
    """Return a fresh copy of the headers required on every response."""

    return dict(_SECURITY_HEADERS)


def apply_security_headers(headers: MutableMapping[str, str]) -> None:
    """Overwrite unsafe values without leaving differently-cased duplicates."""

    for name, value in _SECURITY_HEADERS:
        for existing_name in tuple(headers):
            if existing_name != name and existing_name.casefold() == name.casefold():
                del headers[existing_name]
        headers[name] = value
