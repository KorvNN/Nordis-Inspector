"""Framework-neutral primitives used by the local web panel."""

from .events import (
    EventReplay,
    SseEvent,
    SseEventBroker,
    format_sse,
    parse_last_event_id,
)
from .security import (
    CSRF_HEADER_NAME,
    CsrfNonce,
    HttpErrorCode,
    SafeHttpError,
    apply_security_headers,
    expected_loopback_origin,
    require_post_security,
    require_same_origin,
    security_headers,
)

__all__ = [
    "CSRF_HEADER_NAME",
    "CsrfNonce",
    "EventReplay",
    "HttpErrorCode",
    "SafeHttpError",
    "SseEvent",
    "SseEventBroker",
    "apply_security_headers",
    "expected_loopback_origin",
    "format_sse",
    "parse_last_event_id",
    "require_post_security",
    "require_same_origin",
    "security_headers",
]
