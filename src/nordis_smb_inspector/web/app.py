"""Starlette adapter for the local, memory-only inspection panel."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from importlib.resources import files
from itertools import islice
from typing import Any

import anyio
from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from nordis_smb_inspector.core.session import ScanSessionManager
from nordis_smb_inspector.core.targets import (
    ExpandedTarget,
    ResolutionFailure,
    TargetParseError,
    parse_targets,
)
from nordis_smb_inspector.web.events import InvalidEventCursor, SseEventBroker
from nordis_smb_inspector.web.security import (
    CSRF_HEADER_NAME,
    CsrfNonce,
    HttpErrorCode,
    SafeHttpError,
    apply_security_headers,
    require_post_security,
)

_MAX_JSON_BODY_BYTES = 64 * 1024
_PREVIEW_ROW_LIMIT = 500
_STATIC_ASSETS: dict[str, str] = {
    "app.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
}

_templates = Environment(
    loader=PackageLoader("nordis_smb_inspector.web", "templates"),
    autoescape=select_autoescape(("html", "xml")),
    enable_async=False,
)


@dataclass(slots=True)
class WebRuntime:
    port: int
    csrf: CsrfNonce
    sessions: ScanSessionManager
    events: SseEventBroker


class SecurityHeadersMiddleware:
    """Apply non-persistence and browser hardening headers to every response."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        async def secure_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                decoded = {
                    name.decode("latin-1"): value.decode("latin-1")
                    for name, value in message.get("headers", ())
                }
                apply_security_headers(decoded)
                message["headers"] = [
                    (name.encode("latin-1"), value.encode("latin-1"))
                    for name, value in decoded.items()
                ]
            await send(message)

        await self.app(scope, receive, secure_send)


def create_app(*, port: int = 8765) -> Starlette:
    runtime = WebRuntime(
        port=port,
        csrf=CsrfNonce(),
        sessions=ScanSessionManager(),
        events=SseEventBroker(capacity=2048),
    )
    routes = [
        Route("/", homepage, methods=["GET"]),
        Route("/scope/preview", scope_preview, methods=["POST"]),
        Route("/scan/snapshot", scan_snapshot, methods=["GET"]),
        Route("/scan/events", scan_events, methods=["GET"]),
        Route("/static/{asset_name}", static_asset, methods=["GET"]),
    ]
    middleware = [
        Middleware(SecurityHeadersMiddleware),
        Middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1"]),
    ]
    app = Starlette(
        debug=False,
        routes=routes,
        middleware=middleware,
        exception_handlers={SafeHttpError: safe_http_error},
    )
    app.state.runtime = runtime
    return app


async def homepage(request: Request) -> HTMLResponse:
    runtime = _runtime(request)
    template = _templates.get_template("index.html")
    return HTMLResponse(
        template.render(
            csrf_token=runtime.csrf.value,
            app_origin=f"http://127.0.0.1:{runtime.port}",
        )
    )


async def scope_preview(request: Request) -> JSONResponse:
    runtime = _runtime(request)
    _protect_post(request, runtime)
    body = await _read_json(request)
    target_expression = body.get("targets")
    if not isinstance(target_expression, str):
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST)

    try:
        plan = parse_targets(target_expression)
    except TargetParseError as exc:
        return JSONResponse(
            {
                "ok": False,
                "errors": [
                    {"value": error.value, "reason": error.reason}
                    for error in exc.errors
                ],
            },
            status_code=422,
        )

    events = list(islice(plan.iter_expanded(), _PREVIEW_ROW_LIMIT + 1))
    display_limited = len(events) > _PREVIEW_ROW_LIMIT
    visible_events = events[:_PREVIEW_ROW_LIMIT]
    return JSONResponse(
        {
            "ok": True,
            "known_address_count": plan.known_address_count,
            "hostname_count": plan.hostname_count,
            "display_limit": _PREVIEW_ROW_LIMIT,
            "display_limited": display_limited,
            "rows": [_target_event_payload(event) for event in visible_events],
        }
    )


async def scan_snapshot(request: Request) -> JSONResponse:
    state = _runtime(request).sessions.snapshot
    progress = state.progress
    return JSONResponse(
        {
            "status": state.status.value,
            "generation": state.generation,
            "scan_id": state.scan_id,
            "inventory_count": state.inventory_count,
            "finding_count": state.finding_count,
            "partial": state.partial,
            "terminal_reason": state.terminal_reason.value if state.terminal_reason else None,
            "progress": None
            if progress is None
            else {
                "sequence": progress.sequence,
                "phase": progress.phase.value,
                "phase_completed": progress.phase_completed,
                "phase_total": progress.phase_total,
                "phase_percent": progress.phase_percent,
                "overall_percent": progress.overall_percent,
                "overall_is_estimate": progress.overall_is_estimate,
                "counters": dict(progress.counters),
                "message": progress.message,
            },
        }
    )


async def scan_events(request: Request) -> StreamingResponse:
    broker = _runtime(request).events
    cursor_value = request.headers.get("last-event-id")
    try:
        replay = broker.replay_after(cursor_value, limit=200)
    except InvalidEventCursor as exc:
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST) from exc

    async def stream() -> AsyncIterator[bytes]:
        cursor = replay.requested_after_id
        current = replay
        while True:
            if await request.is_disconnected():
                return
            if current.resync_required:
                for frame in current.to_sse():
                    yield frame
                cursor = current.latest_event_id
            elif current.events:
                for event in current.events:
                    yield event.to_sse()
                    cursor = event.event_id
            elif current.closed:
                return
            else:
                yield b": keepalive\n\n"

            for _tick in range(60):
                await anyio.sleep(0.25)
                if await request.is_disconnected():
                    return
                current = broker.replay_after(cursor, limit=200)
                if current.events or current.resync_required or current.closed:
                    break
            else:
                current = broker.replay_after(cursor, limit=200)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no"},
    )


async def static_asset(request: Request) -> Response:
    asset_name = request.path_params["asset_name"]
    media_type = _STATIC_ASSETS.get(asset_name)
    if media_type is None:
        raise SafeHttpError(HttpErrorCode.NOT_FOUND)
    data = files("nordis_smb_inspector.web").joinpath("static", asset_name).read_bytes()
    return Response(data, media_type=media_type)


async def safe_http_error(_request: Request, exc: SafeHttpError) -> JSONResponse:
    return JSONResponse(exc.as_payload(), status_code=exc.status_code)


def _runtime(request: Request) -> WebRuntime:
    runtime = request.app.state.runtime
    if not isinstance(runtime, WebRuntime):
        raise RuntimeError("Web runtime is not initialized.")
    return runtime


def _protect_post(request: Request, runtime: WebRuntime) -> None:
    require_post_security(
        origin=request.headers.get("origin"),
        csrf_candidate=request.headers.get(CSRF_HEADER_NAME),
        csrf_nonce=runtime.csrf,
        port=runtime.port,
    )


async def _read_json(request: Request) -> Mapping[str, object]:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type.casefold() != "application/json":
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST)

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_JSON_BODY_BYTES:
            raise SafeHttpError(HttpErrorCode.PAYLOAD_TOO_LARGE)
        body.extend(chunk)
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST) from exc
    if not isinstance(value, dict):
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST)
    return value


def _target_event_payload(event: ExpandedTarget | ResolutionFailure) -> dict[str, object]:
    if isinstance(event, ResolutionFailure):
        return {
            "status": "resolution_failed",
            "source": event.source,
            "hostname": event.hostname,
            "error_code": event.error_code,
            "message": event.message,
        }
    return {
        "status": "resolved",
        "source": event.source,
        "source_kind": event.source_kind.value,
        "source_hostname": event.source_hostname,
        "address": str(event.address),
        "ip_version": event.address.version,
    }
