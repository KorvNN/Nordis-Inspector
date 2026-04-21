"""Starlette adapter for the local, memory-only inspection panel."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from threading import RLock, Thread
from typing import Any

import anyio
from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from nordis_smb_inspector.core.connectivity import (
    ConnectivityResult,
    ConnectivityScanner,
    ConnectivityStatus,
)
from nordis_smb_inspector.core.progress import ScanPhase
from nordis_smb_inspector.core.session import (
    InvalidScanTransition,
    ScanAlreadyRunning,
    ScanHandle,
    ScanSessionManager,
)
from nordis_smb_inspector.core.targets import (
    TargetParseError,
    TargetPlan,
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
    connectivity: ConnectivityScanner
    _target_lock: RLock = field(default_factory=RLock, repr=False)
    _target_generation: int = field(default=0, repr=False)
    _targets: dict[str, dict[str, object]] = field(default_factory=dict, repr=False)
    worker: Thread | None = field(default=None, repr=False)

    def reset_targets(self, generation: int) -> None:
        with self._target_lock:
            self._target_generation = generation
            self._targets.clear()

    def update_target(self, generation: int, result: ConnectivityResult) -> dict[str, object]:
        payload = _connectivity_payload(result, generation=generation)
        key = str(payload["address"])
        with self._target_lock:
            if generation != self._target_generation:
                return payload
            if _is_confirmed_target(result.status):
                self._targets[key] = payload
        return payload

    def target_snapshot(self, generation: int) -> list[dict[str, object]]:
        with self._target_lock:
            if generation != self._target_generation:
                return []
            return [dict(item) for item in self._targets.values()]


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


def create_app(
    *,
    port: int = 8765,
    connectivity_scanner: ConnectivityScanner | None = None,
) -> Starlette:
    runtime = WebRuntime(
        port=port,
        csrf=CsrfNonce(),
        sessions=ScanSessionManager(),
        events=SseEventBroker(capacity=2048),
        connectivity=connectivity_scanner or ConnectivityScanner(),
    )
    routes = [
        Route("/", homepage, methods=["GET"]),
        Route("/scan", scan_start, methods=["POST"]),
        Route("/scan/cancel", scan_cancel, methods=["POST"]),
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


async def scan_snapshot(request: Request) -> JSONResponse:
    return JSONResponse(_snapshot_payload(_runtime(request)))


async def scan_start(request: Request) -> JSONResponse:
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

    try:
        handle = runtime.sessions.begin_scan()
    except ScanAlreadyRunning as exc:
        raise SafeHttpError(HttpErrorCode.CONFLICT) from exc

    runtime.reset_targets(handle.token.generation)
    phase_total = (
        plan.known_address_count
        if plan.hostname_count == 0 and len(plan.specs) == 1
        else None
    )
    handle.progress.set_phase(
        ScanPhase.CONNECTIVITY,
        total=phase_total,
        message="TCP/445 hedefleri kontrol ediliyor.",
        overall_percent=0,
        overall_is_estimate=phase_total is None,
    )
    runtime.events.publish("snapshot", _snapshot_payload(runtime))
    worker = Thread(
        target=_run_connectivity_scan,
        args=(runtime, handle, plan, phase_total),
        name=f"nordis-scan-{handle.token.generation}",
        daemon=True,
    )
    runtime.worker = worker
    worker.start()
    return JSONResponse(
        {
            "ok": True,
            "scan_id": handle.token.scan_id,
            "generation": handle.token.generation,
        },
        status_code=202,
    )


async def scan_cancel(request: Request) -> JSONResponse:
    runtime = _runtime(request)
    _protect_post(request, runtime)
    state = runtime.sessions.snapshot
    token = state.token
    if token is None:
        raise SafeHttpError(HttpErrorCode.CONFLICT)
    try:
        runtime.sessions.request_cancel(token)
    except InvalidScanTransition as exc:
        raise SafeHttpError(HttpErrorCode.CONFLICT) from exc
    payload = _snapshot_payload(runtime)
    runtime.events.publish("snapshot", payload)
    return JSONResponse(payload, status_code=202)


def _snapshot_payload(runtime: WebRuntime) -> dict[str, object]:
    state = runtime.sessions.snapshot
    progress = state.progress
    return {
        "status": state.status.value,
        "generation": state.generation,
        "scan_id": state.scan_id,
        "inventory_count": state.inventory_count,
        "finding_count": state.finding_count,
        "partial": state.partial,
        "terminal_reason": state.terminal_reason.value if state.terminal_reason else None,
        "targets": runtime.target_snapshot(state.generation),
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


def _run_connectivity_scan(
    runtime: WebRuntime,
    handle: ScanHandle,
    plan: TargetPlan,
    phase_total: int | None,
) -> None:
    completed = 0
    try:
        for result in runtime.connectivity.iter_results(
            plan,
            cancellation=handle.cancellation,
        ):
            payload = runtime.update_target(handle.token.generation, result)
            if _is_confirmed_target(result.status):
                runtime.events.publish("target.changed", payload)
            completed += 1
            handle.progress.increment(result.status.value)
            handle.progress.update_progress(
                completed,
                expected_phase=ScanPhase.CONNECTIVITY,
                total=phase_total,
                overall_percent=(
                    completed * 100 / phase_total if phase_total is not None else None
                ),
                overall_is_estimate=phase_total is None,
                message=f"{completed} hedef kontrol edildi.",
            )
            runtime.events.publish("snapshot", _snapshot_payload(runtime))

        runtime.sessions.complete(handle.token)
    except Exception:
        state = runtime.sessions.snapshot
        if state.active:
            runtime.sessions.fail(handle.token)
    finally:
        runtime.events.publish("snapshot", _snapshot_payload(runtime))


def _connectivity_payload(
    result: ConnectivityResult,
    *,
    generation: int,
) -> dict[str, object]:
    address = str(result.address) if result.address is not None else result.source_hostname
    return {
        "generation": generation,
        "address": address or result.source,
        "source": result.source,
        "source_kind": result.source_kind.value,
        "tcp_status": result.status.value,
        "smb_status": None,
        "authentication_status": None,
        "last_status": result.status.value,
        "port": result.port,
        "elapsed_ms": result.elapsed_ms,
        "os_error_code": result.os_error_code,
        "error_name": result.error_name,
    }


def _is_confirmed_target(status: ConnectivityStatus) -> bool:
    """Return whether the target positively answered the TCP attempt."""

    return status in {
        ConnectivityStatus.PORT_OPEN,
        ConnectivityStatus.CONNECTION_REFUSED,
    }


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
