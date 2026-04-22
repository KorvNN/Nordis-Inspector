"""Starlette adapter for the local, memory-only inspection panel."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from threading import RLock, Thread
from typing import Any, Protocol

import anyio
from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from nordis_smb_inspector.core.access_pipeline import (
    AccessEventKind as PipelineEventKind,
)
from nordis_smb_inspector.core.access_pipeline import (
    AccessPipelineEvent,
    AccessPipelineExecutor,
    AccessPipelineSettings,
)
from nordis_smb_inspector.core.credentials import (
    AuthMode,
    Credential,
    CredentialKind,
    CredentialValidationError,
)
from nordis_smb_inspector.core.progress import ScanPhase
from nordis_smb_inspector.core.session import (
    InvalidScanTransition,
    ScanAlreadyRunning,
    ScanHandle,
    ScanSessionManager,
)
from nordis_smb_inspector.core.targets import (
    ExpandedTarget,
    TargetParseError,
    TargetPlan,
    parse_targets,
)
from nordis_smb_inspector.smb.cancellation import (
    ScanCancelled as SmbScanCancelled,
)
from nordis_smb_inspector.smb.contracts import ConnectRequest
from nordis_smb_inspector.smb.models import (
    TargetStage,
    TargetStatus,
)
from nordis_smb_inspector.smb.smbprotocol_adapter import SmbProtocolConnector
from nordis_smb_inspector.smb.smbprotocol_auth_adapter import SmbProtocolAuthenticator
from nordis_smb_inspector.smb.workflow import (
    AccessEvent,
    AccessEventKind,
    TargetAccessResult,
    inspect_target_access,
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
_MAX_TARGET_WORKERS = 32
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
    connector: Any = field(repr=False)
    authenticator: Any = field(repr=False)
    access_inspector: Any = field(repr=False)
    _target_lock: RLock = field(default_factory=RLock, repr=False)
    _target_generation: int = field(default=0, repr=False)
    _targets: dict[str, dict[str, object]] = field(default_factory=dict, repr=False)
    worker: Thread | None = field(default=None, repr=False)

    def reset_targets(self, generation: int) -> None:
        with self._target_lock:
            self._target_generation = generation
            self._targets.clear()

    def update_target(self, generation: int, payload: dict[str, object]) -> bool:
        key = str(payload["address"])
        with self._target_lock:
            if generation != self._target_generation:
                return False
            self._targets[key] = dict(payload)
            return True

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


class AccessInspector(Protocol):
    def __call__(self, **kwargs: object) -> TargetAccessResult: ...


@dataclass(frozen=True, slots=True)
class _CancellationBridge:
    signal: Any = field(repr=False)

    @property
    def cancelled(self) -> bool:
        return bool(self.signal.requested)

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise SmbScanCancelled()


def create_app(
    *,
    port: int = 8765,
    connector: Any | None = None,
    authenticator: Any | None = None,
    access_inspector: AccessInspector = inspect_target_access,
) -> Starlette:
    runtime = WebRuntime(
        port=port,
        csrf=CsrfNonce(),
        sessions=ScanSessionManager(),
        events=SseEventBroker(capacity=2048),
        connector=connector or SmbProtocolConnector(),
        authenticator=authenticator or SmbProtocolAuthenticator(),
        access_inspector=access_inspector,
    )
    routes = [
        Route("/", homepage, methods=["GET"]),
        Route("/scan", scan_start, methods=["POST"]),
        Route("/scan/cancel", scan_cancel, methods=["POST"]),
        Route("/scan/snapshot", scan_snapshot, methods=["GET"]),
        Route("/scan/events", scan_events, methods=["GET"]),
        Route("/inventory", inventory_results, methods=["GET"]),
        Route("/findings", finding_results, methods=["GET"]),
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


async def inventory_results(request: Request) -> JSONResponse:
    return JSONResponse(_result_page_payload(request, findings=False))


async def finding_results(request: Request) -> JSONResponse:
    return JSONResponse(_result_page_payload(request, findings=True))


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
        credential = _credential_from_body(body.get("credential"))
    except CredentialValidationError as exc:
        return JSONResponse(
            {
                "ok": False,
                "errors": [{"value": "Kimlik bilgisi", "reason": str(exc)}],
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
        ScanPhase.AUTHENTICATION,
        total=phase_total,
        message="SMB bağlantısı ve kimlik doğrulama kontrol ediliyor.",
        overall_percent=0,
        overall_is_estimate=phase_total is None,
    )
    runtime.events.publish("snapshot", _snapshot_payload(runtime))
    worker = Thread(
        target=_run_access_scan,
        args=(runtime, handle, plan, credential, phase_total),
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


def _run_access_scan(
    runtime: WebRuntime,
    handle: ScanHandle,
    plan: TargetPlan,
    credential: Credential,
    phase_total: int | None,
) -> None:
    completed = 0
    cancellation = _CancellationBridge(handle.cancellation)
    executor = AccessPipelineExecutor(
        AccessPipelineSettings(max_concurrency=_MAX_TARGET_WORKERS)
    )

    def inspect_one(
        target: ExpandedTarget,
        target_cancellation: _CancellationBridge,
    ) -> TargetAccessResult:
        address = str(target.address)

        def publish_access_event(event: AccessEvent) -> None:
            payload = _access_event_payload(
                target,
                event,
                generation=handle.token.generation,
            )
            if payload is not None and runtime.update_target(
                handle.token.generation,
                payload,
            ):
                runtime.events.publish("target.changed", payload)

        return runtime.access_inspector(
            target=address,
            connect_request=ConnectRequest(target=address),
            credential=credential,
            kerberos_hostname=target.source_hostname,
            connector=runtime.connector,
            authenticator=runtime.authenticator,
            cancellation=target_cancellation,
            on_event=publish_access_event,
        )

    try:
        for event in executor.iter_events(
            plan,
            inspect_one,
            cancellation=cancellation,
        ):
            counter = _pipeline_counter(event)
            if event.kind is PipelineEventKind.INSPECTION_COMPLETED:
                result = event.result
                if isinstance(result, TargetAccessResult):
                    counter = _result_counter(result)
                    payload = _access_result_payload(
                        event,
                        result,
                        generation=handle.token.generation,
                    )
                    if _is_confirmed_access_result(result) and runtime.update_target(
                        handle.token.generation,
                        payload,
                    ):
                        runtime.events.publish("target.changed", payload)
            completed += 1
            handle.progress.increment(counter)
            handle.progress.update_progress(
                completed,
                expected_phase=ScanPhase.AUTHENTICATION,
                total=phase_total,
                overall_percent=(
                    completed * 100 / phase_total if phase_total is not None else None
                ),
                overall_is_estimate=phase_total is None,
                message=f"{completed} hedefte SMB erişimi kontrol edildi.",
            )
            runtime.events.publish("snapshot", _snapshot_payload(runtime))

        runtime.sessions.complete(handle.token)
    except Exception:
        state = runtime.sessions.snapshot
        if state.active:
            runtime.sessions.fail(handle.token)
    finally:
        runtime.events.publish("snapshot", _snapshot_payload(runtime))


def _access_event_payload(
    target: ExpandedTarget,
    event: AccessEvent,
    *,
    generation: int,
) -> dict[str, object] | None:
    common: dict[str, object] = {
        "generation": generation,
        "address": str(target.address),
        "source": target.source,
        "source_kind": target.source_kind.value,
        "port": 445,
    }
    if event.kind is AccessEventKind.NEGOTIATION_SUCCEEDED and event.negotiation:
        return {
            **common,
            "tcp_status": TargetStatus.PORT_OPEN.value,
            "smb_status": event.negotiation.dialect.value,
            "authentication_status": "authenticating",
            "authentication_method": None,
            "last_status": "authenticating",
        }
    if event.kind is AccessEventKind.AUTHENTICATION_SUCCEEDED and event.authentication:
        mechanism = event.authentication.selected_mechanism
        return {
            **common,
            "tcp_status": TargetStatus.PORT_OPEN.value,
            "smb_status": None,
            "authentication_status": TargetStatus.AUTHENTICATED.value,
            "authentication_method": mechanism.value if mechanism else None,
            "last_status": TargetStatus.AUTHENTICATED.value,
        }
    return None


def _access_result_payload(
    event: AccessPipelineEvent[TargetAccessResult],
    result: TargetAccessResult,
    *,
    generation: int,
) -> dict[str, object]:
    outcome = result.outcome
    negotiation = result.negotiation
    authentication = result.authentication
    network_status = (
        outcome.status
        if outcome is not None and outcome.stage is TargetStage.NETWORK
        else TargetStatus.PORT_OPEN
        if negotiation is not None
        else None
    )
    authentication_status = (
        TargetStatus.AUTHENTICATED.value
        if result.authenticated
        else TargetStatus.AUTH_FAILED.value
        if authentication is not None
        else None
    )
    selected = authentication.selected_mechanism if authentication is not None else None
    return {
        "generation": generation,
        "address": str(event.address),
        "source": event.source,
        "source_kind": event.source_kind.value,
        "tcp_status": network_status.value if network_status is not None else None,
        "smb_status": negotiation.dialect.value if negotiation is not None else None,
        "authentication_status": authentication_status,
        "authentication_method": selected.value if selected is not None else None,
        "last_status": (
            outcome.status.value if outcome is not None else result.status.value
        ),
        "port": 445,
        "raw_error_code": (
            outcome.error.raw_code
            if outcome is not None and outcome.error is not None
            else None
        ),
        "error_name": (
            outcome.error.symbolic_name
            if outcome is not None and outcome.error is not None
            else None
        ),
    }


def _pipeline_counter(event: AccessPipelineEvent[object]) -> str:
    if event.kind is PipelineEventKind.DNS_RESOLUTION_FAILED:
        return event.error_code or "dns_resolution_failed"
    if event.kind is PipelineEventKind.CANCELLED:
        return TargetStatus.CANCELLED.value
    if event.kind is PipelineEventKind.INSPECTION_FAILED:
        return event.error_code or "inspector_error"
    return "inspection_completed"


def _result_counter(result: TargetAccessResult) -> str:
    if result.outcome is not None:
        return result.outcome.status.value
    return result.status.value


def _is_confirmed_access_result(result: TargetAccessResult) -> bool:
    if result.negotiation is not None:
        return True
    outcome = result.outcome
    return bool(
        outcome is not None
        and (
            outcome.stage is not TargetStage.NETWORK
            or outcome.status is TargetStatus.CONNECTION_REFUSED
        )
    )


def _credential_from_body(value: object) -> Credential:
    if not isinstance(value, Mapping):
        raise CredentialValidationError("Kimlik bilgisi alanları eksik.")
    try:
        kind = CredentialKind(value.get("kind"))
        auth_mode = AuthMode(value.get("auth_mode"))
    except (TypeError, ValueError) as exc:
        raise CredentialValidationError(
            "Credential türü veya auth modu geçersiz."
        ) from exc

    username = value.get("username")
    domain = value.get("domain")
    if not isinstance(username, str):
        raise CredentialValidationError("Kullanıcı adı metin olmalı.")
    if domain is not None and not isinstance(domain, str):
        raise CredentialValidationError("Domain metin olmalı.")

    if kind is CredentialKind.PASSWORD:
        password = value.get("password")
        if not isinstance(password, str) or value.get("nt_hash") is not None:
            raise CredentialValidationError("Parola credential alanları geçersiz.")
        return Credential.from_password(
            username=username,
            password=password,
            domain=domain,
            auth_mode=auth_mode,
        )
    if kind is CredentialKind.NT_HASH:
        nt_hash = value.get("nt_hash")
        if not isinstance(nt_hash, str) or value.get("password") is not None:
            raise CredentialValidationError("NT hash credential alanları geçersiz.")
        return Credential.from_nt_hash(
            username=username,
            nt_hash=nt_hash,
            domain=domain,
            auth_mode=auth_mode,
        )
    raise CredentialValidationError(
        "CCache yükleme akışı henüz bu formda kullanılamıyor."
    )


def _result_page_payload(request: Request, *, findings: bool) -> dict[str, object]:
    runtime = _runtime(request)
    token = runtime.sessions.snapshot.token
    if token is None:
        return {"items": [], "page": 1, "page_size": 100, "total_items": 0}
    page = _positive_query_integer(request, "page", default=1)
    page_size = _positive_query_integer(request, "page_size", default=100)
    try:
        result_page = (
            runtime.sessions.findings_page(token, page=page, page_size=page_size)
            if findings
            else runtime.sessions.inventory_page(token, page=page, page_size=page_size)
        )
    except ValueError as exc:
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST) from exc
    return {
        "items": list(result_page.items),
        "page": result_page.page,
        "page_size": result_page.page_size,
        "total_items": result_page.total_items,
        "total_pages": result_page.total_pages,
    }


def _positive_query_integer(request: Request, name: str, *, default: int) -> int:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST) from exc
    if value < 1:
        raise SafeHttpError(HttpErrorCode.BAD_REQUEST)
    return value


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
