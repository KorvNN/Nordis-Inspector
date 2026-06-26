"""Starlette adapter for the local, memory-only inspection panel."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import AsyncIterator, Callable, Mapping
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
from nordis_smb_inspector.core.credential_audit import classify_audit_material
from nordis_smb_inspector.core.credentials import (
    AuthMode,
    Credential,
    CredentialKind,
    CredentialValidationError,
)
from nordis_smb_inspector.core.detection import (
    DetectionRulePack,
    detection_rules_for_packs,
)
from nordis_smb_inspector.core.kerberos import resolve_kerberos_hostname
from nordis_smb_inspector.core.progress import ScanPhase
from nordis_smb_inspector.core.scan_config import (
    ScanConfigError,
    ScanOptions,
    parse_scan_options,
)
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
from nordis_smb_inspector.smb.impacket_discovery import ImpacketShareDiscoverer
from nordis_smb_inspector.smb.inspection import (
    ContentFinding,
    InspectionEventKind,
    InspectionResult,
    InspectionTargetEvent,
    inspect_target,
)
from nordis_smb_inspector.smb.models import (
    InventoryEntry,
    TargetStage,
    TargetStatus,
)
from nordis_smb_inspector.smb.smbprotocol_adapter import SmbProtocolConnector
from nordis_smb_inspector.smb.smbprotocol_auth_adapter import SmbProtocolAuthenticator
from nordis_smb_inspector.smb.smbprotocol_files import SmbProtocolFileAdapter
from nordis_smb_inspector.web.audit import (
    MAX_WORDLIST_UPLOAD_BYTES,
    AuditAlreadyRunning,
    AuditInvalidTransition,
    AuditRequestError,
    AuditToolUnavailable,
    CredentialAuditManager,
    WordlistUploadValidator,
    create_private_upload_file,
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

_MAX_CCACHE_BYTES = 1024 * 1024
_MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
_MAX_TARGET_WORKERS = 32
_DEFAULT_MAX_DEPTH = 32
_STATIC_ASSETS: dict[str, str] = {
    "app.css": "text/css; charset=utf-8",
    "app-hash-tools.js": "text/javascript; charset=utf-8",
    "app-history.js": "text/javascript; charset=utf-8",
    "app-i18n.js": "text/javascript; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "nordis-icon.svg": "image/svg+xml",
}
_STATIC_ASSET_ALIASES = {"favicon.svg": "nordis-icon.svg"}

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
    file_adapter: Any = field(repr=False)
    share_discoverer: Any = field(repr=False)
    access_inspector: Any = field(repr=False)
    hash_tools: CredentialAuditManager = field(repr=False)
    kerberos_hostname_resolver: Callable[[ExpandedTarget], str | None] = field(
        repr=False
    )
    _target_lock: RLock = field(default_factory=RLock, repr=False)
    _target_generation: int = field(default=0, repr=False)
    _targets: dict[str, dict[str, object]] = field(default_factory=dict, repr=False)
    _terminal_error: dict[str, str] | None = field(default=None, repr=False)
    worker: Thread | None = field(default=None, repr=False)

    def reset_targets(self, generation: int) -> None:
        with self._target_lock:
            self._target_generation = generation
            self._targets.clear()
            self._terminal_error = None

    def update_target(self, generation: int, payload: dict[str, object]) -> bool:
        key = str(payload["address"])
        with self._target_lock:
            if generation != self._target_generation:
                return False
            current = self._targets.get(key)
            if current is None:
                current = dict(payload)
            else:
                current.update(
                    (name, value)
                    for name, value in payload.items()
                    if value is not None
                )
            self._targets[key] = current
            return True

    def target_snapshot(self, generation: int) -> list[dict[str, object]]:
        with self._target_lock:
            if generation != self._target_generation:
                return []
            return [dict(item) for item in self._targets.values()]

    def set_terminal_error(
        self,
        generation: int,
        *,
        phase: ScanPhase,
        code: str,
        message: str,
    ) -> bool:
        """Retain one pre-normalized failure outcome for the current scan."""

        with self._target_lock:
            if generation != self._target_generation:
                return False
            self._terminal_error = {
                "phase": phase.value,
                "code": code,
                "message": message,
            }
            return True

    def terminal_error_snapshot(self, generation: int) -> dict[str, str] | None:
        with self._target_lock:
            if generation != self._target_generation or self._terminal_error is None:
                return None
            return dict(self._terminal_error)


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
    def __call__(self, **kwargs: object) -> InspectionResult: ...


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
    file_adapter: Any | None = None,
    share_discoverer: Any | None = None,
    hash_tool_manager: CredentialAuditManager | None = None,
    kerberos_hostname_resolver: Callable[
        [ExpandedTarget], str | None
    ] = resolve_kerberos_hostname,
    access_inspector: AccessInspector = inspect_target,
) -> Starlette:
    runtime = WebRuntime(
        port=port,
        csrf=CsrfNonce(),
        sessions=ScanSessionManager(),
        events=SseEventBroker(capacity=2048),
        connector=connector or SmbProtocolConnector(),
        authenticator=authenticator or SmbProtocolAuthenticator(),
        file_adapter=file_adapter or SmbProtocolFileAdapter(),
        share_discoverer=share_discoverer or ImpacketShareDiscoverer(),
        access_inspector=access_inspector,
        hash_tools=hash_tool_manager or CredentialAuditManager(),
        kerberos_hostname_resolver=kerberos_hostname_resolver,
    )
    routes = [
        Route("/", homepage, methods=["GET"]),
        Route("/scan", scan_start, methods=["POST"]),
        Route("/scan/cancel", scan_cancel, methods=["POST"]),
        Route("/scan/snapshot", scan_snapshot, methods=["GET"]),
        Route("/scan/events", scan_events, methods=["GET"]),
        Route("/inventory", inventory_results, methods=["GET"]),
        Route("/findings", finding_results, methods=["GET"]),
        Route("/hash-tools", hash_tools_snapshot, methods=["GET"]),
        Route("/hash-tools/wordlist", hash_wordlist_upload, methods=["PUT"]),
        Route("/hash-tools/jobs", hash_tools_start, methods=["POST"]),
        Route("/hash-tools/jobs/cancel", hash_tools_cancel, methods=["POST"]),
        Route("/favicon.ico", favicon, methods=["GET"]),
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


async def hash_tools_snapshot(request: Request) -> JSONResponse:
    return JSONResponse(_hash_tools_payload(_runtime(request)))


async def hash_wordlist_upload(request: Request) -> JSONResponse:
    runtime = _runtime(request)
    _protect_post(request, runtime)
    if runtime.sessions.snapshot.active:
        return _hash_tools_error("SCAN_IN_PROGRESS", status_code=409)
    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type.casefold() not in {"application/octet-stream", "text/plain"}:
        return _hash_tools_error("INVALID_WORDLIST")
    raw_length = request.headers.get("content-length")
    if raw_length is not None:
        try:
            content_length = int(raw_length)
        except ValueError:
            return _hash_tools_error("INVALID_WORDLIST")
        if content_length > MAX_WORDLIST_UPLOAD_BYTES:
            return _hash_tools_error("WORDLIST_TOO_LARGE", status_code=413)

    try:
        handle = runtime.hash_tools.begin_wordlist_upload()
    except AuditAlreadyRunning:
        return _hash_tools_error("HASH_TOOL_IN_PROGRESS", status_code=409)
    validator = WordlistUploadValidator()
    try:
        create_private_upload_file(handle.path)
        with handle.path.open("wb") as target:
            async for chunk in request.stream():
                validator.consume(chunk)
                target.write(chunk)
        size_bytes, entry_count = validator.finish()
        runtime.hash_tools.complete_wordlist_upload(
            handle,
            size_bytes=size_bytes,
            entry_count=entry_count,
        )
    except AuditRequestError as exc:
        runtime.hash_tools.abort_wordlist_upload(handle)
        code = _safe_hash_tool_error(exc)
        return _hash_tools_error(
            code,
            status_code=413 if code == "WORDLIST_TOO_LARGE" else 422,
        )
    except Exception:
        runtime.hash_tools.abort_wordlist_upload(handle)
        return _hash_tools_error("WORDLIST_UPLOAD_FAILED", status_code=500)
    return JSONResponse(_hash_tools_payload(runtime), status_code=201)


async def hash_tools_start(request: Request) -> JSONResponse:
    runtime = _runtime(request)
    _protect_post(request, runtime)
    body = await _read_json(request)
    if runtime.sessions.snapshot.active:
        return _hash_tools_error("SCAN_IN_PROGRESS", status_code=409)
    materials = classify_audit_material(body.get("rule_id"), body.get("full_line"))
    variant = body.get("variant")
    if not isinstance(variant, str):
        return _hash_tools_error("INVALID_CANDIDATE")
    material = next(
        (candidate for candidate in materials if candidate.variant == variant),
        None,
    )
    if material is None:
        return _hash_tools_error("UNSUPPORTED_CANDIDATE")
    try:
        runtime.hash_tools.start(
            material=material,
            tool_id=body.get("tool_id"),
            wordlist_upload_id=body.get("wordlist_upload_id"),
            runtime_seconds=body.get("runtime_seconds"),
        )
    except AuditAlreadyRunning:
        return _hash_tools_error("HASH_TOOL_IN_PROGRESS", status_code=409)
    except AuditToolUnavailable:
        return _hash_tools_error("TOOL_UNAVAILABLE", status_code=409)
    except AuditRequestError as exc:
        return _hash_tools_error(_safe_hash_tool_error(exc))
    return JSONResponse(_hash_tools_payload(runtime), status_code=202)


async def hash_tools_cancel(request: Request) -> JSONResponse:
    runtime = _runtime(request)
    _protect_post(request, runtime)
    try:
        runtime.hash_tools.cancel()
    except AuditInvalidTransition:
        return _hash_tools_error("HASH_TOOL_NOT_RUNNING", status_code=409)
    return JSONResponse(_hash_tools_payload(runtime), status_code=202)


async def scan_start(request: Request) -> JSONResponse:
    runtime = _runtime(request)
    _protect_post(request, runtime)
    body = await _read_json(request)
    if runtime.hash_tools.active:
        return JSONResponse(
            {
                "ok": False,
                "errors": [
                    {"value": "Hash tools", "reason": "HASH_TOOL_IN_PROGRESS"}
                ],
            },
            status_code=409,
        )
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
        options = parse_scan_options(body.get("search"), _DEFAULT_MAX_DEPTH)
    except ScanConfigError as exc:
        return JSONResponse(
            {
                "ok": False,
                "errors": [{"value": "Tarama ayarları", "reason": str(exc)}],
            },
            status_code=422,
        )
    test_write_access = body.get("test_write_access", False)
    if not isinstance(test_write_access, bool):
        return JSONResponse(
            {
                "ok": False,
                "errors": [
                    {
                        "value": "Yazma erişimi",
                        "reason": "Write-access selection must be a boolean.",
                    }
                ],
            },
            status_code=422,
        )

    try:
        handle = runtime.sessions.begin_scan()
    except ScanAlreadyRunning as exc:
        raise SafeHttpError(HttpErrorCode.CONFLICT) from exc

    runtime.hash_tools.clear()

    runtime.reset_targets(handle.token.generation)
    phase_total = (
        plan.known_address_count
        if plan.hostname_count == 0
        else None
    )
    handle.progress.set_phase(
        ScanPhase.INSPECTION,
        total=phase_total,
        message="SMB hedefleri inceleniyor.",
        overall_percent=0,
        overall_is_estimate=phase_total is None,
    )
    runtime.events.publish("snapshot", _snapshot_payload(runtime))
    worker = Thread(
        target=_run_access_scan,
        args=(
            runtime,
            handle,
            plan,
            credential,
            options,
            test_write_access,
            phase_total,
        ),
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
        "terminal_error": runtime.terminal_error_snapshot(state.generation),
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


_HASH_TOOL_ERROR_CODES = frozenset(
    {
        "INVALID_TOOL",
        "INVALID_RUNTIME",
        "INVALID_WORDLIST",
        "WORDLIST_SIZE_INVALID",
        "WORDLIST_ENTRY_COUNT_INVALID",
        "WORDLIST_LINE_TOO_LONG",
        "WORDLIST_TOO_LARGE",
        "WORDLIST_NOT_FOUND",
        "WORDLIST_UPLOAD_IN_PROGRESS",
        "INCOMPATIBLE_TOOL",
    }
)


def _hash_tools_payload(runtime: WebRuntime) -> dict[str, object]:
    job = runtime.hash_tools.snapshot
    wordlist = runtime.hash_tools.wordlist
    return {
        "ok": True,
        "tools": [tool.public_payload() for tool in runtime.hash_tools.tools()],
        "job": job.public_payload() if job is not None else None,
        "wordlist": wordlist.public_payload() if wordlist is not None else None,
    }


def _hash_tools_error(code: str, *, status_code: int = 422) -> JSONResponse:
    return JSONResponse(
        {"ok": False, "error": code},
        status_code=status_code,
    )


def _safe_hash_tool_error(error: AuditRequestError) -> str:
    code = str(error)
    return code if code in _HASH_TOOL_ERROR_CODES else "INVALID_REQUEST"


def _run_access_scan(
    runtime: WebRuntime,
    handle: ScanHandle,
    plan: TargetPlan,
    credential: Credential,
    options: ScanOptions,
    test_write_access: bool,
    phase_total: int | None,
) -> None:
    completed = 0
    pipeline_failed = False
    cancellation = _CancellationBridge(handle.cancellation)
    executor = AccessPipelineExecutor(
        AccessPipelineSettings(max_concurrency=_MAX_TARGET_WORKERS)
    )

    def inspect_one(
        target: ExpandedTarget,
        target_cancellation: _CancellationBridge,
    ) -> InspectionResult:
        address = str(target.address)
        kerberos_hostname = (
            None
            if credential.auth_mode is AuthMode.NTLM_ONLY
            else runtime.kerberos_hostname_resolver(target)
        )

        def publish_target_event(event: InspectionTargetEvent) -> None:
            message = _inspection_progress_message(
                address,
                credential.domain,
                event,
            )
            if message is not None:
                current = handle.progress.snapshot.phase_completed
                handle.progress.update_progress(
                    current,
                    expected_phase=ScanPhase.INSPECTION,
                    total=phase_total,
                    overall_is_estimate=phase_total is None,
                    message=message,
                )
                runtime.events.publish("snapshot", _snapshot_payload(runtime))
            payload = _inspection_event_payload(
                target,
                event,
                generation=handle.token.generation,
            )
            if payload is not None and runtime.update_target(
                handle.token.generation,
                payload,
            ):
                runtime.events.publish("target.changed", payload)

        def publish_inventory(entry: InventoryEntry) -> None:
            payload = _inventory_payload(entry, generation=handle.token.generation)
            runtime.sessions.upsert_inventory(
                handle.token,
                (entry.target, entry.share_name, entry.relative_path, entry.kind.value),
                payload,
            )
            runtime.events.publish("inventory.added", payload)
            runtime.events.publish("snapshot", _snapshot_payload(runtime))

        def publish_finding(finding: ContentFinding) -> None:
            payload = _finding_payload(finding, generation=handle.token.generation)
            runtime.sessions.add_finding(handle.token, payload)
            runtime.events.publish("finding.added", payload)
            runtime.events.publish("snapshot", _snapshot_payload(runtime))

        return runtime.access_inspector(
            target=address,
            connect_request=ConnectRequest(target=address),
            credential=credential,
            kerberos_hostname=kerberos_hostname,
            search_terms=options.terms,
            max_depth=options.max_depth,
            connector=runtime.connector,
            authenticator=runtime.authenticator,
            file_adapter=runtime.file_adapter,
            share_discoverer=runtime.share_discoverer,
            cancellation=target_cancellation,
            detect_patterns=options.detect_patterns,
            pattern_rules=detection_rules_for_packs(options.rule_packs),
            detect_credential_artifacts=(
                DetectionRulePack.WINDOWS_AD in options.rule_packs
            ),
            test_write_access=test_write_access,
            on_target=publish_target_event,
            on_inventory=publish_inventory,
            on_finding=publish_finding,
        )

    try:
        for event in executor.iter_events(
            plan,
            inspect_one,
            cancellation=cancellation,
        ):
            counter = _pipeline_counter(event)
            if event.kind is PipelineEventKind.INSPECTION_FAILED:
                pipeline_failed = True
                runtime.set_terminal_error(
                    handle.token.generation,
                    phase=ScanPhase.INSPECTION,
                    code=event.error_code or "TARGET_INSPECTION_FAILED",
                    message=(
                        f"{event.address} hedefinin denetim iş akışı "
                        "beklenmeyen bir uygulama hatasıyla durdu."
                    ),
                )
            if event.kind is PipelineEventKind.INSPECTION_COMPLETED:
                result = event.result
                if isinstance(result, InspectionResult):
                    counter = result.status.value
                    payload = _inspection_result_payload(
                        event,
                        result,
                        generation=handle.token.generation,
                    )
                    if _is_confirmed_inspection_result(result) and runtime.update_target(
                        handle.token.generation,
                        payload,
                    ):
                        runtime.events.publish("target.changed", payload)
            completed += 1
            handle.progress.increment(counter)
            handle.progress.update_progress(
                completed,
                expected_phase=ScanPhase.INSPECTION,
                total=phase_total,
                overall_percent=(
                    completed * 100 / phase_total if phase_total is not None else None
                ),
                overall_is_estimate=phase_total is None,
                message=f"{completed} hedefte SMB erişimi kontrol edildi.",
            )
            runtime.events.publish("snapshot", _snapshot_payload(runtime))

        state = runtime.sessions.snapshot
        if state.active:
            if pipeline_failed:
                runtime.sessions.fail(handle.token)
            else:
                runtime.sessions.complete(handle.token)
    except Exception:
        runtime.set_terminal_error(
            handle.token.generation,
            phase=ScanPhase.INSPECTION,
            code="SCAN_WORKER_FAILED",
            message="Tarama iş akışı beklenmeyen bir uygulama hatasıyla durdu.",
        )
        state = runtime.sessions.snapshot
        if state.active:
            runtime.sessions.fail(handle.token)
    finally:
        _ensure_terminal_error(runtime, handle)
        runtime.events.publish("snapshot", _snapshot_payload(runtime))


def _ensure_terminal_error(runtime: WebRuntime, handle: ScanHandle) -> None:
    state = runtime.sessions.snapshot
    if state.token != handle.token or state.status.value != "failed":
        return
    if runtime.terminal_error_snapshot(handle.token.generation) is not None:
        return
    collection = state.capacity_collection.value if state.capacity_collection else None
    if collection == "inventory":
        code = "INVENTORY_CAPACITY_REACHED"
        message = "Envanter için ayrılan bellek kapasitesine ulaşıldı."
    elif collection == "findings":
        code = "FINDINGS_CAPACITY_REACHED"
        message = "Bulgular için ayrılan bellek kapasitesine ulaşıldı."
    else:
        code = "SCAN_WORKER_FAILED"
        message = "Tarama iş akışı beklenmeyen bir uygulama hatasıyla durdu."
    runtime.set_terminal_error(
        handle.token.generation,
        phase=ScanPhase.INSPECTION,
        code=code,
        message=message,
    )


def _inspection_event_payload(
    target: ExpandedTarget,
    event: InspectionTargetEvent,
    *,
    generation: int,
) -> dict[str, object] | None:
    status = event.status
    negotiation = event.negotiation
    visible_without_negotiation = (
        status is TargetStatus.CONNECTION_REFUSED
        or (
            event.stage is TargetStage.NEGOTIATION
            and status is TargetStatus.NEGOTIATION_FAILED
        )
    )
    if negotiation is None and not visible_without_negotiation:
        return None
    authentication = event.authentication
    selected = authentication.selected_mechanism if authentication is not None else None
    if authentication is not None and authentication.authenticated:
        authentication_status: str | None = TargetStatus.AUTHENTICATED.value
    elif event.stage is TargetStage.AUTHENTICATION and status is TargetStatus.AUTH_FAILED:
        authentication_status = TargetStatus.AUTH_FAILED.value
    else:
        authentication_status = None
    tcp_status = (
        TargetStatus.CONNECTION_REFUSED.value
        if status is TargetStatus.CONNECTION_REFUSED
        else TargetStatus.PORT_OPEN.value
        if negotiation is not None or event.stage is TargetStage.NEGOTIATION
        else None
    )
    signing = negotiation.security.signing if negotiation is not None else None
    encryption = negotiation.security.encryption if negotiation is not None else None
    error = event.error
    return {
        "generation": generation,
        "address": str(target.address),
        "source": target.source,
        "source_kind": target.source_kind.value,
        "tcp_status": tcp_status,
        "smb_status": negotiation.dialect.value if negotiation is not None else None,
        "signing_supported": signing.supported if signing is not None else None,
        "signing_required": signing.required if signing is not None else None,
        "signing_active": signing.active if signing is not None else None,
        "encryption_supported": encryption.supported if encryption is not None else None,
        "encryption_required": encryption.required if encryption is not None else None,
        "encryption_active": encryption.active if encryption is not None else None,
        "authentication_status": authentication_status,
        "authentication_method": selected.value if selected is not None else None,
        "last_status": status.value if status is not None else event.stage.value,
        "raw_error_code": error.raw_code if error is not None else None,
        "error_name": error.symbolic_name if error is not None else None,
        "error_message": error.safe_message if error is not None else None,
        "port": 445,
    }


def _inspection_progress_message(
    address: str,
    domain: str | None,
    event: InspectionTargetEvent,
) -> str | None:
    context = f"{address} · {domain}" if domain else address
    label = {
        InspectionEventKind.NEGOTIATED: "SMB görüşmesi",
        InspectionEventKind.AUTHENTICATED: "Kimlik doğrulama",
        InspectionEventKind.DISCOVERING_SHARES: "Share listesi alınıyor",
        InspectionEventKind.PROBING_SHARES: "Share erişimi denetleniyor",
        InspectionEventKind.WALKING_SHARE: "Dosya envanteri",
        InspectionEventKind.SCANNING_FILE: "İçerik taraması",
        InspectionEventKind.STAGE_ERROR: "Erişim hatası",
    }.get(event.kind)
    if label is None:
        return None
    location = ""
    if event.share:
        location = f" · {event.share}"
    if event.path:
        location = f"{location}/{event.path}" if location else f" · {event.path}"
    return f"{context} · {label}{location}"


def _inspection_result_payload(
    event: AccessPipelineEvent[InspectionResult],
    result: InspectionResult,
    *,
    generation: int,
) -> dict[str, object]:
    outcome = result.outcome
    authentication = result.authentication
    selected = authentication.selected_mechanism if authentication is not None else None
    tcp_status = (
        outcome.status.value
        if outcome.stage is TargetStage.NETWORK
        else TargetStatus.PORT_OPEN.value
        if result.negotiation is not None or outcome.stage is TargetStage.NEGOTIATION
        else None
    )
    authentication_status = (
        TargetStatus.AUTHENTICATED.value
        if authentication is not None and authentication.authenticated
        else TargetStatus.AUTH_FAILED.value
        if outcome.stage is TargetStage.AUTHENTICATION
        else None
    )
    security = result.negotiation.security if result.negotiation is not None else None
    signing = security.signing if security is not None else None
    encryption = security.encryption if security is not None else None
    return {
        "generation": generation,
        "address": str(event.address),
        "source": event.source,
        "source_kind": event.source_kind.value,
        "tcp_status": tcp_status,
        "smb_status": (
            result.negotiation.dialect.value if result.negotiation is not None else None
        ),
        "signing_supported": signing.supported if signing is not None else None,
        "signing_required": signing.required if signing is not None else None,
        "signing_active": signing.active if signing is not None else None,
        "encryption_supported": encryption.supported if encryption is not None else None,
        "encryption_required": encryption.required if encryption is not None else None,
        "encryption_active": encryption.active if encryption is not None else None,
        "authentication_status": authentication_status,
        "authentication_method": selected.value if selected is not None else None,
        "last_status": result.status.value,
        "port": 445,
        "shares_probed": result.shares_probed,
        "shares_accessible": result.shares_accessible,
        "files_seen": result.files_seen,
        "files_scanned": result.files_scanned,
        "unreadable_files": result.unreadable_files,
        "raw_error_code": outcome.error.raw_code if outcome.error is not None else None,
        "error_name": outcome.error.symbolic_name if outcome.error is not None else None,
        "error_message": outcome.error.safe_message if outcome.error is not None else None,
    }


def _is_confirmed_inspection_result(result: InspectionResult) -> bool:
    if result.negotiation is not None:
        return True
    if result.stage is TargetStage.NETWORK:
        return result.status is TargetStatus.CONNECTION_REFUSED
    return (
        result.stage is TargetStage.NEGOTIATION
        and result.status is TargetStatus.NEGOTIATION_FAILED
    )


def _inventory_payload(
    entry: InventoryEntry,
    *,
    generation: int,
) -> dict[str, object]:
    read_access = (
        "allowed"
        if entry.status.value in {
            "share_connected",
            "directory_listable",
            "file_readable",
            "depth_limit_reached",
        }
        else "denied"
        if entry.status.value in {
            "share_access_denied",
            "directory_list_denied",
            "file_read_denied",
        }
        else "error"
    )
    return {
        "generation": generation,
        "target": entry.target,
        "share": entry.share_name,
        "path": entry.relative_path,
        "type": entry.kind.value,
        "status": entry.status.value,
        "read_access": read_access,
        "write_access": entry.write_access.value,
        "size": entry.size,
        "modified_at": entry.modified_at.isoformat() if entry.modified_at else None,
        "raw_error_code": entry.error.raw_code if entry.error is not None else None,
        "error_name": entry.error.symbolic_name if entry.error is not None else None,
        "error_message": entry.error.safe_message if entry.error is not None else None,
    }


def _finding_payload(
    finding: ContentFinding,
    *,
    generation: int,
) -> dict[str, object]:
    audit_candidates = tuple(
        material.public_metadata()
        for material in classify_audit_material(finding.rule_id, finding.full_line)
    )
    return {
        "generation": generation,
        "target": finding.target,
        "share": finding.share,
        "path": finding.path,
        "file": f"\\\\{finding.target}\\{finding.share}\\{finding.path}",
        "line_number": finding.line_number,
        "term": finding.term,
        "full_line": finding.full_line,
        "method": finding.method.value,
        "rule_id": finding.rule_id,
        "category": finding.category,
        "confidence": (
            finding.confidence.value if finding.confidence is not None else None
        ),
        "audit_candidates": audit_candidates,
    }


def _pipeline_counter(event: AccessPipelineEvent[object]) -> str:
    if event.kind is PipelineEventKind.DNS_RESOLUTION_FAILED:
        return event.error_code or "dns_resolution_failed"
    if event.kind is PipelineEventKind.CANCELLED:
        return TargetStatus.CANCELLED.value
    if event.kind is PipelineEventKind.INSPECTION_FAILED:
        return event.error_code or "inspector_error"
    return "inspection_completed"


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
    if kind is not CredentialKind.CCACHE and not isinstance(username, str):
        raise CredentialValidationError("Kullanıcı adı metin olmalı.")
    if kind is CredentialKind.CCACHE and username is not None and not isinstance(
        username, str
    ):
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
    if kind is CredentialKind.CCACHE:
        if auth_mode is not AuthMode.KERBEROS_ONLY:
            raise CredentialValidationError("CCache yalnız Kerberos modunu kullanabilir.")
        filename = value.get("ccache_name")
        encoded = value.get("ccache_base64")
        if not isinstance(filename, str) or not isinstance(encoded, str):
            raise CredentialValidationError("CCache dosyası eksik.")
        if value.get("password") is not None or value.get("nt_hash") is not None:
            raise CredentialValidationError("CCache credential alanları geçersiz.")
        if len(encoded) > ((_MAX_CCACHE_BYTES + 2) // 3) * 4:
            raise CredentialValidationError("CCache dosyası 1 MiB sınırını aşıyor.")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise CredentialValidationError("CCache verisi geçersiz.") from exc
        if len(data) > _MAX_CCACHE_BYTES:
            raise CredentialValidationError("CCache dosyası 1 MiB sınırını aşıyor.")
        return Credential.from_ccache(
            filename=filename,
            data=data,
            username=username,
            domain=domain,
        )
    raise CredentialValidationError("Credential türü desteklenmiyor.")


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


def _static_asset_response(asset_name: str) -> Response:
    asset_name = _STATIC_ASSET_ALIASES.get(asset_name, asset_name)
    media_type = _STATIC_ASSETS.get(asset_name)
    if media_type is None:
        raise SafeHttpError(HttpErrorCode.NOT_FOUND)
    data = files("nordis_smb_inspector.web").joinpath("static", asset_name).read_bytes()
    return Response(data, media_type=media_type)


async def favicon(_request: Request) -> Response:
    return _static_asset_response("favicon.svg")


async def static_asset(request: Request) -> Response:
    return _static_asset_response(request.path_params["asset_name"])


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
