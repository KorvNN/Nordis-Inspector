"""In-memory lifecycle and result storage for one local scan at a time.

The session manager deliberately has no serialization, logging, or filesystem
hooks.  Web and worker adapters receive immutable snapshots and must present
them directly from process memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from threading import Event, RLock
from uuid import UUID, uuid4

from nordis_smb_inspector.core.progress import ProgressSnapshot, ProgressTracker, ScanPhase


class ScanStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


class TerminalReason(StrEnum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    WORKER_FAILED = "worker_failed"
    CAPACITY_REACHED = "capacity_reached"


class ResultCollection(StrEnum):
    INVENTORY = "inventory"
    FINDINGS = "findings"


_ACTIVE_STATUSES = frozenset({ScanStatus.RUNNING, ScanStatus.CANCELLING})
_TERMINAL_STATUSES = frozenset(
    {ScanStatus.CANCELLED, ScanStatus.COMPLETED, ScanStatus.FAILED}
)


class ScanSessionError(RuntimeError):
    """Base class for scan-session lifecycle errors."""


class ScanAlreadyRunning(ScanSessionError):
    """Raised when a second scan is requested while one is active."""


class StaleScanUpdate(ScanSessionError):
    """Raised when a worker refers to a scan that is no longer current."""


class InvalidScanTransition(ScanSessionError):
    """Raised when a lifecycle operation is invalid for the current status."""


class CapacityReached(ScanSessionError):
    """Raised instead of silently discarding an inventory item or finding."""

    def __init__(self, collection: ResultCollection, limit: int) -> None:
        self.collection = collection
        self.limit = limit
        super().__init__(f"{collection.value} capacity reached ({limit} items)")


@dataclass(frozen=True, slots=True)
class SessionLimits:
    """Explicit process-memory and UI page bounds.

    The storage bounds are intentionally mandatory and finite.  Deployments
    can raise them, but reaching one is a visible terminal partial result rather
    than an implicit eviction policy.
    """

    max_inventory_items: int = 250_000
    max_findings: int = 100_000
    default_page_size: int = 100
    max_page_size: int = 1_000

    def __post_init__(self) -> None:
        for name in ("max_inventory_items", "max_findings", "default_page_size"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be greater than zero.")
        if self.max_page_size <= 0:
            raise ValueError("max_page_size must be greater than zero.")
        if self.default_page_size > self.max_page_size:
            raise ValueError("default_page_size cannot exceed max_page_size.")


@dataclass(frozen=True, slots=True)
class ScanToken:
    """Unambiguous capability passed from the orchestrator to scan workers."""

    scan_id: str
    generation: int

    def __post_init__(self) -> None:
        try:
            parsed = UUID(self.scan_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("scan_id must be a UUID string.") from exc
        if parsed.version != 4:
            raise ValueError("scan_id must be a random UUID4 value.")
        if self.generation <= 0:
            raise ValueError("generation must be greater than zero.")


@dataclass(frozen=True, slots=True, repr=False)
class CancellationSignal:
    """Read-only cooperative cancellation view for worker code."""

    _event: Event = field(repr=False, compare=False)

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def raise_if_requested(self) -> None:
        if self.requested:
            raise ScanCancelled("Scan cancellation was requested.")

    def __repr__(self) -> str:
        return f"CancellationSignal(requested={self.requested!r})"


class ScanCancelled(ScanSessionError):
    """Cooperative worker exception raised by ``raise_if_requested``."""


@dataclass(frozen=True, slots=True, repr=False)
class ScanHandle:
    """Worker-facing references for exactly one scan generation."""

    token: ScanToken
    progress: ProgressTracker = field(repr=False, compare=False)
    cancellation: CancellationSignal = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return f"ScanHandle(token={self.token!r}, cancellation={self.cancellation!r})"


@dataclass(frozen=True, slots=True, repr=False)
class ScanState:
    """Immutable, safe-to-share summary of the current in-memory session."""

    status: ScanStatus
    generation: int
    scan_id: str | None = None
    progress: ProgressSnapshot | None = field(default=None, repr=False)
    inventory_count: int = 0
    finding_count: int = 0
    terminal_reason: TerminalReason | None = None
    capacity_collection: ResultCollection | None = None
    partial: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def active(self) -> bool:
        return self.status in _ACTIVE_STATUSES

    @property
    def terminal(self) -> bool:
        return self.status in _TERMINAL_STATUSES

    @property
    def token(self) -> ScanToken | None:
        if self.scan_id is None:
            return None
        return ScanToken(self.scan_id, self.generation)

    def __repr__(self) -> str:
        return (
            "ScanState("
            f"status={self.status.value!r}, generation={self.generation!r}, "
            f"scan_id={self.scan_id!r}, inventory_count={self.inventory_count!r}, "
            f"finding_count={self.finding_count!r}, partial={self.partial!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ResultPage[ItemT]:
    """A stable page copy whose representation never prints result contents."""

    page: int
    page_size: int
    total_items: int
    items: tuple[ItemT, ...] = field(repr=False)

    @property
    def total_pages(self) -> int:
        if self.total_items == 0:
            return 0
        return (self.total_items + self.page_size - 1) // self.page_size

    @property
    def has_previous(self) -> bool:
        return self.page > 1 and self.total_items > 0

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    def __repr__(self) -> str:
        return (
            "ResultPage("
            f"page={self.page!r}, page_size={self.page_size!r}, "
            f"total_items={self.total_items!r}, returned_items={len(self.items)!r})"
        )


class ScanSessionManager:
    """Own the one active scan and its bounded, RAM-only result collections."""

    def __init__(self, limits: SessionLimits | None = None) -> None:
        self._limits = limits or SessionLimits()
        self._lock = RLock()
        self._generation = 0
        self._state = ScanState(status=ScanStatus.IDLE, generation=0)
        self._inventory: list[object] = []
        self._findings: list[object] = []
        self._progress: ProgressTracker | None = None
        self._cancel_event: Event | None = None
        self._unsubscribe_progress = None

    @property
    def limits(self) -> SessionLimits:
        return self._limits

    @property
    def snapshot(self) -> ScanState:
        """Return the current immutable state under the session lock."""

        with self._lock:
            return self._state

    def begin_scan(self) -> ScanHandle:
        """Explicitly begin a scan and clear the preceding terminal results."""

        with self._lock:
            if self._state.active:
                raise ScanAlreadyRunning(
                    f"Scan {self._state.scan_id} is already {self._state.status.value}."
                )

            if self._unsubscribe_progress is not None:
                self._unsubscribe_progress()
                self._unsubscribe_progress = None

            self._generation += 1
            token = ScanToken(str(uuid4()), self._generation)
            progress = ProgressTracker()
            cancel_event = Event()
            now = datetime.now(UTC)

            # This is the only operation that discards a preceding scan's
            # results. Merely completing, failing, or cancelling retains them.
            self._inventory.clear()
            self._findings.clear()
            self._progress = progress
            self._cancel_event = cancel_event
            self._state = ScanState(
                status=ScanStatus.RUNNING,
                generation=token.generation,
                scan_id=token.scan_id,
                progress=progress.snapshot,
                started_at=now,
                updated_at=now,
            )
            self._unsubscribe_progress = progress.subscribe(
                lambda snapshot: self._accept_progress(token, snapshot)
            )

            return ScanHandle(
                token=token,
                progress=progress,
                cancellation=CancellationSignal(cancel_event),
            )

    def add_inventory(self, token: ScanToken, item: object) -> int:
        """Append one inventory record and return the new count."""

        return self._append_result(token, ResultCollection.INVENTORY, item)

    def add_finding(self, token: ScanToken, item: object) -> int:
        """Append one finding and return the new count."""

        return self._append_result(token, ResultCollection.FINDINGS, item)

    def inventory_page(
        self,
        token: ScanToken,
        *,
        page: int = 1,
        page_size: int | None = None,
    ) -> ResultPage[object]:
        return self._result_page(token, ResultCollection.INVENTORY, page, page_size)

    def findings_page(
        self,
        token: ScanToken,
        *,
        page: int = 1,
        page_size: int | None = None,
    ) -> ResultPage[object]:
        return self._result_page(token, ResultCollection.FINDINGS, page, page_size)

    def request_cancel(self, token: ScanToken) -> ScanState:
        """Request cooperative cancellation; repeated requests are idempotent."""

        with self._lock:
            self._require_current_locked(token)
            if self._state.status is ScanStatus.CANCELLING:
                return self._state
            if self._state.status is not ScanStatus.RUNNING:
                raise InvalidScanTransition(
                    f"Cannot cancel a scan in {self._state.status.value} state."
                )
            assert self._cancel_event is not None
            self._cancel_event.set()
            self._state = self._replace_state_locked(status=ScanStatus.CANCELLING)
            progress = self._progress

        assert progress is not None
        progress.set_phase(ScanPhase.CANCELLING, message="Cancellation requested.")
        return self._state_for_token_or(token, self._state)

    def mark_cancelled(self, token: ScanToken) -> ScanState:
        with self._lock:
            self._require_current_locked(token)
            if self._state.status is not ScanStatus.CANCELLING:
                raise InvalidScanTransition(
                    f"Cannot mark {self._state.status.value} scan as cancelled."
                )
            state, progress = self._finish_locked(
                ScanStatus.CANCELLED,
                TerminalReason.CANCELLED,
                partial=bool(self._inventory or self._findings),
            )

        progress.set_phase(ScanPhase.CANCELLED, message="Scan cancelled.")
        return self._state_for_token_or(token, state)

    def complete(self, token: ScanToken) -> ScanState:
        """Complete a running scan, or acknowledge an already requested cancel."""

        with self._lock:
            self._require_current_locked(token)
            if self._state.status is ScanStatus.CANCELLING:
                status = ScanStatus.CANCELLED
                reason = TerminalReason.CANCELLED
                phase = ScanPhase.CANCELLED
                partial = bool(self._inventory or self._findings)
            elif self._state.status is ScanStatus.RUNNING:
                status = ScanStatus.COMPLETED
                reason = TerminalReason.COMPLETED
                phase = ScanPhase.COMPLETED
                partial = False
            else:
                raise InvalidScanTransition(
                    f"Cannot complete a scan in {self._state.status.value} state."
                )
            state, progress = self._finish_locked(status, reason, partial=partial)

        progress.set_phase(phase)
        return self._state_for_token_or(token, state)

    def fail(self, token: ScanToken) -> ScanState:
        """Mark an active scan failed without retaining arbitrary exception text."""

        with self._lock:
            self._require_current_locked(token)
            if self._state.status not in _ACTIVE_STATUSES:
                raise InvalidScanTransition(
                    f"Cannot fail a scan in {self._state.status.value} state."
                )
            state, progress = self._finish_locked(
                ScanStatus.FAILED,
                TerminalReason.WORKER_FAILED,
                partial=bool(self._inventory or self._findings),
            )

        progress.set_phase(ScanPhase.FAILED, message="Scan worker failed.")
        return self._state_for_token_or(token, state)

    def _append_result(
        self,
        token: ScanToken,
        collection: ResultCollection,
        item: object,
    ) -> int:
        capacity: tuple[ProgressTracker, int] | None = None
        with self._lock:
            self._require_running_locked(token)
            if collection is ResultCollection.INVENTORY:
                values = self._inventory
                limit = self._limits.max_inventory_items
            else:
                values = self._findings
                limit = self._limits.max_findings

            if len(values) >= limit:
                assert self._cancel_event is not None
                self._cancel_event.set()
                _, progress = self._finish_locked(
                    ScanStatus.FAILED,
                    TerminalReason.CAPACITY_REACHED,
                    partial=True,
                    capacity_collection=collection,
                )
                capacity = (progress, limit)
            else:
                values.append(item)
                if collection is ResultCollection.INVENTORY:
                    self._state = self._replace_state_locked(inventory_count=len(values))
                else:
                    self._state = self._replace_state_locked(finding_count=len(values))
                return len(values)

        assert capacity is not None
        progress, limit = capacity
        progress.set_phase(
            ScanPhase.FAILED,
            message=f"{collection.value} in-memory capacity reached.",
        )
        raise CapacityReached(collection, limit)

    def _result_page(
        self,
        token: ScanToken,
        collection: ResultCollection,
        page: int,
        page_size: int | None,
    ) -> ResultPage[object]:
        effective_size = self._limits.default_page_size if page_size is None else page_size
        if page <= 0:
            raise ValueError("page must be greater than zero.")
        if effective_size <= 0:
            raise ValueError("page_size must be greater than zero.")
        if effective_size > self._limits.max_page_size:
            raise ValueError(
                f"page_size cannot exceed configured maximum {self._limits.max_page_size}."
            )

        with self._lock:
            self._require_current_locked(token)
            values = (
                self._inventory
                if collection is ResultCollection.INVENTORY
                else self._findings
            )
            total = len(values)
            start = (page - 1) * effective_size
            items = tuple(values[start : start + effective_size])

        return ResultPage(
            page=page,
            page_size=effective_size,
            total_items=total,
            items=items,
        )

    def _accept_progress(self, token: ScanToken, snapshot: ProgressSnapshot) -> None:
        """Mirror only progress that agrees with the guarded session lifecycle."""

        with self._lock:
            if not self._is_current_locked(token):
                return
            allowed_phase = {
                ScanStatus.CANCELLING: ScanPhase.CANCELLING,
                ScanStatus.CANCELLED: ScanPhase.CANCELLED,
                ScanStatus.COMPLETED: ScanPhase.COMPLETED,
                ScanStatus.FAILED: ScanPhase.FAILED,
            }.get(self._state.status)
            if allowed_phase is not None and snapshot.phase is not allowed_phase:
                return
            if self._state.status is ScanStatus.RUNNING and snapshot.phase in {
                ScanPhase.CANCELLING,
                ScanPhase.CANCELLED,
                ScanPhase.COMPLETED,
                ScanPhase.FAILED,
            }:
                return
            self._state = self._replace_state_locked(progress=snapshot)

    def _finish_locked(
        self,
        status: ScanStatus,
        reason: TerminalReason,
        *,
        partial: bool,
        capacity_collection: ResultCollection | None = None,
    ) -> tuple[ScanState, ProgressTracker]:
        now = datetime.now(UTC)
        self._state = replace(
            self._state,
            status=status,
            terminal_reason=reason,
            capacity_collection=capacity_collection,
            partial=partial,
            finished_at=now,
            updated_at=now,
        )
        assert self._progress is not None
        return self._state, self._progress

    def _replace_state_locked(self, **changes: object) -> ScanState:
        self._state = replace(self._state, **changes, updated_at=datetime.now(UTC))
        return self._state

    def _require_running_locked(self, token: ScanToken) -> None:
        self._require_current_locked(token)
        if self._state.status is not ScanStatus.RUNNING:
            raise InvalidScanTransition(
                f"Results cannot be added in {self._state.status.value} state."
            )

    def _require_current_locked(self, token: ScanToken) -> None:
        if not self._is_current_locked(token):
            raise StaleScanUpdate("Worker update belongs to a stale scan generation.")

    def _is_current_locked(self, token: ScanToken) -> bool:
        return (
            self._state.scan_id == token.scan_id
            and self._state.generation == token.generation
        )

    def _state_for_token_or(self, token: ScanToken, fallback: ScanState) -> ScanState:
        with self._lock:
            return self._state if self._is_current_locked(token) else fallback

    def __repr__(self) -> str:
        state = self.snapshot
        return (
            "ScanSessionManager("
            f"status={state.status.value!r}, generation={state.generation!r}, "
            f"inventory_count={state.inventory_count!r}, "
            f"finding_count={state.finding_count!r})"
        )
