"""Thread-safe, framework-neutral live scan progress state."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock, RLock, local
from types import MappingProxyType


class ScanPhase(StrEnum):
    PREPARING_TARGETS = "preparing_targets"
    CONNECTIVITY = "connectivity"
    INSPECTION = "inspection"
    AUTHENTICATION = "authentication"
    SHARE_DISCOVERY = "share_discovery"
    FILE_INVENTORY = "file_inventory"
    CONTENT_SCAN = "content_scan"
    IDENTITY_ACCESS = "identity_access"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ActiveWork:
    worker_id: str
    action: str
    target: str | None = None
    share: str | None = None
    path: str | None = None


@dataclass(frozen=True, slots=True)
class ProgressSnapshot:
    sequence: int
    phase: ScanPhase
    phase_completed: int = 0
    phase_total: int | None = None
    overall_percent: float | None = None
    overall_is_estimate: bool = True
    counters: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    active_work: tuple[ActiveWork, ...] = ()
    message: str | None = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def phase_percent(self) -> float | None:
        if self.phase_total is None:
            return None
        if self.phase_total == 0:
            return 100.0
        return min(100.0, self.phase_completed * 100.0 / self.phase_total)


ProgressListener = Callable[[ProgressSnapshot], None]
ProgressChangeBuilder = Callable[[ProgressSnapshot], dict[str, object]]


class StaleProgressUpdate(RuntimeError):
    """Raised when work from an earlier phase tries to update a later phase."""


class ProgressTracker:
    """Publishes immutable snapshots without depending on a web framework."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._dispatch_lock = Lock()
        self._dispatch_state = local()
        self._listeners: dict[int, ProgressListener] = {}
        self._next_listener_id = 1
        self._pending_notifications: deque[
            tuple[ProgressSnapshot, tuple[ProgressListener, ...]]
        ] = deque()
        self._snapshot = ProgressSnapshot(sequence=0, phase=ScanPhase.PREPARING_TARGETS)

    @property
    def snapshot(self) -> ProgressSnapshot:
        with self._lock:
            return self._snapshot

    def subscribe(self, listener: ProgressListener) -> Callable[[], None]:
        """Register a listener and return an idempotent unsubscribe function."""

        with self._lock:
            listener_id = self._next_listener_id
            self._next_listener_id += 1
            self._listeners[listener_id] = listener

        def unsubscribe() -> None:
            with self._lock:
                self._listeners.pop(listener_id, None)

        return unsubscribe

    def set_phase(
        self,
        phase: ScanPhase,
        *,
        total: int | None = None,
        message: str | None = None,
        overall_percent: float | None = None,
        overall_is_estimate: bool = True,
    ) -> ProgressSnapshot:
        _validate_progress(0, total, overall_percent)
        return self._publish(
            phase=phase,
            phase_completed=0,
            phase_total=total,
            message=message,
            overall_percent=overall_percent,
            overall_is_estimate=overall_is_estimate,
            active_work=(),
        )

    def update_progress(
        self,
        completed: int,
        *,
        expected_phase: ScanPhase,
        total: int | None = None,
        overall_percent: float | None = None,
        overall_is_estimate: bool | None = None,
        message: str | None = None,
    ) -> ProgressSnapshot:
        def build_changes(current: ProgressSnapshot) -> dict[str, object]:
            if current.phase is not expected_phase:
                raise StaleProgressUpdate(
                    f"Expected phase {expected_phase.value!r}, found {current.phase.value!r}."
                )
            effective_total = current.phase_total if total is None else total
            _validate_progress(completed, effective_total, overall_percent)
            changes: dict[str, object] = {
                "phase_completed": completed,
                "phase_total": effective_total,
            }
            if overall_percent is not None:
                changes["overall_percent"] = overall_percent
            if overall_is_estimate is not None:
                changes["overall_is_estimate"] = overall_is_estimate
            if message is not None:
                changes["message"] = message
            return changes

        return self._commit(build_changes)

    def increment(self, counter: str, amount: int = 1) -> ProgressSnapshot:
        if not counter or not counter.strip():
            raise ValueError("Counter name is required.")
        if amount < 0:
            raise ValueError("Counter increment cannot be negative.")
        def build_changes(current: ProgressSnapshot) -> dict[str, object]:
            counters = dict(current.counters)
            counters[counter] = counters.get(counter, 0) + amount
            return {"counters": MappingProxyType(counters)}

        return self._commit(build_changes)

    def set_active_work(self, work: Sequence[ActiveWork]) -> ProgressSnapshot:
        immutable_work = tuple(work)
        worker_ids = [item.worker_id for item in immutable_work]
        if len(worker_ids) != len(set(worker_ids)):
            raise ValueError("Active worker IDs must be unique.")
        return self._publish(active_work=immutable_work)

    def _publish(self, **changes: object) -> ProgressSnapshot:
        return self._commit(lambda _current: changes)

    def _commit(self, build_changes: ProgressChangeBuilder) -> ProgressSnapshot:
        """Mutate state atomically, then deliver snapshots in sequence order."""

        with self._lock:
            changes = build_changes(self._snapshot)
            snapshot = replace(
                self._snapshot,
                **changes,
                sequence=self._snapshot.sequence + 1,
                updated_at=datetime.now(UTC),
            )
            self._snapshot = snapshot
            self._pending_notifications.append((snapshot, tuple(self._listeners.values())))
        self._drain_notifications()
        return snapshot

    def _drain_notifications(self) -> None:
        # A listener may publish another update. Queue that nested event and let
        # the outer dispatch loop deliver it after the current snapshot.
        if getattr(self._dispatch_state, "active", False):
            return
        with self._dispatch_lock:
            self._dispatch_state.active = True
            try:
                while True:
                    with self._lock:
                        if not self._pending_notifications:
                            break
                        snapshot, listeners = self._pending_notifications.popleft()
                    for listener in listeners:
                        try:
                            listener(snapshot)
                        except Exception:
                            # UI/event adapters are isolation boundaries. A
                            # disconnected consumer must not stop scan workers.
                            continue
            finally:
                self._dispatch_state.active = False


def _validate_progress(
    completed: int,
    total: int | None,
    overall_percent: float | None,
) -> None:
    if completed < 0:
        raise ValueError("Completed work cannot be negative.")
    if total is not None:
        if total < 0:
            raise ValueError("Total work cannot be negative.")
        if completed > total:
            raise ValueError("Completed work cannot exceed total work.")
    if overall_percent is not None and not 0.0 <= overall_percent <= 100.0:
        raise ValueError("Overall percent must be between 0 and 100.")
