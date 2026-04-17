"""Cooperative cancellation primitives shared by SMB adapter operations."""

from __future__ import annotations

from threading import Event
from typing import Protocol, runtime_checkable


class ScanCancelled(RuntimeError):
    """Raised at a cooperative cancellation boundary."""

    def __init__(self) -> None:
        super().__init__("SMB operation cancelled.")


@runtime_checkable
class CancellationToken(Protocol):
    """Minimal hook accepted by every potentially blocking adapter operation."""

    @property
    def cancelled(self) -> bool: ...

    def raise_if_cancelled(self) -> None: ...


class CancellationFlag:
    """Thread-safe token/controller used by the scan orchestrator."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise ScanCancelled()


class NeverCancelled:
    """Stateless token for callers that intentionally have no controller."""

    __slots__ = ()

    @property
    def cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None


NEVER_CANCELLED = NeverCancelled()

