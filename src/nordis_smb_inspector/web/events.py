"""Bounded in-memory Server-Sent Events primitives.

Publishing never waits for a consumer. Once the fixed-capacity replay window is
full, the oldest event is discarded. A reconnecting client that missed an event
receives an explicit ``resync.required`` control frame and must fetch the RAM
snapshot before resuming the live stream.
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from threading import Condition
from time import monotonic

_EVENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_MAX_CURSOR = (1 << 63) - 1


class InvalidSseField(ValueError):
    """Raised without reflecting an untrusted header or event name."""

    __slots__ = ("field",)

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"Invalid SSE {field}.")

    def __repr__(self) -> str:
        return f"InvalidSseField(field={self.field!r}, value=<redacted>)"


class InvalidEventCursor(ValueError):
    """A safe error for an invalid Last-Event-ID value."""

    def __init__(self) -> None:
        super().__init__("Invalid SSE event cursor.")


class InvalidEventPayload(ValueError):
    """A safe error for a value that cannot be serialized as strict JSON."""

    def __init__(self) -> None:
        super().__init__("Event payload must be valid JSON data.")


class EventBrokerClosed(RuntimeError):
    def __init__(self) -> None:
        super().__init__("The event broker is closed.")


@dataclass(frozen=True, slots=True, repr=False)
class SseEvent:
    """A published event whose payload stays out of debug representations."""

    event_id: int
    event: str
    data: str

    def __post_init__(self) -> None:
        if isinstance(self.event_id, bool) or not isinstance(self.event_id, int):
            raise InvalidSseField("id")
        if self.event_id <= 0:
            raise InvalidSseField("id")
        _validate_event_name(self.event)
        if not isinstance(self.data, str):
            raise TypeError("SSE event data must be a string")

    def to_sse(self) -> bytes:
        return format_sse(event=self.event, data=self.data, event_id=self.event_id)

    def __repr__(self) -> str:
        return (
            f"SseEvent(event_id={self.event_id}, event={self.event!r}, "
            "data=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EventReplay:
    """An immutable replay decision for a new or reconnecting client."""

    events: tuple[SseEvent, ...]
    requested_after_id: int | None
    oldest_available_id: int | None
    latest_event_id: int
    resync_required: bool = False
    closed: bool = False

    def to_sse(self) -> tuple[bytes, ...]:
        if not self.resync_required:
            return tuple(event.to_sse() for event in self.events)

        payload = _serialize_payload(
            {
                "requested_after_id": self.requested_after_id,
                "oldest_available_id": self.oldest_available_id,
                "latest_event_id": self.latest_event_id,
            }
        )
        return (format_sse(event="resync.required", data=payload),)

    def __repr__(self) -> str:
        return (
            "EventReplay("
            f"event_count={len(self.events)}, "
            f"requested_after_id={self.requested_after_id}, "
            f"oldest_available_id={self.oldest_available_id}, "
            f"latest_event_id={self.latest_event_id}, "
            f"resync_required={self.resync_required}, closed={self.closed})"
        )


class SseEventBroker:
    """A thread-safe bounded replay buffer with non-blocking publication."""

    def __init__(self, capacity: int = 1024) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("capacity must be an integer")
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._events: deque[SseEvent] = deque(maxlen=capacity)
        self._condition = Condition()
        self._next_event_id = 1
        self._closed = False

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def latest_event_id(self) -> int:
        with self._condition:
            return self._next_event_id - 1

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    def __len__(self) -> int:
        with self._condition:
            return len(self._events)

    def __repr__(self) -> str:
        with self._condition:
            return (
                "SseEventBroker("
                f"capacity={self._capacity}, event_count={len(self._events)}, "
                f"latest_event_id={self._next_event_id - 1}, closed={self._closed})"
            )

    def publish(self, event: str, data: object) -> SseEvent:
        """Serialize and append one event without waiting for any consumer."""

        _validate_event_name(event)
        serialized = _serialize_payload(data)

        with self._condition:
            if self._closed:
                raise EventBrokerClosed
            event_id = self._next_event_id
            if event_id > _MAX_CURSOR:
                raise OverflowError("SSE event ID space is exhausted.")
            self._next_event_id += 1
            published = SseEvent(event_id=event_id, event=event, data=serialized)
            self._events.append(published)
            self._condition.notify_all()
            return published

    def replay_after(
        self,
        last_event_id: int | str | None,
        *,
        limit: int | None = None,
    ) -> EventReplay:
        """Return retained events after ``last_event_id`` or request a resync."""

        cursor = parse_last_event_id(last_event_id)
        normalized_limit = _validate_limit(limit)
        with self._condition:
            return self._replay_locked(cursor, normalized_limit)

    def wait_after(
        self,
        last_event_id: int | str | None,
        *,
        timeout: float | None = None,
        limit: int | None = None,
    ) -> EventReplay:
        """Wait on the consumer side until a replay decision is available.

        Scan workers never call this method. The condition wait releases the
        broker lock, so a publisher remains able to append and notify.
        """

        cursor = parse_last_event_id(last_event_id)
        normalized_limit = _validate_limit(limit)
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, int | float):
                raise TypeError("timeout must be a number or None")
            if timeout < 0:
                raise ValueError("timeout cannot be negative")

        deadline = None if timeout is None else monotonic() + timeout
        with self._condition:
            while True:
                replay = self._replay_locked(cursor, normalized_limit)
                if replay.events or replay.resync_required or replay.closed:
                    return replay
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    return replay
                self._condition.wait(remaining)

    def close(self) -> None:
        """Wake consumers during application shutdown; retained data stays in RAM."""

        with self._condition:
            if not self._closed:
                self._closed = True
                self._condition.notify_all()

    def _replay_locked(self, cursor: int | None, limit: int | None) -> EventReplay:
        latest = self._next_event_id - 1
        oldest = self._events[0].event_id if self._events else None

        resync_required = cursor is not None and (
            cursor > latest or (oldest is not None and cursor < oldest - 1)
        )

        if resync_required:
            selected: tuple[SseEvent, ...] = ()
        else:
            selected = tuple(
                event
                for event in self._events
                if cursor is None or event.event_id > cursor
            )
            if limit is not None:
                selected = selected[:limit]

        return EventReplay(
            events=selected,
            requested_after_id=cursor,
            oldest_available_id=oldest,
            latest_event_id=latest,
            resync_required=resync_required,
            closed=self._closed,
        )


def parse_last_event_id(value: int | str | None) -> int | None:
    """Parse an untrusted Last-Event-ID header without reflecting its value."""

    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise InvalidEventCursor from None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        if (
            not value.isascii()
            or not value.isdecimal()
            or len(value) > 19
            or "\r" in value
            or "\n" in value
            or "\0" in value
        ):
            raise InvalidEventCursor from None
        parsed = int(value)
    else:
        raise InvalidEventCursor from None

    if not 0 <= parsed <= _MAX_CURSOR:
        raise InvalidEventCursor from None
    return parsed


def format_sse(*, event: str, data: str, event_id: int | str | None = None) -> bytes:
    """Format a valid UTF-8 SSE frame while preventing field injection."""

    _validate_event_name(event)
    if not isinstance(data, str):
        raise TypeError("SSE data must be a string")

    lines: list[str] = []
    if event_id is not None:
        lines.append(f"id: {_validate_wire_id(event_id)}")
    lines.append(f"event: {event}")

    normalized_data = data.replace("\r\n", "\n").replace("\r", "\n")
    lines.extend(f"data: {line}" for line in normalized_data.split("\n"))
    return ("\n".join(lines) + "\n\n").encode()


def _serialize_payload(data: object) -> str:
    try:
        return json.dumps(
            data,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError):
        raise InvalidEventPayload from None


def _validate_event_name(value: object) -> str:
    if not isinstance(value, str) or _EVENT_NAME.fullmatch(value) is None:
        raise InvalidSseField("event")
    return value


def _validate_wire_id(value: int | str) -> str:
    if isinstance(value, bool):
        raise InvalidSseField("id")
    if isinstance(value, int):
        if value < 0:
            raise InvalidSseField("id")
        wire_value = str(value)
    elif isinstance(value, str):
        wire_value = value
    else:
        raise InvalidSseField("id")

    if (
        not wire_value
        or len(wire_value) > 128
        or "\r" in wire_value
        or "\n" in wire_value
        or "\0" in wire_value
    ):
        raise InvalidSseField("id")
    return wire_value


def _validate_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer or None")
    if limit <= 0:
        raise ValueError("limit must be positive")
    return limit
