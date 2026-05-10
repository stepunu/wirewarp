"""In-process event bus driving the dashboard realtime channel.

Routers and WS handlers call `bus.publish(event_type, **payload)` after
committing a state change. Dashboard WebSocket sessions subscribe and
forward each event to the connected browser, which uses it as a hint to
invalidate the matching React Query keys (no payload duplication —
events are minimal).

A single in-process bus is enough today: the control server is a single
FastAPI process. If we ever scale horizontally, swap the in-memory
queues for Redis pub/sub or NATS — the publisher API stays the same.

## Backpressure

Each subscriber has its own bounded queue (DEFAULT_QUEUE_SIZE). If a
subscriber is too slow and the queue fills up, the bus drops the
oldest event and emits a `desync` event so the dashboard knows it
missed something — the frontend invalidates everything in response.
This keeps publishers fire-and-forget; they never block on a slow
consumer.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_QUEUE_SIZE = 256


class _Subscriber:
    """One dashboard session's event queue + drop tracking."""

    __slots__ = ("queue", "dropped")

    def __init__(self, maxsize: int):
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self.dropped: int = 0


class EventBus:
    """Fan-out async pub/sub. publish() is non-blocking; slow subscribers
    lose old events rather than holding up everyone else.
    """

    def __init__(self, queue_size: int = DEFAULT_QUEUE_SIZE):
        self._subscribers: set[_Subscriber] = set()
        self._queue_size = queue_size
        self._lock = asyncio.Lock()

    def publish_nowait(self, event_type: str, **payload: Any) -> None:
        """Synchronous publish — safe to call from sync code paths. Drops
        oldest event for any saturated subscriber.
        """
        event = {"type": event_type, **payload}
        for sub in list(self._subscribers):
            self._enqueue(sub, event)

    async def publish(self, event_type: str, **payload: Any) -> None:
        """Async-flavoured publish. Identical to publish_nowait — kept
        async so handlers can `await bus.publish(...)` without thinking
        about it. Internally it's still non-blocking.
        """
        self.publish_nowait(event_type, **payload)

    def _enqueue(self, sub: _Subscriber, event: dict[str, Any]) -> None:
        try:
            sub.queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        # Queue full: drop one old event to make room, increment counter.
        try:
            sub.queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        sub.dropped += 1
        try:
            sub.queue.put_nowait(event)
        except asyncio.QueueFull:
            # Highly unlikely after the drop; give up cleanly.
            return

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        """Async generator that yields events for one subscriber. Caller is
        expected to wrap in `async for ... in bus.subscribe()` and rely on
        `aclose()` (raised by the consumer's task cancellation) to clean up.
        """
        sub = _Subscriber(self._queue_size)
        async with self._lock:
            self._subscribers.add(sub)
        try:
            while True:
                event = await sub.queue.get()
                if sub.dropped:
                    # Emit a desync hint *before* this event so the consumer
                    # knows it missed N preceding events and should refetch.
                    dropped = sub.dropped
                    sub.dropped = 0
                    yield {"type": "desync", "dropped": dropped}
                yield event
        finally:
            async with self._lock:
                self._subscribers.discard(sub)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Global instance — imported by routers + dashboard WS.
bus = EventBus()
