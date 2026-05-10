"""Event bus unit tests.

Covers fan-out, backpressure (drop oldest + desync), late-subscribe
isolation, and clean unsubscribe on consumer cancellation.
"""
import asyncio

import pytest

from app.realtime.bus import EventBus


pytestmark = pytest.mark.asyncio


async def _collect(bus: EventBus, n: int) -> list[dict]:
    """Subscribe and collect exactly n events, then break."""
    out: list[dict] = []
    async for event in bus.subscribe():
        out.append(event)
        if len(out) >= n:
            break
    return out


async def test_publish_fan_out_to_all_subscribers():
    bus = EventBus()

    sub_a = asyncio.create_task(_collect(bus, 2))
    sub_b = asyncio.create_task(_collect(bus, 2))
    # Yield once so the subscribers register before we publish.
    await asyncio.sleep(0)
    assert bus.subscriber_count == 2

    bus.publish_nowait("agent.changed")
    bus.publish_nowait("port_forward.changed")

    a, b = await asyncio.gather(sub_a, sub_b)
    assert a == [{"type": "agent.changed"}, {"type": "port_forward.changed"}]
    assert b == a


async def test_late_subscriber_does_not_see_past_events():
    bus = EventBus()

    bus.publish_nowait("agent.changed")  # nobody listening — discarded
    sub = asyncio.create_task(_collect(bus, 1))
    await asyncio.sleep(0)
    bus.publish_nowait("port_forward.changed")
    out = await sub
    assert out == [{"type": "port_forward.changed"}]


async def test_backpressure_drops_oldest_then_emits_desync():
    bus = EventBus(queue_size=2)

    received: list[dict] = []

    async def consumer():
        async for event in bus.subscribe():
            received.append(event)
            if len(received) >= 3:
                return

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0)

    # Saturate without yielding to the consumer in between.
    bus.publish_nowait("a.changed", n=1)
    bus.publish_nowait("b.changed", n=2)
    bus.publish_nowait("c.changed", n=3)

    await task

    # Expected: desync first (since at least one drop happened), then the
    # surviving events. The exact set depends on queue eviction order:
    # we drop the oldest queued event (a), so after the third publish the
    # queue holds [b, c]. The yield order is desync, b, c.
    assert received[0]["type"] == "desync"
    assert received[0]["dropped"] >= 1
    assert {received[1]["type"], received[2]["type"]} == {"b.changed", "c.changed"}


async def test_subscriber_cleanup_on_cancel():
    bus = EventBus()

    async def consumer():
        async for _event in bus.subscribe():
            return  # exit on first event

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0)
    assert bus.subscriber_count == 1
    bus.publish_nowait("agent.changed")
    await task
    # Unsubscribe runs in the generator's `finally` block.
    await asyncio.sleep(0)
    assert bus.subscriber_count == 0
