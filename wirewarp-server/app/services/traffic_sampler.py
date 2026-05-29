"""Background task: sample wg_peer_snapshots into wg_traffic_samples.

Runs every 60 s, copying current rx/tx counters from wg_peer_snapshots
into the append-only wg_traffic_samples table. Rows older than 30 days
are pruned at the same time so the table doesn't grow unbounded.

Never crashes the loop — all errors are caught, logged, and swallowed so
a transient DB error doesn't take down the lifespan task.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app.database import SessionLocal
from app.models.wg_peer_snapshot import WgPeerSnapshot
from app.models.wg_traffic_sample import WgTrafficSample

logger = logging.getLogger(__name__)

_INTERVAL_SECONDS = 60
_RETENTION_DAYS = 30


async def _sample_once() -> None:
    try:
        async with SessionLocal() as db:
            peers = (await db.execute(select(WgPeerSnapshot))).scalars().all()
            now = datetime.now(timezone.utc)
            for peer in peers:
                db.add(
                    WgTrafficSample(
                        agent_id=peer.agent_id,
                        interface=peer.interface,
                        public_key=peer.public_key,
                        rx_bytes=peer.rx_bytes,
                        tx_bytes=peer.tx_bytes,
                        sampled_at=now,
                    )
                )

            cutoff = now - timedelta(days=_RETENTION_DAYS)
            await db.execute(
                delete(WgTrafficSample).where(WgTrafficSample.sampled_at < cutoff)
            )
            await db.commit()
            logger.debug("Traffic sampler: sampled %d peer(s)", len(peers))
    except Exception:
        logger.exception("Traffic sampler error (will retry in %ds)", _INTERVAL_SECONDS)


async def run_traffic_sampler() -> None:
    """Main loop — runs for the lifetime of the FastAPI lifespan context."""
    logger.info("Traffic sampler started (interval=%ds, retention=%dd)",
                _INTERVAL_SECONDS, _RETENTION_DAYS)
    while True:
        await asyncio.sleep(_INTERVAL_SECONDS)
        await _sample_once()
