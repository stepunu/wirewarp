"""Verifies that `handle_command_result` only mutates a CommandLog when the
authenticated agent owns it. Without this binding a compromised or
spoofed agent JWT could ack — and inject output into — another agent's
pending command (notably `wg_attach`, which writes the public-key from
the output to TunnelClientAttachment.wg_public_key).
"""
from __future__ import annotations

import uuid

import pytest

from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.websocket.handlers import handle_command_result


def _make_agent(agent_type: str = "server") -> Agent:
    return Agent(
        id=uuid.uuid4(),
        name=f"{agent_type}-test",
        agent_type=agent_type,
        token_hash="x",
    )


@pytest.mark.asyncio
async def test_command_result_owner_can_ack(db) -> None:
    owner = _make_agent()
    db.add(owner)
    await db.commit()

    log = CommandLog(
        id=uuid.uuid4(),
        agent_id=owner.id,
        command_type="wg_init",
        params={},
    )
    db.add(log)
    await db.commit()

    await handle_command_result(
        str(owner.id),
        {"command_id": str(log.id), "success": True, "output": "ok"},
        db,
    )
    await db.refresh(log)
    assert log.success is True
    assert log.output == "ok"


@pytest.mark.asyncio
async def test_command_result_non_owner_is_rejected(db) -> None:
    owner = _make_agent()
    attacker = _make_agent(agent_type="client")
    db.add_all([owner, attacker])
    await db.commit()

    log = CommandLog(
        id=uuid.uuid4(),
        agent_id=owner.id,
        command_type="wg_attach",
        params={"attachment_id": str(uuid.uuid4())},
    )
    db.add(log)
    await db.commit()

    await handle_command_result(
        str(attacker.id),
        {
            "command_id": str(log.id),
            "success": True,
            "output": "public key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        },
        db,
    )
    await db.refresh(log)
    # The CommandLog row must be untouched: still pending, no output.
    assert log.success is None
    assert log.output is None
