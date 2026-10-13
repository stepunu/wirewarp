import uuid

import pytest

from app.models.agent import Agent
from app.models.command_log import CommandLog
from app.websocket import handlers


@pytest.mark.asyncio
@pytest.mark.parametrize("success", [True, False])
async def test_update_ack_follows_commit_and_replays(db, monkeypatch, success):
    owner = Agent(id=uuid.uuid4(), name="receipt-owner", type="server")
    log = CommandLog(id=uuid.uuid4(), agent_id=owner.id, command_type="agent_update", params={})
    db.add_all([owner, log])
    await db.commit()
    events = []
    commit = db.commit

    async def record_commit():
        await commit()
        events.append("committed")

    async def send(agent_id, message):
        assert events[-1] == "committed"
        assert log.success is success
        assert message == {"type": "command_result_ack", "agent_id": str(owner.id),
                           "command_id": str(log.id), "receipt_id": "a" * 32}
        events.append("ack")
        return False  # Lost ACK must leave the committed result available for replay.

    monkeypatch.setattr(db, "commit", record_commit)
    monkeypatch.setattr(handlers.manager, "send", send)
    msg = {"command_id": str(log.id), "success": success, "output": "installed proof", "receipt_id": "a" * 32}
    await handlers.handle_command_result(str(owner.id), msg, db)
    await handlers.handle_command_result(str(owner.id), msg, db)
    assert events.count("ack") == 2
    await db.refresh(log)
    assert log.success is success


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["foreign", "missing", "legacy", "other-command", "invalid-receipt"])
async def test_update_receipt_ack_is_exactly_bound(db, monkeypatch, case):
    owner = Agent(id=uuid.uuid4(), name="owner", type="server")
    other = Agent(id=uuid.uuid4(), name="other", type="client")
    log = CommandLog(id=uuid.uuid4(), agent_id=owner.id,
                     command_type="other" if case == "other-command" else "agent_update", params={})
    db.add_all([owner, other, log])
    await db.commit()

    async def send(*args):
        pytest.fail("unbound or legacy result received an update ACK")

    monkeypatch.setattr(handlers.manager, "send", send)
    msg = {"command_id": str(uuid.uuid4() if case == "missing" else log.id), "success": True,
           "output": "ok", "receipt_id": "a" * 32}
    if case == "legacy":
        msg.pop("receipt_id")
    if case == "invalid-receipt":
        msg["receipt_id"] = "not-a-receipt"
    await handlers.handle_command_result(str(other.id if case == "foreign" else owner.id), msg, db)
    await db.refresh(log)
    if case in {"foreign", "missing"}:
        assert log.success is None


@pytest.mark.asyncio
async def test_failed_commit_never_acknowledges_update(db, monkeypatch):
    owner = Agent(id=uuid.uuid4(), name="owner", type="server")
    log = CommandLog(id=uuid.uuid4(), agent_id=owner.id, command_type="agent_update", params={})
    db.add_all([owner, log])
    await db.commit()

    async def fail_commit():
        raise RuntimeError("database unavailable")

    async def send(*args):
        pytest.fail("failed commit was acknowledged")

    monkeypatch.setattr(db, "commit", fail_commit)
    monkeypatch.setattr(handlers.manager, "send", send)
    with pytest.raises(RuntimeError, match="database unavailable"):
        await handlers.handle_command_result(str(owner.id), {
            "command_id": str(log.id), "success": True, "output": "ok", "receipt_id": "a" * 32}, db)
