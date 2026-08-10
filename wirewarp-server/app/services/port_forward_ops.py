"""Command dispatch helpers for raw port-forward runtime state."""

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.port_forward import PortForward
from app.models.tunnel_client_attachment import TunnelClientAttachment
from app.models.tunnel_server import TunnelServer
from app.services.agent_commands import (
    CommandResultState,
    send_command,
    wait_for_command_result,
)
from app.services.primary_ip import resolve_public_ip


logger = logging.getLogger(__name__)

RAW_FORWARD_REMOVE_TIMEOUT_SECONDS = 5.0
_raw_forward_mutation_lock = asyncio.Lock()
_POSTGRES_RAW_FORWARD_LOCK_KEY = 0x57575250


@dataclass(frozen=True)
class RawForwardRule:
    forward: PortForward
    public_ip: str


class RawForwardRemovalError(RuntimeError):
    def __init__(self, state: CommandResultState):
        super().__init__(state.value)
        self.state = state


@asynccontextmanager
async def serialize_server_runtime_mutation(
    server_id: uuid.UUID,
    db: AsyncSession,
):
    """Serialize endpoint and raw-forward mutations.

    Write volume is low, so one global lock avoids cross-server migration
    races and lock-set drift. PostgreSQL uses a session advisory lock because
    command-result logging commits while the runtime mutation is waiting.
    SQLite tests use the same process-local lock.
    """
    async with _raw_forward_mutation_lock:
        bind = db.bind
        if bind is None or bind.dialect.name != "postgresql":
            yield
            return
        async with AsyncSession(bind=bind, expire_on_commit=False) as lock_db:
            await lock_db.execute(
                text("SELECT pg_advisory_lock(:lock_key)"),
                {"lock_key": _POSTGRES_RAW_FORWARD_LOCK_KEY},
            )
            try:
                yield
            finally:
                await lock_db.execute(
                    text("SELECT pg_advisory_unlock(:lock_key)"),
                    {"lock_key": _POSTGRES_RAW_FORWARD_LOCK_KEY},
                )


@asynccontextmanager
async def serialize_server_runtime_mutations(
    server_ids: set[uuid.UUID],
    db: AsyncSession,
):
    """Serialize a mutation that can move rules between servers."""
    representative = min(server_ids, key=str) if server_ids else uuid.UUID(int=0)
    async with serialize_server_runtime_mutation(representative, db):
        yield


def snapshot_raw_forward(pf: PortForward) -> PortForward:
    """Copy all fields needed to address one exact runtime rule."""
    return PortForward(
        id=pf.id,
        attachment_id=pf.attachment_id,
        tunnel_server_ip_id=pf.tunnel_server_ip_id,
        protocol=pf.protocol,
        public_port=pf.public_port,
        public_port_end=pf.public_port_end,
        destination_ip=pf.destination_ip,
        destination_port=pf.destination_port,
        destination_port_end=pf.destination_port_end,
        service_kind=pf.service_kind,
        active=pf.active,
    )


async def _shared_forward_rule_survivor(
    removed_rule: RawForwardRule,
    server_id: uuid.UUID,
    excluded_ids: set[uuid.UUID],
    db: AsyncSession,
) -> RawForwardRule | None:
    """Find a retained DNAT whose shared FORWARD ACCEPT was just removed."""
    pf = removed_rule.forward
    query = (
        select(PortForward)
        .join(
            TunnelClientAttachment,
            PortForward.attachment_id == TunnelClientAttachment.id,
        )
        .where(
            TunnelClientAttachment.tunnel_server_id == server_id,
            PortForward.service_kind == "raw",
            PortForward.active.is_(True),
            PortForward.protocol == pf.protocol,
            PortForward.destination_ip == pf.destination_ip,
            PortForward.destination_port == pf.destination_port,
            PortForward.destination_port_end == pf.destination_port_end,
        )
    )
    if excluded_ids:
        query = query.where(PortForward.id.not_in(excluded_ids))
    survivor = await db.scalar(query.limit(1))
    if survivor is None:
        return None
    return RawForwardRule(
        snapshot_raw_forward(survivor),
        await resolve_public_ip(survivor, db),
    )


async def server_for_attachment(
    attachment_id: uuid.UUID, db: AsyncSession
) -> TunnelServer | None:
    server_id = await db.scalar(
        select(TunnelClientAttachment.tunnel_server_id).where(
            TunnelClientAttachment.id == attachment_id
        )
    )
    if server_id is None:
        return None
    return await db.scalar(select(TunnelServer).where(TunnelServer.id == server_id))


def build_raw_forward_params(pf: PortForward, public_ip: str) -> dict:
    params: dict = {
        "protocol": pf.protocol,
        "public_port": pf.public_port,
        "destination_ip": pf.destination_ip,
        "destination_port": pf.destination_port,
        "public_ip": public_ip,
    }
    if pf.public_port_end is not None:
        params["public_port_end"] = pf.public_port_end
    if pf.destination_port_end is not None:
        params["destination_port_end"] = pf.destination_port_end
    return params


async def dispatch_raw_forward(
    pf: PortForward,
    command_type: str,
    db: AsyncSession,
    *,
    public_ip_override: str | None = None,
) -> tuple[bool, str]:
    """Dispatch one exact raw forward add or removal command."""
    server = await server_for_attachment(pf.attachment_id, db)
    if server is None:
        return False, ""
    public_ip = (
        public_ip_override
        if public_ip_override is not None
        else await resolve_public_ip(pf, db)
    )
    sent, command_id = await send_command(
        agent_id=str(server.agent_id),
        command_type=command_type,
        params=build_raw_forward_params(pf, public_ip),
        db=db,
    )
    if not sent:
        port = (
            f"{pf.public_port}-{pf.public_port_end}"
            if pf.public_port_end
            else str(pf.public_port)
        )
        logger.warning(
            "Server agent %s not connected; %s was not delivered for port %s",
            server.agent_id,
            command_type,
            port,
        )
    return sent, command_id


async def restore_raw_forward_rules(
    rules: list[RawForwardRule],
    db: AsyncSession,
) -> None:
    """Best-effort restore exact rules removed before a failed DB change."""
    for rule in rules:
        try:
            await dispatch_raw_forward(
                rule.forward,
                "iptables_add_forward",
                db,
                public_ip_override=rule.public_ip,
            )
        except Exception:
            await db.rollback()
            logger.exception(
                "Could not restore old raw forward rule after aborted desired-state change"
            )


async def remove_raw_forward_rules_confirmed(
    rules: list[RawForwardRule],
    db: AsyncSession,
    *,
    timeout_seconds: float = RAW_FORWARD_REMOVE_TIMEOUT_SECONDS,
) -> list[RawForwardRule]:
    """Remove exact rules and require agent results before desired-state writes.

    Each command has its own timeout. If a later removal fails, all earlier
    confirmed removals are restored before the error is returned.
    """
    confirmed: list[RawForwardRule] = []
    excluded_ids = {
        rule.forward.id for rule in rules if rule.forward.id is not None
    }
    for rule in rules:
        server = await server_for_attachment(rule.forward.attachment_id, db)
        if server is None:
            await restore_raw_forward_rules(confirmed + [rule], db)
            raise RawForwardRemovalError(CommandResultState.MISSING)
        try:
            sent, command_id = await dispatch_raw_forward(
                rule.forward,
                "iptables_remove_forward",
                db,
                public_ip_override=rule.public_ip,
            )
        except Exception:
            await db.rollback()
            await restore_raw_forward_rules(confirmed + [rule], db)
            raise RawForwardRemovalError(CommandResultState.MISSING)
        if not sent:
            await restore_raw_forward_rules(confirmed + [rule], db)
            raise RawForwardRemovalError(CommandResultState.DISCONNECTED)
        result = await wait_for_command_result(
            command_id,
            str(server.agent_id),
            db,
            timeout_seconds=timeout_seconds,
        )
        if result is not CommandResultState.SUCCESS:
            await restore_raw_forward_rules(confirmed + [rule], db)
            raise RawForwardRemovalError(result)
        confirmed.append(rule)

        survivor = await _shared_forward_rule_survivor(
            rule,
            server.id,
            excluded_ids,
            db,
        )
        if survivor is not None:
            try:
                sent, command_id = await dispatch_raw_forward(
                    survivor.forward,
                    "iptables_add_forward",
                    db,
                    public_ip_override=survivor.public_ip,
                )
            except Exception:
                await db.rollback()
                await restore_raw_forward_rules(confirmed, db)
                raise RawForwardRemovalError(CommandResultState.MISSING)
            if not sent:
                await restore_raw_forward_rules(confirmed, db)
                raise RawForwardRemovalError(CommandResultState.DISCONNECTED)
            result = await wait_for_command_result(
                command_id,
                str(server.agent_id),
                db,
                timeout_seconds=timeout_seconds,
            )
            if result is not CommandResultState.SUCCESS:
                await restore_raw_forward_rules(confirmed, db)
                raise RawForwardRemovalError(result)
    return confirmed
