"""Shared fixtures for the wirewarp-server test suite.

We run against SQLite via aiosqlite so the suite works without a Postgres
sidecar. JSONB columns (used by command_log.params) get a compile hook that
renders them as plain JSON on SQLite — semantically equivalent for our
storage purposes. Most Postgres-specific migration features (gen_random_uuid,
older migration-only partial indexes, etc.) live in alembic, and tests skip
alembic in favour of `Base.metadata.create_all`.
"""
from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

# SQLite tests don't read .env or expect a real DB URL, but pydantic-settings
# would still try the default postgres URL on import. Pre-empt by setting an
# inert URL before any app module loads.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles


# Render JSONB as JSON on SQLite. See module docstring.
@compiles(JSONB, "sqlite")
def _jsonb_sqlite(type_, compiler, **kw):  # noqa: ANN001
    return "JSON"


from sqlalchemy import event  # noqa: E402
from sqlalchemy.dialects.postgresql import UUID as PgUUID  # noqa: E402


# Render the postgres dialect's UUID type as CHAR(32) on SQLite, since
# SQLite has no native UUID storage.
@compiles(PgUUID, "sqlite")
def _pguuid_sqlite(type_, compiler, **kw):  # noqa: ANN001
    return "CHAR(32)"


# The postgres UUID type's bind processor calls `.hex` on the input, which
# fails for string params (FastAPI path/query strings, command IDs sent
# from the WS handler). Wrap the processor on SQLite so string UUIDs are
# coerced to uuid.UUID first.
_orig_uuid_bind = PgUUID.bind_processor


def _coercing_bind_processor(self, dialect):  # noqa: ANN001
    proc = _orig_uuid_bind(self, dialect)
    if dialect.name != "sqlite":
        return proc

    def wrap(value):
        if isinstance(value, str):
            try:
                value = uuid.UUID(value)
            except (TypeError, ValueError):
                return None
        if proc is None:
            return value.hex if value is not None else None
        return proc(value)

    return wrap


PgUUID.bind_processor = _coercing_bind_processor


# The postgres UUID result_processor on as_uuid=True mode expects bytes-or-
# UUID from the driver. SQLite returns CHAR(32) strings, which we need to
# parse back into uuid.UUID for ORM consumers.
_orig_uuid_result = PgUUID.result_processor


def _coercing_result_processor(self, dialect, coltype):  # noqa: ANN001
    proc = _orig_uuid_result(self, dialect, coltype)
    if dialect.name != "sqlite":
        return proc

    def wrap(value):
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        if isinstance(value, (bytes, bytearray)):
            return uuid.UUID(bytes=bytes(value))
        try:
            return uuid.UUID(str(value))
        except (TypeError, ValueError):
            return None

    return wrap


PgUUID.result_processor = _coercing_result_processor


def _enable_sqlite_fks(dbapi_conn, _record):  # noqa: ANN001
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


from app import database as db_module  # noqa: E402  (after env vars + compiles hook)
from app.auth import get_current_user  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.agent import Agent  # noqa: E402
from app.models.tunnel_client import TunnelClient  # noqa: E402
from app.models.tunnel_client_attachment import TunnelClientAttachment  # noqa: E402
from app.models.tunnel_server import TunnelServer  # noqa: E402
from app.models.tunnel_server_ip import TunnelServerIP  # noqa: E402
from app.models.user import User  # noqa: E402
from app.websocket import hub as hub_module  # noqa: E402


@pytest_asyncio.fixture
async def engine(tmp_path_factory):
    """One on-disk SQLite engine per test (file scoped to tmp dir). Avoids
    aiosqlite's per-connection `:memory:` isolation, which would prevent
    the test session and the FastAPI app's session from seeing each other.
    """
    db_path = tmp_path_factory.mktemp("wirewarp-tests") / "test.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    e = create_async_engine(url, future=True)
    event.listen(e.sync_engine, "connect", _enable_sqlite_fks)
    async with e.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield e
    await e.dispose()


@pytest_asyncio.fixture
async def session_maker(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def db(session_maker) -> AsyncIterator[AsyncSession]:
    async with session_maker() as s:
        yield s


class FakeManager:
    """Stub for app.websocket.hub.manager. Tracks per-agent connectivity and
    captures every send_command payload for assertions.
    """

    def __init__(self) -> None:
        self.online: set[str] = set()
        self.sent: list[dict[str, Any]] = []

    def is_connected(self, agent_id: str) -> bool:
        return agent_id in self.online

    async def connect(self, agent_id: str, ws: Any) -> None:  # pragma: no cover
        self.online.add(agent_id)

    def disconnect(self, agent_id: str) -> None:  # pragma: no cover
        self.online.discard(agent_id)

    async def send(self, agent_id: str, message: dict[str, Any]) -> bool:
        self.sent.append({"agent_id": agent_id, "message": message})
        return agent_id in self.online


@pytest.fixture
def fake_manager(monkeypatch: pytest.MonkeyPatch) -> FakeManager:
    fm = FakeManager()
    monkeypatch.setattr(hub_module, "manager", fm)
    # The router modules import `manager` directly at import time; patch
    # those references too so connectivity checks see the fake.
    from app.routers import lan_clients, tunnel_client_attachments, tunnel_servers
    from app.services import agent_commands

    monkeypatch.setattr(tunnel_client_attachments, "manager", fm)
    monkeypatch.setattr(tunnel_servers, "manager", fm)
    monkeypatch.setattr(lan_clients, "manager", fm)
    monkeypatch.setattr(agent_commands, "manager", fm)
    return fm


def _make_stub_user(role: str = "admin", *, is_active: bool = True) -> User:
    return User(
        id=uuid.uuid4(),
        username=f"{role}-stub",
        email=f"{role}@stub.example",
        password_hash="x",
        role=role,
        is_active=is_active,
        auth_provider="local",
    )


async def _build_client(session_maker, role: str, *, is_active: bool = True) -> AsyncClient:
    async def override_get_db():
        async with session_maker() as s:
            yield s

    stub = _make_stub_user(role, is_active=is_active)

    async def override_get_user():
        return stub

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_user
    monkey_engine = db_module.engine
    db_module.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    transport = ASGITransport(app=app)
    ac = AsyncClient(transport=transport, base_url="http://test")
    ac._wirewarp_old_engine = monkey_engine  # type: ignore[attr-defined]
    return ac


async def _client_with_role(
    session_maker,
    role: str,
    *,
    is_active: bool = True,
) -> AsyncIterator[AsyncClient]:
    async def override_get_db():
        async with session_maker() as s:
            yield s

    stub = _make_stub_user(role, is_active=is_active)
    # Persist the stub so log_auth_event's actor_user_id FK is satisfied.
    async with session_maker() as s:
        s.add(stub)
        await s.commit()
        await s.refresh(stub)

    async def override_get_user():
        return stub

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_user
    monkey_engine = db_module.engine
    db_module.engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        old_sl = db_module.SessionLocal
        db_module.SessionLocal = session_maker
        try:
            ac._wirewarp_user = stub  # type: ignore[attr-defined]
            yield ac
        finally:
            db_module.SessionLocal = old_sl
            db_module.engine = monkey_engine
            app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def client(session_maker, fake_manager) -> AsyncIterator[AsyncClient]:
    """Admin-role FastAPI test client (default role for legacy tests)."""
    async for c in _client_with_role(session_maker, "admin"):
        yield c


@pytest_asyncio.fixture
async def operator_client(session_maker, fake_manager) -> AsyncIterator[AsyncClient]:
    async for c in _client_with_role(session_maker, "operator"):
        yield c


@pytest_asyncio.fixture
async def viewer_client(session_maker, fake_manager) -> AsyncIterator[AsyncClient]:
    async for c in _client_with_role(session_maker, "viewer"):
        yield c


# --- factories ---


async def make_agent(db: AsyncSession, *, type_: str, name: str = "test-agent", status: str = "connected") -> Agent:
    a = Agent(id=uuid.uuid4(), name=name, type=type_, status=status)
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


async def make_server(
    db: AsyncSession,
    *,
    agent: Agent | None = None,
    network: str = "10.21.0.0/24",
    primary_ip: str = "1.2.3.4",
    public_key: str = "SERVERPUBKEY",
    edge_mode: str = "tcp_udp_only",
    edge_state: str = "disabled",
    edge_install_phase: str = "disabled",
) -> TunnelServer:
    if agent is None:
        agent = await make_agent(db, type_="server", name=f"srv-{network}")
    s = TunnelServer(
        id=uuid.uuid4(),
        agent_id=agent.id,
        wg_port=51820,
        wg_interface="wg0",
        public_iface="eth0",
        wg_public_key=public_key,
        tunnel_network=network,
        edge_mode=edge_mode,
        edge_state=edge_state,
        edge_install_phase=edge_install_phase,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    db.add(
        TunnelServerIP(
            tunnel_server_id=s.id,
            address=primary_ip,
            label=None,
            is_primary=True,
        )
    )
    await db.commit()
    return s


async def make_client(
    db: AsyncSession,
    *,
    agent: Agent | None = None,
    is_gateway: bool = True,
    vm_network: str = "192.168.1.0/24",
    lan_ip: str = "192.168.1.110",
) -> TunnelClient:
    if agent is None:
        agent = await make_agent(db, type_="client")
    c = TunnelClient(
        id=uuid.uuid4(),
        agent_id=agent.id,
        vm_network=vm_network,
        lan_ip=lan_ip,
        is_gateway=is_gateway,
        status="connected",
    )
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c


async def make_attachment(
    db: AsyncSession,
    *,
    client: TunnelClient,
    server: TunnelServer,
    tunnel_ip: str = "10.21.0.10",
    wg_interface: str = "wg0",
    fwmark: int = 0x101,
    route_table_id: int = 100,
    public_key: str | None = "ATTACHPUBKEY",
) -> TunnelClientAttachment:
    a = TunnelClientAttachment(
        id=uuid.uuid4(),
        tunnel_client_id=client.id,
        tunnel_server_id=server.id,
        tunnel_ip=tunnel_ip,
        wg_interface=wg_interface,
        wg_public_key=public_key,
        fwmark=fwmark,
        route_table_id=route_table_id,
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


@pytest.fixture
def factories():
    """Bundle the factory helpers as a fixture so tests that don't need
    individual ones can grab the namespace.
    """
    return type(
        "Factories",
        (),
        {
            "make_agent": staticmethod(make_agent),
            "make_server": staticmethod(make_server),
            "make_client": staticmethod(make_client),
            "make_attachment": staticmethod(make_attachment),
        },
    )
