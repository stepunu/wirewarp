"""Stable VPN route envelopes and gateway permission delivery."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import uuid

import pytest
from sqlalchemy import select

from app.auth import get_current_user, hash_password
from app.main import app
from app.models.user import User
from app.models.vpn_endpoint import VpnEndpoint
from app.models.vpn_profile import VpnProfile


async def _vpn_user(db, username: str) -> User:
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password("passwordpassword"),
        role="viewer",
        is_active=True,
        auth_provider="local",
        vpn_enabled=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _endpoint(
    client,
    db,
    factories,
    *,
    remote_subnets: list[str] | None = None,
):
    gateway = await factories.make_client(db, is_gateway=True)
    response = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
            "remote_subnets": (
                ["192.168.1.0/24", "192.168.2.0/24"]
                if remote_subnets is None
                else remote_subnets
            ),
        },
    )
    assert response.status_code == 201, response.text
    return gateway, response.json()


def _allowed_ips(config_text: str) -> str:
    return next(
        line.removeprefix("AllowedIPs = ")
        for line in config_text.splitlines()
        if line.startswith("AllowedIPs = ")
    )


@pytest.mark.asyncio
async def test_split_profiles_share_endpoint_routes_not_permissions(client, db, factories):
    _, endpoint = await _endpoint(client, db, factories)
    alice = await _vpn_user(db, "alice-routes")
    bob = await _vpn_user(db, "bob-routes")

    for user, destination in [
        (alice, "192.168.1.10"),
        (bob, "192.168.2.20"),
    ]:
        response = await client.put(
            f"/api/vpn-endpoints/{endpoint['id']}/users/{user.id}/permissions",
            json={"permissions": [{"destination": destination, "protocol": "any"}]},
        )
        assert response.status_code == 200, response.text

    configs = []
    for user in [alice, bob]:
        response = await client.post(
            "/api/vpn-profiles",
            json={
                "user_id": str(user.id),
                "vpn_endpoint_id": endpoint["id"],
                "label": "phone",
                "tunnel_mode": "split",
            },
        )
        assert response.status_code == 201, response.text
        configs.append(response.json())

    expected = "10.21.0.0/24, 192.168.1.0/24, 192.168.2.0/24"
    assert [_allowed_ips(config["config_text"]) for config in configs] == [
        expected,
        expected,
    ]
    assert all(config["config_route_status"] == "current" for config in configs)


@pytest.mark.asyncio
async def test_route_revision_statuses_and_regeneration(client, db, factories):
    _, endpoint = await _endpoint(client, db, factories)
    user = await _vpn_user(db, "revision-user")

    split = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint["id"],
            "label": "split",
            "tunnel_mode": "split",
        },
    )
    full = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint["id"],
            "label": "full",
            "tunnel_mode": "full",
        },
    )
    assert split.status_code == full.status_code == 201
    assert split.json()["config_route_status"] == "current"
    assert full.json()["config_route_status"] == "not_applicable"

    response = await client.patch(
        f"/api/vpn-endpoints/{endpoint['id']}",
        json={"remote_subnets": [*endpoint["remote_subnets"], "172.16.0.0/16"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["route_revision"] == endpoint["route_revision"] + 1

    listed = await client.get(f"/api/vpn-profiles?endpoint_id={endpoint['id']}")
    by_label = {profile["label"]: profile for profile in listed.json()}
    assert by_label["split"]["config_route_status"] == "stale"
    assert by_label["full"]["config_route_status"] == "not_applicable"

    async def _as_user():
        return user

    app.dependency_overrides[get_current_user] = _as_user
    regenerated = await client.post(
        f"/api/vpn-profiles/me/{split.json()['id']}/regenerate"
    )
    assert regenerated.status_code == 200, regenerated.text
    assert regenerated.json()["config_route_status"] == "current"
    assert "172.16.0.0/16" in regenerated.json()["config_text"]

    profile = await db.get(VpnProfile, uuid.UUID(split.json()["id"]))
    profile.issued_route_revision = None
    await db.commit()
    listed = await client.get("/api/vpn-profiles/me")
    by_label = {item["label"]: item for item in listed.json()}
    assert by_label["split"]["config_route_status"] == "legacy"


@pytest.mark.asyncio
async def test_permission_change_keeps_route_revisions(client, db, factories):
    _, endpoint = await _endpoint(client, db, factories)
    user = await _vpn_user(db, "permission-revision")
    created = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint["id"],
            "label": "phone",
            "tunnel_mode": "split",
        },
    )
    assert created.status_code == 201, created.text

    response = await client.put(
        f"/api/vpn-endpoints/{endpoint['id']}/users/{user.id}/permissions",
        json={"permissions": [{"destination": "192.168.2.40", "protocol": "any"}]},
    )
    assert response.status_code == 200, response.text
    endpoint_row = await db.get(VpnEndpoint, uuid.UUID(endpoint["id"]))
    profile_row = await db.get(VpnProfile, uuid.UUID(created.json()["id"]))
    assert endpoint_row.route_revision == endpoint["route_revision"]
    assert profile_row.issued_route_revision == created.json()["issued_route_revision"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "routes",
    [
        ["0.0.0.0/0"],
        ["192.168.1.0/24", "192.168.1.0/24"],
        ["192.168.0.0/16", "192.168.1.0/24"],
        ["10.21.0.5"],
        ["not-a-network"],
    ],
)
async def test_invalid_remote_subnets_are_rejected(client, db, factories, routes):
    gateway = await factories.make_client(db, is_gateway=True)
    response = await client.post(
        "/api/vpn-endpoints",
        json={
            "tunnel_client_id": str(gateway.id),
            "public_endpoint": "vpn.example:51821",
            "remote_subnets": routes,
        },
    )
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_remote_subnet_hosts_are_canonical_and_route_only_update_is_local(
    client, db, factories, fake_manager
):
    _, endpoint = await _endpoint(
        client, db, factories, remote_subnets=["192.168.1.9"]
    )
    assert endpoint["remote_subnets"] == ["192.168.1.9/32"]
    sent_before = len(fake_manager.sent)
    response = await client.patch(
        f"/api/vpn-endpoints/{endpoint['id']}",
        json={"remote_subnets": ["192.168.1.0/24"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["route_revision"] == 2
    assert len(fake_manager.sent) == sent_before


@pytest.mark.asyncio
async def test_route_envelope_guards_permissions_and_removal(client, db, factories):
    _, endpoint = await _endpoint(client, db, factories)
    user = await _vpn_user(db, "route-guard")
    outside = await client.put(
        f"/api/vpn-endpoints/{endpoint['id']}/users/{user.id}/permissions",
        json={"permissions": [{"destination": "172.16.1.2", "protocol": "any"}]},
    )
    assert outside.status_code == 422

    saved = await client.put(
        f"/api/vpn-endpoints/{endpoint['id']}/users/{user.id}/permissions",
        json={"permissions": [{"destination": "192.168.2.12", "protocol": "any"}]},
    )
    assert saved.status_code == 200, saved.text
    removal = await client.patch(
        f"/api/vpn-endpoints/{endpoint['id']}",
        json={"remote_subnets": ["192.168.1.0/24"]},
    )
    assert removal.status_code == 409, removal.text


@pytest.mark.asyncio
async def test_split_requires_routes_and_tunnel_mode_patch_is_rejected(client, db, factories):
    _, endpoint = await _endpoint(client, db, factories, remote_subnets=[])
    user = await _vpn_user(db, "immutable-mode")
    split = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint["id"],
            "label": "split",
            "tunnel_mode": "split",
        },
    )
    assert split.status_code == 400

    full = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint["id"],
            "label": "full",
            "tunnel_mode": "full",
        },
    )
    assert full.status_code == 201, full.text
    patched = await client.patch(
        f"/api/vpn-profiles/{full.json()['id']}", json={"tunnel_mode": "split"}
    )
    assert patched.status_code == 422


@pytest.mark.asyncio
async def test_permission_delivery_reports_pending_and_dispatched(
    client, db, factories, fake_manager
):
    gateway, endpoint = await _endpoint(client, db, factories)
    user = await _vpn_user(db, "delivery-state")
    profile = await client.post(
        "/api/vpn-profiles",
        json={
            "user_id": str(user.id),
            "vpn_endpoint_id": endpoint["id"],
            "label": "phone",
            "tunnel_mode": "full",
        },
    )
    assert profile.status_code == 201, profile.text

    pending = await client.put(
        f"/api/vpn-endpoints/{endpoint['id']}/users/{user.id}/permissions",
        json={"permissions": [{"destination": "192.168.1.20", "protocol": "any"}]},
    )
    assert pending.status_code == 200, pending.text
    assert pending.json()["gateway_sync"] == "pending"
    assert len(pending.json()["command_ids"]) == 1

    fake_manager.online.add(str(gateway.agent_id))
    dispatched = await client.put(
        f"/api/vpn-endpoints/{endpoint['id']}/users/{user.id}/permissions",
        json={"permissions": [{"destination": "192.168.2.30", "protocol": "tcp"}]},
    )
    assert dispatched.status_code == 200, dispatched.text
    assert dispatched.json()["gateway_sync"] == "dispatched"
    message = fake_manager.sent[-1]["message"]
    assert message["type"] == "vpn_peer_update_rules"
    assert message["params"]["rules"] == [
        {
            "destination": "192.168.2.30",
            "protocol": "tcp",
            "port_range_start": None,
            "port_range_end": None,
        }
    ]


def test_migration_backfill_builds_minimal_canonical_routes():
    path = Path(__file__).parents[1] / "alembic/versions/0039_vpn_remote_routes.py"
    spec = importlib.util.spec_from_file_location("vpn_routes_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert migration._canonical_route_envelope(
        "192.168.1.7/24",
        "10.21.0.0/24",
        [
            "192.168.1.20",
            "192.168.2.25",
            "192.168.2.0/24",
            "192.168.2.40/32",
            "10.21.0.10",
        ],
    ) == ["192.168.1.0/24", "192.168.2.0/24"]
