"""Keypair generation + .conf rendering."""
from __future__ import annotations

import base64
import uuid

import pytest

from app.models.vpn_endpoint import VpnEndpoint
from app.models.vpn_permission import VpnPermission
from app.models.vpn_profile import VpnProfile
from app.services.vpn_ops import (
    compute_allowed_ips,
    generate_keypair,
    generate_psk,
    render_conf,
)


def _endpoint(**over) -> VpnEndpoint:
    base = dict(
        id=uuid.uuid4(),
        tunnel_client_id=uuid.uuid4(),
        wg_interface="wg-vpn0",
        listen_port=51821,
        vpn_network="10.30.0.0/24",
        public_endpoint="vpn.example.com:51821",
        wg_public_key="ENDPOINTPUBKEY",
        dns_servers=None,
        remote_subnets=["192.168.1.0/24", "192.168.2.0/24"],
        route_revision=1,
        enabled=True,
    )
    base.update(over)
    return VpnEndpoint(**base)


def _profile(**over) -> VpnProfile:
    base = dict(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        vpn_endpoint_id=uuid.uuid4(),
        label="phone",
        tunnel_ip="10.30.0.2",
        wg_public_key="PROFILEPUBKEY",
        wg_psk="PSKPSKPSK",
        tunnel_mode="split",
    )
    base.update(over)
    return VpnProfile(**base)


def _perm(**over) -> VpnPermission:
    base = dict(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        vpn_endpoint_id=uuid.uuid4(),
        destination="192.168.1.50",
        protocol="any",
        port_range_start=None,
        port_range_end=None,
    )
    base.update(over)
    return VpnPermission(**base)


def test_keypair_shape():
    kp = generate_keypair()
    raw_priv = base64.b64decode(kp.private_key)
    raw_pub = base64.b64decode(kp.public_key)
    assert len(raw_priv) == 32
    assert len(raw_pub) == 32
    assert kp.private_key != kp.public_key


def test_psk_shape():
    psk = generate_psk()
    assert len(base64.b64decode(psk)) == 32


def test_split_tunnel_allowed_ips_uses_endpoint_routes_not_permissions():
    ep = _endpoint()
    p = _profile(tunnel_mode="split")
    perms = [
        _perm(destination="192.168.1.50"),
        _perm(destination="192.168.2.0/24"),
    ]
    assert compute_allowed_ips(ep, p, perms) == [
        "10.30.0.0/24",
        "192.168.1.0/24",
        "192.168.2.0/24",
    ]


def test_split_tunnel_with_no_perms_keeps_all_endpoint_routes():
    ep = _endpoint()
    p = _profile(tunnel_mode="split")
    assert compute_allowed_ips(ep, p, []) == [
        "10.30.0.0/24",
        "192.168.1.0/24",
        "192.168.2.0/24",
    ]


def test_full_tunnel_overrides_perms():
    ep = _endpoint()
    p = _profile(tunnel_mode="full")
    perms = [_perm(destination="192.168.1.50")]
    assert compute_allowed_ips(ep, p, perms) == ["0.0.0.0/0"]


def test_render_conf_contains_required_blocks():
    ep = _endpoint(dns_servers=["1.1.1.1", "1.0.0.1"])
    p = _profile()
    perms = [_perm(destination="192.168.1.50")]
    text = render_conf(
        endpoint=ep, profile=p, permissions=perms, private_key="PRIVPRIV"
    )
    assert "[Interface]" in text
    assert "PrivateKey = PRIVPRIV" in text
    assert "Address = 10.30.0.2/32" in text
    assert "DNS = 1.1.1.1, 1.0.0.1" in text
    assert "[Peer]" in text
    assert "PublicKey = ENDPOINTPUBKEY" in text
    assert "PresharedKey = PSKPSKPSK" in text
    assert "AllowedIPs = 10.30.0.0/24, 192.168.1.0/24, 192.168.2.0/24" in text
    assert "Endpoint = vpn.example.com:51821" in text
    assert "PersistentKeepalive = 25" in text


def test_render_conf_full_tunnel_allowed_ips():
    ep = _endpoint()
    p = _profile(tunnel_mode="full")
    text = render_conf(
        endpoint=ep, profile=p, permissions=[], private_key="PRIVPRIV"
    )
    assert "AllowedIPs = 0.0.0.0/0" in text
    assert "::/0" not in text


def test_render_conf_endpoint_pubkey_pending_marker_when_endpoint_not_yet_initialized():
    ep = _endpoint(wg_public_key=None)
    p = _profile()
    text = render_conf(endpoint=ep, profile=p, permissions=[], private_key="X")
    assert "PublicKey = PENDING_ENDPOINT_INIT" in text
