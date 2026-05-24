"""Unit tests for VpnPermissionInput.destination validation.

The API previously accepted joined CIDR strings — the row was persisted
verbatim and the agent's IPv4CIDR validator rejected the resulting
`vpn_peer_add` command. The schema now mirrors the agent: one IPv4
host or CIDR per row.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.vpn import VpnPermissionInput


def test_accepts_bare_ipv4_host():
    p = VpnPermissionInput(destination="192.168.1.50")
    assert p.destination == "192.168.1.50"


def test_accepts_ipv4_cidr():
    p = VpnPermissionInput(destination="192.168.2.0/24")
    assert p.destination == "192.168.2.0/24"


def test_accepts_host_with_32_suffix():
    p = VpnPermissionInput(destination="10.0.0.5/32")
    assert p.destination == "10.0.0.5/32"


def test_trims_whitespace():
    p = VpnPermissionInput(destination="  192.168.1.50  ")
    assert p.destination == "192.168.1.50"


@pytest.mark.parametrize(
    "joined",
    [
        "192.168.1.50,192.168.1.51",
        "192.168.20.5/32,192.168.20.90/32,192.168.20.111/32,192.168.20.115/32",
        "192.168.1.50 192.168.1.51",
        "192.168.1.50;192.168.1.51",
        "192.168.1.50\t192.168.1.51",
    ],
)
def test_rejects_joined_destinations(joined: str):
    with pytest.raises(ValidationError) as ei:
        VpnPermissionInput(destination=joined)
    assert "one CIDR" in str(ei.value) or "multiple rows" in str(ei.value)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-an-ip",
        "999.0.0.1",
        "192.168.1.0/33",
        "192.168.1",
        "::1",  # IPv6 not supported by the agent
        "2001:db8::/32",
    ],
)
def test_rejects_malformed(bad: str):
    with pytest.raises(ValidationError):
        VpnPermissionInput(destination=bad)
