"""Validation helpers for VPN client route envelopes."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def _network(value: str, *, field: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(value.strip(), strict=False)
    except (AttributeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise ValueError(f"{field} must be an IPv4 host or CIDR") from exc


def normalize_remote_subnets(
    values: Iterable[str],
    *,
    vpn_network: str | None = None,
) -> list[str]:
    """Return canonical, non-overlapping IPv4 CIDRs in input order."""
    networks: list[ipaddress.IPv4Network] = []
    vpn = _network(vpn_network, field="VPN network") if vpn_network else None

    for value in values:
        network = _network(value, field="Remote subnet")
        if network.prefixlen == 0:
            raise ValueError("Remote subnets cannot include 0.0.0.0/0")
        if vpn is not None and network.overlaps(vpn):
            raise ValueError(
                f"Remote subnet {network.with_prefixlen} overlaps VPN network {vpn.with_prefixlen}"
            )
        for existing in networks:
            if network == existing:
                raise ValueError(f"Duplicate remote subnet {network.with_prefixlen}")
            if network.overlaps(existing):
                raise ValueError(
                    f"Remote subnets {existing.with_prefixlen} and {network.with_prefixlen} overlap"
                )
        networks.append(network)

    return [network.with_prefixlen for network in networks]


def destination_in_route_envelope(
    destination: str,
    *,
    vpn_network: str,
    remote_subnets: Iterable[str],
) -> bool:
    network = _network(destination, field="Permission destination")
    envelope = [_network(vpn_network, field="VPN network")]
    envelope.extend(_network(value, field="Remote subnet") for value in remote_subnets)
    return any(network.subnet_of(route) for route in envelope)
