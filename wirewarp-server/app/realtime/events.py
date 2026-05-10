"""Typed publishers for the dashboard realtime channel.

Each helper is a one-line wrapper around `bus.publish_nowait`. They
exist mostly for grep-ability — a `bus.publish("foo")` is hard to find
across the codebase, but `emit_tunnel_server_changed()` is not. Keep
them dumb: minimal payload (the frontend uses the event as a key, not
a state diff). If you need to ship structured payloads later (e.g. a
status flip without forcing a refetch), add a new helper rather than
overloading these.
"""
from __future__ import annotations

from app.realtime.bus import bus


def emit_agent_changed() -> None:
    bus.publish_nowait("agent.changed")


def emit_tunnel_server_changed() -> None:
    bus.publish_nowait("tunnel_server.changed")


def emit_tunnel_client_changed() -> None:
    bus.publish_nowait("tunnel_client.changed")


def emit_port_forward_changed() -> None:
    bus.publish_nowait("port_forward.changed")


def emit_lan_client_changed() -> None:
    bus.publish_nowait("lan_client.changed")


def emit_audit_changed() -> None:
    bus.publish_nowait("audit.changed")
