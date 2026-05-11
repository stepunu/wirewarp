"""Regression tests for the SPA-fallback path-traversal fix in app/main.py.

A pre-auth `GET /../alembic.ini` (or any path that resolves outside
STATIC_DIR) must NOT leak the file's contents; the handler should fall
back to index.html. SPA-style paths that don't match a file (e.g.
/agents, /servers) keep returning index.html. Real static files
(/vite.svg, /favicon.ico) still resolve.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


def _static_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "static"


def _index_bytes() -> bytes:
    return (_static_dir() / "index.html").read_bytes()


@pytest.mark.asyncio
async def test_spa_fallback_serves_real_file() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get("/vite.svg")
    assert r.status_code == 200
    assert r.content == (_static_dir() / "vite.svg").read_bytes()


@pytest.mark.asyncio
async def test_spa_fallback_unknown_route_returns_index() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get("/agents")
    assert r.status_code == 200
    assert r.content == _index_bytes()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "evil_path",
    [
        "/..%2Falembic.ini",
        "/..%2F..%2Falembic.ini",
        "/..%2F..%2Fetc%2Fpasswd",
        "/..%2Fapp%2Fmain.py",
        "/..%2F..%2Fpyproject.toml",
    ],
)
async def test_spa_fallback_rejects_path_traversal(evil_path: str) -> None:
    """Any traversal attempt must NOT return the targeted file. The handler
    falls back to index.html so the response body is the SPA shell, never
    the contents of a file outside STATIC_DIR.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get(evil_path)
    assert r.status_code == 200
    # The fallback always returns the SPA shell. If a future regression
    # served the targeted file, this assertion would fail.
    assert r.content == _index_bytes()
    # And make doubly sure none of the well-known target signatures slip
    # through (defense-in-depth against an HTML index.html that happens
    # to share bytes with index.html — vanishingly unlikely, but cheap).
    assert b"root:x:0:0:" not in r.content
    assert b"sqlalchemy.url" not in r.content
