"""JWT typ claim split: user vs agent tokens must not be cross-acceptable."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.auth import (
    TYP_AGENT,
    TYP_USER,
    create_access_token,
    create_agent_token,
    decode_token,
)


def test_user_token_decoded_as_user():
    tok = create_access_token("alice")
    assert decode_token(tok, expected_typ=TYP_USER) == "alice"


def test_user_token_rejected_as_agent():
    tok = create_access_token("alice")
    with pytest.raises(HTTPException) as exc:
        decode_token(tok, expected_typ=TYP_AGENT)
    assert exc.value.status_code == 401


def test_agent_token_decoded_as_agent():
    tok = create_agent_token("11111111-1111-1111-1111-111111111111")
    assert decode_token(tok, expected_typ=TYP_AGENT).startswith("11111111")


def test_agent_token_rejected_as_user():
    tok = create_agent_token("11111111-1111-1111-1111-111111111111")
    with pytest.raises(HTTPException) as exc:
        decode_token(tok, expected_typ=TYP_USER)
    assert exc.value.status_code == 401


def test_pre_0016_legacy_token_treated_as_either_for_grace():
    """Tokens issued before 0016 lack the `typ` claim. The decode helper
    accepts those for both user and agent auth during the grace window —
    pre-split tokens were all issued by the same trusted SECRET_KEY, so
    the cross-typ threat model doesn't apply. Tokens that DO carry a
    `typ` claim are still strictly validated (asserted by the four
    other tests in this file)."""
    from datetime import datetime, timedelta, timezone

    from jose import jwt

    from app.config import settings

    legacy = jwt.encode(
        {"sub": "alice", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        settings.SECRET_KEY,
        algorithm="HS256",
    )
    assert decode_token(legacy, expected_typ=TYP_USER) == "alice"
    assert decode_token(legacy, expected_typ=TYP_AGENT) == "alice"
