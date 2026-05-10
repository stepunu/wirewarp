"""Round-trip + tamper checks for app.services.secrets."""
from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken

from app.services.secrets import (
    FERNET_PREFIX,
    decrypt_ldap_config,
    decrypt_oidc_config,
    decrypt_secret,
    encrypt_ldap_config,
    encrypt_oidc_config,
    encrypt_secret,
    hash_token,
    looks_like_fernet,
    verify_token,
)


def test_encrypt_decrypt_round_trip():
    plaintext = "cf-tok-abc123-with-symbols-!@#"
    ct = encrypt_secret(plaintext)
    assert ct != plaintext
    assert ct.startswith(FERNET_PREFIX)
    assert decrypt_secret(ct) == plaintext


def test_encrypt_two_calls_different_ciphertexts():
    a = encrypt_secret("same")
    b = encrypt_secret("same")
    assert a != b
    assert decrypt_secret(a) == decrypt_secret(b) == "same"


def test_decrypt_tampered_raises():
    ct = encrypt_secret("hello")
    tampered = ct[:-2] + ("aa" if ct[-2:] != "aa" else "bb")
    with pytest.raises(InvalidToken):
        decrypt_secret(tampered)


def test_hash_token_is_deterministic_and_hex():
    a = hash_token("AAAA-BBBB-CCCC")
    b = hash_token("AAAA-BBBB-CCCC")
    assert a == b
    assert len(a) == 64
    int(a, 16)  # parses as hex


def test_verify_token_match_and_mismatch():
    plaintext = "AAAA-BBBB-CCCC"
    h = hash_token(plaintext)
    assert verify_token(plaintext, h) is True
    assert verify_token(plaintext + "X", h) is False
    assert verify_token("totally-different", h) is False


def test_looks_like_fernet():
    assert looks_like_fernet(encrypt_secret("x")) is True
    assert looks_like_fernet("not-a-fernet-token") is False
    assert looks_like_fernet("") is False
    assert looks_like_fernet(None) is False


def test_encrypt_oidc_config_only_touches_secret_keys():
    cfg = {
        "issuer": "https://idp.example",
        "client_id": "wirewarp",
        "client_secret": "shh",
        "claim_role_map": {"wg-admins": "admin"},
    }
    enc = encrypt_oidc_config(cfg)
    assert enc["issuer"] == cfg["issuer"]
    assert enc["client_id"] == cfg["client_id"]
    assert enc["claim_role_map"] == cfg["claim_role_map"]
    assert enc["client_secret"] != cfg["client_secret"]
    assert looks_like_fernet(enc["client_secret"])

    dec = decrypt_oidc_config(enc)
    assert dec["client_secret"] == "shh"


def test_encrypt_oidc_config_idempotent():
    """Calling encrypt twice must not double-encrypt the secret."""
    cfg = {"client_secret": "shh"}
    once = encrypt_oidc_config(cfg)
    twice = encrypt_oidc_config(once)
    assert twice["client_secret"] == once["client_secret"]


def test_encrypt_ldap_config_round_trip():
    cfg = {
        "url": "ldaps://ldap.example",
        "bind_dn": "cn=svc,dc=example,dc=com",
        "bind_password": "very-secret",
        "user_dn_template": "uid={username},ou=people,dc=example,dc=com",
    }
    enc = encrypt_ldap_config(cfg)
    assert enc["bind_password"] != cfg["bind_password"]
    assert looks_like_fernet(enc["bind_password"])
    assert enc["url"] == cfg["url"]
    dec = decrypt_ldap_config(enc)
    assert dec["bind_password"] == "very-secret"


def test_encrypt_blob_handles_none_and_missing_keys():
    assert encrypt_oidc_config(None) is None
    assert encrypt_oidc_config({"issuer": "x"}) == {"issuer": "x"}
