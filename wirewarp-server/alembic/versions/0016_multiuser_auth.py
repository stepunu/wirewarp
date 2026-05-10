"""Multi-user auth: roles + provider config + secrets-at-rest.

Bundles every schema change required for the user-system / OIDC / LDAP
feature into a single revision so the running deploy goes from 0015 →
0016 atomically:

  * `users`: nullable `password_hash` (external IdP rows have no local
    password), `is_active`, `auth_provider`, `external_id`,
    `last_login_at`, `role` CHECK constraint, partial unique index on
    `(auth_provider, external_id) WHERE external_id IS NOT NULL`.
  * `command_log`: `actor_user_id` FK, `event_type`, `details_json` —
    enables user-attributed audit and auth-event logging into the same
    table.
  * `system_settings`: `auth_provider`, `oidc_config` JSONB,
    `ldap_config` JSONB. Existing `cloudflare_api_token` is re-encrypted
    in place via Fernet (idempotent — skips values that already look
    like a Fernet token).
  * `registration_tokens`: store SHA-256 hex of the plaintext as the
    lookup key. `id` UUID becomes the primary key; the plaintext is
    returned to the admin once on issuance and is no longer persisted.
  * New `oauth_states` table for in-flight OIDC state/nonce, survives
    multi-process deploys.

Revision ID: 0016
Revises: 0015
Create Date: 2026-05-10
"""
from __future__ import annotations

import hashlib
import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # -- users -------------------------------------------------------
    op.alter_column("users", "password_hash", nullable=True)
    op.add_column(
        "users",
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "users",
        sa.Column(
            "auth_provider",
            sa.String(),
            nullable=False,
            server_default="local",
        ),
    )
    op.add_column("users", sa.Column("external_id", sa.String(), nullable=True))
    op.add_column(
        "users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True)
    )

    # Backfill any pre-existing rows with role values outside the new
    # vocabulary. Today only 'admin' / 'viewer' have shipped, but be
    # defensive about anything weirder.
    bind.execute(
        sa.text(
            "UPDATE users SET role = 'admin' "
            "WHERE role IS NULL OR role NOT IN ('admin','operator','viewer')"
        )
    )
    op.alter_column(
        "users",
        "role",
        existing_type=sa.String(),
        nullable=False,
        server_default="admin",
    )
    op.create_check_constraint(
        "ck_users_role", "users", "role IN ('admin','operator','viewer')"
    )
    op.create_index(
        "uq_users_provider_external",
        "users",
        ["auth_provider", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )

    # -- command_log -------------------------------------------------
    op.add_column(
        "command_log",
        sa.Column(
            "actor_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "command_log", sa.Column("event_type", sa.String(), nullable=True)
    )
    op.add_column(
        "command_log",
        sa.Column(
            "details_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
    )

    # -- system_settings + cloudflare token re-encrypt ----------------
    op.add_column(
        "system_settings",
        sa.Column(
            "auth_provider",
            sa.String(),
            nullable=False,
            server_default="local",
        ),
    )
    op.add_column(
        "system_settings",
        sa.Column("oidc_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "system_settings",
        sa.Column("ldap_config", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    # Idempotent: only encrypt values that don't already look Fernet-shaped.
    # Imported lazily so the migration module can still load when alembic
    # is collecting revisions under environments that lack `cryptography`
    # (e.g. lint passes); the actual upgrade requires the dep.
    from app.services.secrets import encrypt_secret, looks_like_fernet

    rows = bind.execute(
        sa.text("SELECT id, cloudflare_api_token FROM system_settings WHERE cloudflare_api_token IS NOT NULL")
    ).fetchall()
    for row in rows:
        raw = row.cloudflare_api_token
        if not raw or looks_like_fernet(raw):
            continue
        bind.execute(
            sa.text(
                "UPDATE system_settings SET cloudflare_api_token = :ct WHERE id = :id"
            ),
            {"ct": encrypt_secret(raw), "id": row.id},
        )

    # -- registration_tokens: token → token_hash + UUID PK ------------
    # Strategy: add new columns (id UUID, token_hash text), populate from
    # the existing rows, drop the old token PK, promote id to PK.
    op.add_column(
        "registration_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "registration_tokens",
        sa.Column("token_hash", sa.String(), nullable=True),
    )
    existing = bind.execute(
        sa.text("SELECT token FROM registration_tokens")
    ).fetchall()
    for row in existing:
        bind.execute(
            sa.text(
                "UPDATE registration_tokens "
                "SET id = :id, token_hash = :h "
                "WHERE token = :tok"
            ),
            {
                "id": uuid.uuid4(),
                "h": hashlib.sha256(row.token.encode("utf-8")).hexdigest(),
                "tok": row.token,
            },
        )
    op.alter_column("registration_tokens", "id", nullable=False)
    op.alter_column("registration_tokens", "token_hash", nullable=False)
    op.drop_constraint(
        "registration_tokens_pkey", "registration_tokens", type_="primary"
    )
    op.create_primary_key("registration_tokens_pkey", "registration_tokens", ["id"])
    op.create_index(
        "ix_registration_tokens_token_hash",
        "registration_tokens",
        ["token_hash"],
        unique=True,
    )
    op.drop_column("registration_tokens", "token")

    # -- oauth_states ------------------------------------------------
    op.create_table(
        "oauth_states",
        sa.Column("state", sa.String(), primary_key=True),
        sa.Column("nonce", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("oauth_states")

    # registration_tokens revert: re-add token col, populate from id (best
    # effort — the original plaintext is unrecoverable from the hash, so
    # we synthesise placeholder values; downgrade in this state is for
    # dev only).
    op.add_column(
        "registration_tokens", sa.Column("token", sa.String(), nullable=True)
    )
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "UPDATE registration_tokens SET token = 'LOST-' || id::text WHERE token IS NULL"
        )
    )
    op.alter_column("registration_tokens", "token", nullable=False)
    op.drop_index(
        "ix_registration_tokens_token_hash", table_name="registration_tokens"
    )
    op.drop_constraint(
        "registration_tokens_pkey", "registration_tokens", type_="primary"
    )
    op.create_primary_key(
        "registration_tokens_pkey", "registration_tokens", ["token"]
    )
    op.drop_column("registration_tokens", "token_hash")
    op.drop_column("registration_tokens", "id")

    op.drop_column("system_settings", "ldap_config")
    op.drop_column("system_settings", "oidc_config")
    op.drop_column("system_settings", "auth_provider")

    op.drop_column("command_log", "details_json")
    op.drop_column("command_log", "event_type")
    op.drop_column("command_log", "actor_user_id")

    op.drop_index("uq_users_provider_external", table_name="users")
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.drop_column("users", "last_login_at")
    op.drop_column("users", "external_id")
    op.drop_column("users", "auth_provider")
    op.drop_column("users", "is_active")
    op.alter_column("users", "password_hash", nullable=False)
