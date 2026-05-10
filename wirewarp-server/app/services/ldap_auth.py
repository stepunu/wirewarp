"""LDAP authentication helper.

`ldap3` is a sync library — wrapped in `run_in_executor` so the FastAPI
async event loop doesn't block on bind/search round-trips.

Config shape (DB-stored, JSONB on `system_settings.ldap_config`):

    {
      "url": "ldaps://ldap.example.com:636",
      "user_dn_template": "uid={username},ou=people,dc=example,dc=com",
      "bind_dn": "cn=svc,dc=example,dc=com",        # optional
      "bind_password": "...",                        # optional, encrypted at rest
      "group_search_base": "ou=groups,dc=example,dc=com",  # optional
      "group_member_attr": "member",                 # default: "member"
      "group_filter_template": "(member={user_dn})", # default
      "group_role_map": {"wirewarp-admins": "admin", "wirewarp-ops": "operator"},
      "default_role": "viewer"
    }

`ldap_authenticate` returns `LdapResult` on success and `None` on
auth failure. Exceptions on connectivity errors (LDAP server down) are
re-raised so the route handler can return a 502.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


ROLE_PRIORITY = {"admin": 3, "operator": 2, "viewer": 1, "vpn_user": 0}


@dataclass
class LdapResult:
    user_dn: str
    role: str
    groups: list[str]
    vpn_enabled: bool = False


def map_groups_to_role(
    groups: list[str], mapping: dict[str, str], default_role: str
) -> str:
    """Pick the highest-privilege role across all matching groups.

    Group keys may be the bare CN (`wirewarp-admins`) or the full DN
    (`cn=wirewarp-admins,ou=groups,dc=example,dc=com`). We compare against
    both forms so operators don't have to memorise our convention.
    """
    chosen: str | None = None
    chosen_priority = -1

    def _cn(dn: str) -> str:
        first = dn.split(",", 1)[0]
        if "=" in first:
            return first.split("=", 1)[1].strip().lower()
        return first.strip().lower()

    cn_index = {_cn(g): g for g in groups}
    dn_index = {g.lower(): g for g in groups}

    for key, role in (mapping or {}).items():
        k = key.lower()
        if k in cn_index or k in dn_index:
            p = ROLE_PRIORITY.get(role, 0)
            if p > chosen_priority:
                chosen = role
                chosen_priority = p
    return chosen or default_role


def _ldap_authenticate_sync(
    username: str, password: str, config: dict[str, Any]
) -> LdapResult | None:
    import ldap3
    from ldap3.core.exceptions import LDAPException

    url = config.get("url")
    if not url:
        raise RuntimeError("LDAP config missing 'url'")
    template = config.get("user_dn_template")
    if not template:
        raise RuntimeError("LDAP config missing 'user_dn_template'")

    user_dn = template.format(username=username)

    server = ldap3.Server(url, get_info=ldap3.NONE)
    try:
        conn = ldap3.Connection(
            server, user=user_dn, password=password, auto_bind=True
        )
    except LDAPException:
        # Bad credentials. ldap3 raises LDAPBindError / LDAPInvalidCredentials.
        return None
    finally:
        pass

    groups: list[str] = []
    base = config.get("group_search_base")
    if base:
        attr = config.get("group_member_attr", "member")
        filter_tpl = config.get("group_filter_template", f"({attr}={{user_dn}})")
        flt = filter_tpl.format(user_dn=user_dn)

        # If a service account was provided, use it for the group search.
        # Otherwise reuse the user's own bind, which works if their DN can
        # read the group OU.
        bind_dn = config.get("bind_dn")
        bind_pw = config.get("bind_password")
        if bind_dn and bind_pw:
            try:
                search_conn = ldap3.Connection(
                    server, user=bind_dn, password=bind_pw, auto_bind=True
                )
            except LDAPException as exc:
                logger.warning("LDAP service-account bind failed: %s", exc)
                search_conn = conn
        else:
            search_conn = conn

        try:
            search_conn.search(
                search_base=base,
                search_filter=flt,
                search_scope=ldap3.SUBTREE,
                attributes=["cn"],
            )
            for entry in search_conn.entries:
                # Use the DN if present, fall back to the cn attribute.
                dn = getattr(entry, "entry_dn", None)
                cn = entry.cn.value if "cn" in entry.entry_attributes_as_dict else None
                groups.append(dn or cn or str(entry))
        except LDAPException as exc:
            logger.warning("LDAP group search failed: %s", exc)
        finally:
            if search_conn is not conn:
                try:
                    search_conn.unbind()
                except Exception:  # noqa: BLE001
                    pass

    try:
        conn.unbind()
    except Exception:  # noqa: BLE001
        pass

    role = map_groups_to_role(
        groups,
        config.get("group_role_map") or {},
        config.get("default_role", "viewer"),
    )
    vpn_enabled = _groups_contain(groups, config.get("vpn_group"))
    return LdapResult(user_dn=user_dn, role=role, groups=groups, vpn_enabled=vpn_enabled)


def _groups_contain(groups: list[str], target: str | None) -> bool:
    """True if `target` (CN or full DN) is present in `groups`. Accepts
    either form so the operator doesn't have to memorise our convention."""
    if not target:
        return False
    target = target.strip()
    if not target:
        return False
    target_lower = target.lower()

    def _cn(dn: str) -> str:
        first = dn.split(",", 1)[0]
        if "=" in first:
            return first.split("=", 1)[1].strip().lower()
        return first.strip().lower()

    for g in groups:
        if g.lower() == target_lower:
            return True
        if _cn(g) == target_lower:
            return True
    return False


async def ldap_authenticate(
    username: str, password: str, config: dict[str, Any]
) -> LdapResult | None:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _ldap_authenticate_sync, username, password, config
    )


async def ldap_test_bind(config: dict[str, Any]) -> tuple[bool, str]:
    """Helper for the settings 'Test connection' button. Tries an
    anonymous bind, or a service-account bind if one is configured.
    """
    import ldap3
    from ldap3.core.exceptions import LDAPException

    url = config.get("url")
    if not url:
        return False, "missing url"

    def _go() -> tuple[bool, str]:
        server = ldap3.Server(url, get_info=ldap3.NONE)
        bind_dn = config.get("bind_dn")
        bind_pw = config.get("bind_password")
        try:
            if bind_dn and bind_pw:
                ldap3.Connection(
                    server, user=bind_dn, password=bind_pw, auto_bind=True
                ).unbind()
            else:
                ldap3.Connection(server, auto_bind=True).unbind()
            return True, "ok"
        except LDAPException as exc:
            return False, str(exc)

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _go)
