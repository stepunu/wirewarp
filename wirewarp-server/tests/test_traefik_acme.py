from __future__ import annotations

from app.services.traefik_ops import LetsEncryptConfig, build_traefik_static_config


def test_static_config_renders_cloudflare_dns_challenge() -> None:
    cfg = build_traefik_static_config(
        letsencrypt=LetsEncryptConfig(
            enabled=True,
            email="admin@example.com",
            challenge="dns-01",
            dns_provider="cloudflare",
            dns_resolvers=["1.1.1.1:53", "1.0.0.1:53"],
            use_staging=True,
            credentials_ready=True,
        )
    )

    acme = cfg["certificatesResolvers"]["wirewarp-le"]["acme"]
    assert acme["email"] == "admin@example.com"
    assert acme["storage"] == "/etc/traefik/acme.json"
    assert acme["caServer"] == "https://acme-staging-v02.api.letsencrypt.org/directory"
    assert acme["dnsChallenge"] == {
        "provider": "cloudflare",
        "resolvers": ["1.1.1.1:53", "1.0.0.1:53"],
    }


def test_static_config_omits_resolver_when_letsencrypt_incomplete() -> None:
    cfg = build_traefik_static_config(
        letsencrypt=LetsEncryptConfig(
            enabled=True,
            email="",
            challenge="dns-01",
            dns_provider="cloudflare",
            dns_resolvers=["1.1.1.1:53"],
            use_staging=False,
        )
    )

    assert "certificatesResolvers" not in cfg
