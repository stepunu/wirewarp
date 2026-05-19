"""Sensitive-port classification for port-forward advisories.

Read-time classifier: every port forward gets checked against a catalogue
of well-known services that are dangerous (or commonly attacked) to expose
publicly. Matches surface a tip card in the UI so operators see the risk
inline before they ever look elsewhere.

Tip copy is intentionally narrow: WireWarp is itself a tunnel tool, so
suggestions are limited to host-local mitigations (CrowdSec, fail2ban,
service config) or hiding behind WireWarp itself — no third-party CDN /
edge / cloud recommendations.
"""

from dataclasses import dataclass
from typing import Literal, Protocol


Severity = Literal["high", "medium"]


@dataclass(frozen=True, slots=True)
class SensitiveServiceTip:
    """One classified sensitive service. Returned to the API as a nested
    object on each PortForwardRead so the UI can render a badge + tip."""

    key: str          # stable identifier, e.g. "ssh", "mysql"
    label: str        # human-readable, e.g. "SSH"
    severity: Severity
    message: str      # one-line advisory shown under the badge


class _PortMatcher(Protocol):
    def __call__(self, protocol: str, port: int) -> bool: ...


@dataclass(frozen=True, slots=True)
class _Entry:
    match: _PortMatcher
    tip: SensitiveServiceTip


_PRIVATE_VPN_LINE = (
    "Best practice: do not expose at all — keep behind WireWarp and reach it "
    "from a peer."
)
_CROWDSEC_LINE = (
    "If exposure is required, deploy CrowdSec (sshd / http / mail parsers + "
    "community blocklists) or fail2ban on the destination host."
)


def _tcp(port: int) -> _PortMatcher:
    def f(protocol: str, p: int) -> bool:
        return protocol == "tcp" and p == port

    return f


def _tcp_in(*ports: int) -> _PortMatcher:
    s = frozenset(ports)

    def f(protocol: str, p: int) -> bool:
        return protocol == "tcp" and p in s

    return f


# Catalogue order matters: when a range overlaps multiple entries, the
# first match wins. List highest-severity entries before broader ones.
_CATALOGUE: tuple[_Entry, ...] = (
    _Entry(
        match=_tcp(23),
        tip=SensitiveServiceTip(
            key="telnet",
            label="Telnet",
            severity="high",
            message=(
                "Telnet sends credentials in clear text and should never face "
                "the internet. Replace with SSH and " + _PRIVATE_VPN_LINE.lower()
            ),
        ),
    ),
    _Entry(
        match=_tcp_in(2375, 2376),
        tip=SensitiveServiceTip(
            key="docker-api",
            label="Docker API",
            severity="high",
            message=(
                "An unauthenticated Docker socket exposed to the internet is "
                "equivalent to root on the host. " + _PRIVATE_VPN_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp(3306),
        tip=SensitiveServiceTip(
            key="mysql",
            label="MySQL / MariaDB",
            severity="high",
            message=(
                "Database engines should not face the internet. Bind to "
                "127.0.0.1 (or LAN only) and reach it through WireWarp. "
                + _CROWDSEC_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp(5432),
        tip=SensitiveServiceTip(
            key="postgres",
            label="PostgreSQL",
            severity="high",
            message=(
                "Database engines should not face the internet. Bind to "
                "127.0.0.1 (or LAN only) and reach it through WireWarp. "
                + _CROWDSEC_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp_in(27017, 27018),
        tip=SensitiveServiceTip(
            key="mongodb",
            label="MongoDB",
            severity="high",
            message=(
                "MongoDB has a long history of unauthenticated public "
                "instances getting wiped. " + _PRIVATE_VPN_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp(6379),
        tip=SensitiveServiceTip(
            key="redis",
            label="Redis",
            severity="high",
            message=(
                "Redis authentication is weak by default and remote code "
                "execution via abused commands is common. " + _PRIVATE_VPN_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp(11211),
        tip=SensitiveServiceTip(
            key="memcached",
            label="Memcached",
            severity="high",
            message=(
                "Memcached has no authentication at all and has been abused "
                "for UDP amplification attacks. " + _PRIVATE_VPN_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp_in(9200, 9300),
        tip=SensitiveServiceTip(
            key="elasticsearch",
            label="Elasticsearch",
            severity="high",
            message=(
                "Open Elasticsearch clusters are routinely scraped and "
                "ransomed. " + _PRIVATE_VPN_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp(5984),
        tip=SensitiveServiceTip(
            key="couchdb",
            label="CouchDB",
            severity="high",
            message=(
                "CouchDB has a long CVE list around admin endpoints. "
                + _PRIVATE_VPN_LINE
            ),
        ),
    ),
    _Entry(
        match=_tcp(3389),
        tip=SensitiveServiceTip(
            key="rdp",
            label="RDP",
            severity="high",
            message=(
                "RDP is under constant bruteforce and has a heavy CVE "
                "history. " + _PRIVATE_VPN_LINE + " Otherwise add CrowdSec or "
                "fail2ban with the rdp-bf scenario."
            ),
        ),
    ),
    _Entry(
        match=_tcp_in(5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910),
        tip=SensitiveServiceTip(
            key="vnc",
            label="VNC",
            severity="high",
            message=(
                "VNC authentication is weak. " + _PRIVATE_VPN_LINE
                + " Alternatively tunnel over SSH."
            ),
        ),
    ),
    _Entry(
        match=_tcp(22),
        tip=SensitiveServiceTip(
            key="ssh",
            label="SSH",
            severity="medium",
            message=(
                "SSH bruteforce is the most common internet attack. Mitigate "
                "with CrowdSec (sshd parser + community blocklist) or "
                "fail2ban on the destination host, disable password "
                "authentication, or expose via WireWarp only."
            ),
        ),
    ),
    _Entry(
        match=_tcp_in(25, 465, 587),
        tip=SensitiveServiceTip(
            key="smtp",
            label="SMTP submission",
            severity="medium",
            message=(
                "Mail submission ports are heavily probed. Run CrowdSec with "
                "the postfix / dovecot parsers on the destination, or front "
                "with mailcow / rspamd which bundle rate-limiting."
            ),
        ),
    ),
    _Entry(
        match=_tcp_in(110, 143, 993, 995),
        tip=SensitiveServiceTip(
            key="imap-pop",
            label="IMAP / POP3",
            severity="medium",
            message=(
                "Mailbox protocols are heavily probed. Run CrowdSec with the "
                "dovecot parser on the destination."
            ),
        ),
    ),
    _Entry(
        match=_tcp(10000),
        tip=SensitiveServiceTip(
            key="webmin",
            label="Webmin",
            severity="medium",
            message=(
                "Webmin has a long CVE history and is a common bruteforce "
                "target. " + _PRIVATE_VPN_LINE + " Otherwise add CrowdSec "
                "and keep it strictly patched."
            ),
        ),
    ),
    _Entry(
        match=_tcp_in(8080, 8081, 8443, 9000, 9090),
        tip=SensitiveServiceTip(
            key="admin-http",
            label="Generic admin / HTTP panel",
            severity="medium",
            message=(
                "Generic admin panels are a common bruteforce + CVE target. "
                + _PRIVATE_VPN_LINE + " Otherwise put an auth proxy (Authelia "
                "/ Authentik) in front and add CrowdSec http-cve scenarios."
            ),
        ),
    ),
)


def classify_forward(
    protocol: str,
    public_port: int,
    public_port_end: int | None = None,
) -> SensitiveServiceTip | None:
    """Return the first matching sensitive-service tip for the forward, or
    None if no entry in the catalogue applies.

    Ranges are checked port-by-port within the catalogue; the first
    catalogue entry to match any port in [public_port, public_port_end]
    wins, which keeps the result stable and surfaces the worst-severity
    advisory (catalogue is ordered high → medium).
    """
    end = public_port_end if public_port_end is not None else public_port
    if end < public_port:
        return None
    for entry in _CATALOGUE:
        for p in range(public_port, end + 1):
            if entry.match(protocol, p):
                return entry.tip
    return None
