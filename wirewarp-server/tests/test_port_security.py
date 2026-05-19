"""Sensitive-port catalogue tests for app.services.port_security.

The classifier is a pure function — no DB / async needed. We just want to
catch the obvious regressions: hits trigger, ranges work, unknown ports
stay None, UDP doesn't accidentally inherit TCP-only tips.
"""

from app.services.port_security import classify_forward


def test_classify_ssh_tcp_hit():
    tip = classify_forward("tcp", 22)
    assert tip is not None
    assert tip.key == "ssh"
    assert tip.severity == "medium"


def test_classify_telnet_tcp_hit_high_severity():
    tip = classify_forward("tcp", 23)
    assert tip is not None
    assert tip.key == "telnet"
    assert tip.severity == "high"


def test_classify_mysql_tcp_hit():
    assert classify_forward("tcp", 3306).key == "mysql"


def test_classify_redis_tcp_hit():
    assert classify_forward("tcp", 6379).key == "redis"


def test_classify_smtp_alt_submission_ports():
    for port in (25, 465, 587):
        assert classify_forward("tcp", port).key == "smtp"


def test_classify_admin_http_alt_ports():
    for port in (8080, 8443, 9000):
        assert classify_forward("tcp", port).key == "admin-http"


def test_classify_no_hit_for_arbitrary_port():
    assert classify_forward("tcp", 25565) is None
    assert classify_forward("udp", 25565) is None


def test_classify_ssh_port_on_udp_does_not_match():
    # SSH catalogue entry is TCP-only; UDP 22 should not pop the tip.
    assert classify_forward("udp", 22) is None


def test_classify_range_overlapping_ssh_triggers():
    tip = classify_forward("tcp", 20, public_port_end=25)
    assert tip is not None
    # SMTP wins in this range because it sits earlier in the high → medium
    # ordering only by virtue of higher severity sections being first.
    # 22 and 23 (high-severity telnet) and 25 (medium smtp) are all in the
    # range — high-severity must win.
    assert tip.severity == "high"


def test_classify_range_with_no_sensitive_port_is_none():
    assert classify_forward("tcp", 25500, public_port_end=25600) is None


def test_classify_inverted_range_is_none():
    # Caller bug, but should not crash.
    assert classify_forward("tcp", 100, public_port_end=50) is None


def test_classify_rdp_and_vnc():
    assert classify_forward("tcp", 3389).key == "rdp"
    assert classify_forward("tcp", 5900).key == "vnc"
    assert classify_forward("tcp", 5910).key == "vnc"


def test_classify_message_mentions_mitigations():
    tip = classify_forward("tcp", 22)
    assert tip is not None
    # SSH tip must reference at least one of the three mitigations the user
    # asked for. If this fails because copy was edited, update the assert.
    assert any(s in tip.message for s in ("CrowdSec", "fail2ban", "WireWarp"))
