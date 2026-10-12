"""Standalone proof against disposable Knot primary and secondary processes.

Requires the existing local Knot image. It never pulls an image or contacts
production DNS. All keys, zones, and records below are synthetic test data.
"""
import concurrent.futures
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


AGENT_ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:6d8c0b7ec8bf758fa2d99d64d80a23e1faf268ad74c6989562b23852463754fc"
NAME = "wirewarp-acme-hook-proof-" + uuid.uuid4().hex[:10]
SECRET = "dGVzdC1hY21lLXNlY3JldA=="
RECORD = "_acme-challenge.app.example.test."
A, B = "A" * 43, "B" * 43


def command(args, *, timeout=30, check=True, cwd=None, env=None):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    if check and result.returncode:
        # Do not include command arguments, credentials, DNS records, or output.
        raise RuntimeError("Synthetic Knot proof command failed")
    return result


def records(port):
    result = command(["docker", "exec", NAME, "kdig", "@127.0.0.1", "-p", str(port), RECORD, "TXT", "+short"])
    return set(re.findall(r'^"([^"\n]+)"$', result.stdout, re.MULTILINE))


def wait_records(expected):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if records(15353) == expected and records(25353) == expected:
            return
        time.sleep(0.1)
    raise RuntimeError("Primary or secondary TXT contents did not match")


def hook(action, value, *, secret_file="/tmp/proof-secret", server="127.0.0.1:15353", expect_success=True):
    args = ["docker", "exec", "-e", "RFC2136_NAMESERVER=" + server, "-e", "RFC2136_TSIG_KEY=acme.example.test.", "-e", "RFC2136_TSIG_ALGORITHM=hmac-sha256", "-e", "RFC2136_TSIG_SECRET_FILE=" + secret_file, NAME, "bash", "-c", '/proof/agent acme-dns "$@"; result=$?; exit "$result"', "proof", action, RECORD, value]
    result = command(args, check=False, timeout=25)
    if (result.returncode == 0) != expect_success:
        raise RuntimeError("Helper result did not match the expected status")
    if result.stdout or any(value in result.stderr for value in (SECRET, A, B, RECORD)):
        raise RuntimeError("Helper output exposed credentials or challenge data")
    return result


def run():
    command(["docker", "image", "inspect", IMAGE])
    with tempfile.TemporaryDirectory(prefix="wirewarp-knot-hook-") as temporary:
        root = Path(temporary)
        (root / "secret").write_text(SECRET)
        (root / "wrong-secret").write_text("aW52YWxpZC1rZXk=")
        (root / "example.test.zone").write_text("$ORIGIN example.test.\n$TTL 60\n@ IN SOA ns1.example.test. hostmaster.example.test. 1 5 2 3600 5\n@ IN NS ns1.example.test.\n@ IN NS ns2.example.test.\nns1 IN A 127.0.0.1\nns2 IN A 127.0.0.1\n_acme-challenge.app IN TXT \"external-existing\"\n")
        key = "key:\n  - id: acme.example.test.\n    algorithm: hmac-sha256\n    secret: " + SECRET + "\n"
        (root / "primary.conf").write_text("server:\n  listen: 127.0.0.1@15353\n  rundir: /tmp/knot-primary-run\nlog:\n  - target: stderr\n    any: warning\n" + key + "remote:\n  - id: secondary\n    address: 127.0.0.1@25353\n    key: acme.example.test.\nacl:\n  - id: transfer\n    address: 127.0.0.1\n    key: acme.example.test.\n    action: transfer\n  - id: acme-update\n    address: 127.0.0.1\n    key: acme.example.test.\n    action: update\n    update-type: TXT\ndatabase:\n  storage: /tmp/knot-primary-data\nzone:\n  - domain: example.test.\n    file: /tmp/knot-primary-data/example.test.zone\n    acl: [transfer, acme-update]\n    notify: secondary\n    zonefile-sync: -1\n")
        (root / "secondary.conf").write_text("server:\n  listen: 127.0.0.1@25353\n  rundir: /tmp/knot-secondary-run\nlog:\n  - target: stderr\n    any: warning\n" + key + "remote:\n  - id: primary\n    address: 127.0.0.1@15353\n    key: acme.example.test.\nacl:\n  - id: notify\n    address: 127.0.0.1\n    key: acme.example.test.\n    action: notify\ndatabase:\n  storage: /tmp/knot-secondary-data\nzone:\n  - domain: example.test.\n    master: primary\n    acl: notify\n")
        build_env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
        command(["go", "build", "-o", str(root / "agent"), "./cmd/agent"], timeout=120, cwd=AGENT_ROOT, env=build_env)
        os.chmod(root, 0o755)
        startup = """set -e
mkdir -p /tmp/knot-primary-run /tmp/knot-primary-data /tmp/knot-secondary-run /tmp/knot-secondary-data
cp /proof/example.test.zone /tmp/knot-primary-data/example.test.zone
cp /proof/secret /tmp/proof-secret
cp /proof/wrong-secret /tmp/proof-wrong-secret
cp /proof/secret /tmp/proof-readable-secret
chmod 0600 /tmp/proof-secret /tmp/proof-wrong-secret
chmod 0644 /tmp/proof-readable-secret
knotd -c /proof/primary.conf &
primary_pid=$!
knotd -c /proof/secondary.conf &
secondary_pid=$!
trap 'kill "$primary_pid" "$secondary_pid"; wait' TERM INT EXIT
wait
"""
        started = False
        try:
            command(["docker", "run", "--rm", "-d", "--name", NAME, "--network", "none", "-v", str(root) + ":/proof:ro", IMAGE, "bash", "-c", startup])
            started = True
            wait_records({"external-existing"})
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                tasks = [pool.submit(hook, "present", value) for value in (A, B)]
                for task in tasks:
                    task.result()
            wait_records({"external-existing", A, B})
            hook("cleanup", A)
            hook("cleanup", A)
            wait_records({"external-existing", B})
            primary_path = root / "primary.conf"
            primary_config = primary_path.read_text()
            primary_path.write_text(primary_config.replace("action: update", "action: transfer"))
            command(["docker", "exec", NAME, "knotc", "-c", "/proof/primary.conf", "reload"])
            hook("cleanup", B, expect_success=False)
            wait_records({"external-existing", B})
            primary_path.write_text(primary_config)
            command(["docker", "exec", NAME, "knotc", "-c", "/proof/primary.conf", "reload"])
            command(["docker", "exec", NAME, "/proof/agent", "acme-dns-cleanup"])
            wait_records({"external-existing"})
            hook("present", A, secret_file="/tmp/proof-wrong-secret", expect_success=False)
            hook("present", A, secret_file="/tmp/proof-readable-secret", expect_success=False)
            hook("present", A, server="127.0.0.1:25353", expect_success=False)
            wait_records({"external-existing"})
            hook("cleanup", B)
            wait_records({"external-existing"})
            version = command(["docker", "exec", NAME, "knotd", "-V"]).stdout.strip().splitlines()[0]
            print("PASS: concurrent helpers preserved TXT values on real primary and secondary; durable retry after denied cleanup, exact cleanup, bad TSIG, and secret mode checks passed. " + version)
        finally:
            if started:
                command(["docker", "stop", "-t", "5", NAME], timeout=15)
                deadline = time.monotonic() + 5
                while True:
                    remaining = command(["docker", "ps", "-a", "--filter", "name=^/" + NAME + "$", "--format", "{{.Names}}"])
                    if not remaining.stdout.strip():
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Synthetic Knot container did not stop and remove")
                    time.sleep(0.1)
            print("Verified disposable Knot container cleanup.")


if __name__ == "__main__":
    run()
