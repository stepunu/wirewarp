package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// crowdSecWhitelistFile is the parser drop-in we write under the
// s02-enrich phase. CrowdSec loads every YAML in this directory; we use
// a distinct filename so we coexist cleanly with any operator-managed
// whitelist (e.g. the homelab Ansible role's 99-local-whitelist.yaml).
const crowdSecWhitelistFile = "/etc/crowdsec/parsers/s02-enrich/99-wirewarp-whitelist.yaml"

// crowdSecInstallTimeout is the upper bound for the whole install
// sequence (apt update + install + cscli register + collections + hub
// upgrade). Generous because apt + cscli network ops can be slow on
// throttled or far-away packagecloud mirrors.
const crowdSecInstallTimeout = 8 * time.Minute

// CrowdSecInstallParams carries the auto-whitelist payload from the
// control server. The server builds it from the DB and re-pushes via
// `crowdsec_sync_whitelist` whenever it drifts.
type CrowdSecInstallParams struct {
	IPs   []string `json:"ips"`
	CIDRs []string `json:"cidrs"`
}

func (h *ServerHandlers) handleCrowdSecInstall(raw json.RawMessage) (string, error) {
	var p CrowdSecInstallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), crowdSecInstallTimeout)
	defer cancel()

	var logBuf strings.Builder
	logf := func(format string, args ...any) {
		fmt.Fprintf(&logBuf, format, args...)
		if !strings.HasSuffix(format, "\n") {
			logBuf.WriteString("\n")
		}
	}

	already := resolveCSCli() != ""
	if already {
		logf("cscli already present — skipping apt install")
	} else {
		if err := assertDebianFamily(); err != nil {
			return "", fmt.Errorf("install precheck: %w", err)
		}

		logf("==> add packagecloud repo")
		if out, err := runShell(ctx, "curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash"); err != nil {
			return logBuf.String(), fmt.Errorf("packagecloud repo install: %w\n%s", err, out)
		} else {
			logBuf.WriteString(tail(out, 8))
		}

		logf("==> apt-get update")
		if out, err := runCmd(ctx, "apt-get", "update", "-y"); err != nil {
			return logBuf.String(), fmt.Errorf("apt-get update: %w\n%s", err, out)
		} else {
			logBuf.WriteString(tail(out, 4))
		}

		logf("==> apt-get install crowdsec + iptables bouncer")
		out, err := runCmd(ctx, "apt-get", "install", "-y", "crowdsec", "crowdsec-firewall-bouncer-iptables")
		if err != nil {
			return logBuf.String(), fmt.Errorf("apt-get install: %w\n%s", err, out)
		}
		logBuf.WriteString(tail(out, 8))

		logf("==> systemctl enable --now crowdsec")
		if out, err := runCmd(ctx, "systemctl", "enable", "--now", "crowdsec"); err != nil {
			return logBuf.String(), fmt.Errorf("enable crowdsec: %w\n%s", err, out)
		} else {
			logBuf.WriteString(string(out))
		}
	}

	// CAPI registration is idempotent: re-running on an already-
	// registered host emits a warning then exits 0.
	logf("==> cscli capi register")
	if out, err := runCmd(ctx, "cscli", "capi", "register"); err != nil {
		// Treat "already registered" as success — cscli signals it via
		// stderr text rather than a distinct exit code.
		if !strings.Contains(string(out), "already registered") {
			return logBuf.String(), fmt.Errorf("capi register: %w\n%s", err, out)
		}
		logf("(already registered)")
	} else {
		logBuf.WriteString(tail(out, 4))
	}

	logf("==> cscli collections install crowdsecurity/linux")
	if out, err := runCmd(ctx, "cscli", "collections", "install", "crowdsecurity/linux"); err != nil {
		// Already-installed: cscli exits 0, but we still want to log the noise.
		return logBuf.String(), fmt.Errorf("collections install: %w\n%s", err, out)
	} else {
		logBuf.WriteString(tail(out, 6))
	}

	logf("==> cscli hub upgrade")
	if out, err := runCmd(ctx, "cscli", "hub", "upgrade"); err != nil {
		// Non-fatal: blocklists / scenarios still work even if the hub
		// is briefly unreachable.
		logf("WARN: hub upgrade: %v\n%s", err, tail(out, 4))
	} else {
		logBuf.WriteString(tail(out, 4))
	}

	logf("==> apply WireWarp auto-whitelist (%d ips, %d cidrs)", len(p.IPs), len(p.CIDRs))
	if err := writeWhitelist(p); err != nil {
		return logBuf.String(), fmt.Errorf("write whitelist: %w", err)
	}

	logf("==> systemctl reload crowdsec")
	if out, err := runCmd(ctx, "systemctl", "reload", "crowdsec"); err != nil {
		// Some packaged units only support restart; fall through.
		if out2, err2 := runCmd(ctx, "systemctl", "restart", "crowdsec"); err2 != nil {
			return logBuf.String(), fmt.Errorf("reload+restart crowdsec: %w / %v\n%s\n%s", err, err2, out, out2)
		}
	}

	// Surface the post-install service state in the command output so an
	// install that succeeds but whose unit fails to start is visible in
	// the audit log instead of looking like a silent "not detected".
	if active, statusMsg := crowdSecServiceActive(ctx); active {
		logf("==> crowdsec service is active")
	} else {
		logf("WARN: crowdsec service not active after install:\n%s", statusMsg)
	}

	// Push a crowdsec_status frame immediately so the dashboard card
	// flips from "not detected" to "running" the instant install
	// finishes, rather than waiting up to 5 min for the next poll.
	// Spawn in a goroutine — collectCrowdSec runs cscli metrics which
	// can take 20-40s on a busy LAPI, and we want this handler to
	// return its log payload to the control server right now.
	go h.EmitCrowdSecNow()

	return logBuf.String() + "\nOK — CrowdSec installed and whitelist applied.", nil
}

func (h *ServerHandlers) handleCrowdSecSyncWhitelist(raw json.RawMessage) (string, error) {
	var p CrowdSecInstallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if resolveCSCli() == "" {
		return "", fmt.Errorf("cscli not installed — run crowdsec_install first")
	}
	if err := writeWhitelist(p); err != nil {
		return "", fmt.Errorf("write whitelist: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if out, err := runCmd(ctx, "systemctl", "reload", "crowdsec"); err != nil {
		if out2, err2 := runCmd(ctx, "systemctl", "restart", "crowdsec"); err2 != nil {
			return "", fmt.Errorf("reload+restart crowdsec: %w / %v\n%s\n%s", err, err2, out, out2)
		}
	}
	// Refresh the snapshot — total_decisions / version may have moved
	// since the last 5-min cycle. Same async pattern as the install
	// handler so the caller's WS reply isn't blocked on cscli metrics.
	go h.EmitCrowdSecNow()
	return fmt.Sprintf("whitelist applied: %d ips, %d cidrs", len(p.IPs), len(p.CIDRs)), nil
}

// writeWhitelist renders the YAML whitelist parser and writes it under
// /etc/crowdsec/parsers/s02-enrich/. We hand-write YAML rather than
// pull in a gopkg.in/yaml.v3 dep because the schema is tiny and
// constraining the format makes diffing on disk easier for operators.
func writeWhitelist(p CrowdSecInstallParams) error {
	dir := filepath.Dir(crowdSecWhitelistFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	var b strings.Builder
	b.WriteString("# AUTO-GENERATED by wirewarp-agent — do not edit by hand.\n")
	b.WriteString("# Sourced from the control server's view of every known IP /\n")
	b.WriteString("# subnet in the WireWarp environment. Drop your own entries in\n")
	b.WriteString("# a SEPARATE parser file (e.g. 99-local-whitelist.yaml) — this\n")
	b.WriteString("# one is overwritten on every sync.\n")
	b.WriteString("name: wirewarp/auto-whitelist\n")
	b.WriteString("description: \"WireWarp-managed allowlist of known infrastructure IPs\"\n")
	b.WriteString("whitelist:\n")
	b.WriteString("  reason: \"WireWarp-managed allowlist; do not edit by hand\"\n")
	if len(p.IPs) > 0 {
		b.WriteString("  ip:\n")
		for _, ip := range p.IPs {
			fmt.Fprintf(&b, "    - %q\n", ip)
		}
	}
	if len(p.CIDRs) > 0 {
		b.WriteString("  cidr:\n")
		for _, c := range p.CIDRs {
			fmt.Fprintf(&b, "    - %q\n", c)
		}
	}
	if len(p.IPs) == 0 && len(p.CIDRs) == 0 {
		// CrowdSec wants at least an empty list rather than the bare key.
		b.WriteString("  ip: []\n")
	}
	return os.WriteFile(crowdSecWhitelistFile, []byte(b.String()), 0644)
}

// assertDebianFamily refuses to run the apt install path on non-Debian
// hosts. Other distros are supported by users running `apt`-equivalent
// install themselves and then triggering only the sync command.
func assertDebianFamily() error {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("read /etc/os-release: %w", err)
	}
	s := string(data)
	if strings.Contains(s, "ID_LIKE=debian") || strings.Contains(s, "ID=debian") || strings.Contains(s, "ID=ubuntu") {
		return nil
	}
	return fmt.Errorf("auto-install requires a Debian-family host; got:\n%s", s)
}

// runShell + runCmd both invoke their target via `systemd-run` so the
// subprocess escapes the agent's restricted capability set. The agent
// systemd unit pins CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
// (so wg / iptables work without unconfined root); apt-get, cscli, and
// the packagecloud installer all need additional caps (DAC_OVERRIDE
// for /var/lib/apt + /etc writes, SETUID so apt can drop priv to
// `_apt`). Launching via systemd-run as a fresh transient unit with
// CapabilityBoundingSet=~ resets the bounding set to the manager's
// default — i.e. full root.
//
// --pipe + --wait stream output back to us and block until the
// transient unit exits. --collect garbage-collects the unit after.
func runShell(ctx context.Context, script string) ([]byte, error) {
	args := []string{
		"--pipe", "--wait", "--quiet", "--collect",
		"--property=CapabilityBoundingSet=~",
		"--property=AmbientCapabilities=~",
		"--", "sh", "-c", script,
	}
	return exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput()
}

func runCmd(ctx context.Context, name string, cmdArgs ...string) ([]byte, error) {
	args := []string{
		"--pipe", "--wait", "--quiet", "--collect",
		"--property=CapabilityBoundingSet=~",
		"--property=AmbientCapabilities=~",
		"--", name,
	}
	args = append(args, cmdArgs...)
	return exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput()
}

// tail returns the last n lines of output (trimmed). Keeps the command
// response payload bounded — apt-get install on a fresh box can spew
// several hundred lines, which is fine in journalctl but a waste on the
// WS channel.
func tail(b []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n") + "\n"
	}
	return strings.Join(lines[len(lines)-n:], "\n") + "\n"
}
