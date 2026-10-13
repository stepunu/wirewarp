package handlers

import (
	"context"
	"fmt"
	"github.com/wirewarp/agent/internal/firewall"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// routingUnitPath is where the systemd unit file is installed. Standard
// location for distro-supplied user units. We don't write to /run because
// the unit must survive reboots.
const routingUnitPath = "/etc/systemd/system/wirewarp-routing.service"

var routingUnitFile = routingUnitPath

// routingUnitName is the unit identifier `systemctl enable` accepts.
const routingUnitName = "wirewarp-routing.service"

// routingUnitTemplate is the oneshot service that re-installs runtime
// routing state on boot. Key decisions:
//
//   - `DefaultDependencies=no` + `Before=network-pre.target` — runs
//     before any networking comes up so workloads that race the agent
//     for first packets still find the iptables rules in place.
//   - `Type=oneshot` + `RemainAfterExit=yes` — the binary exits after
//     applying state; systemd treats the unit as still "active" so the
//     normal Wants/After chain doesn't trigger it twice.
//   - `ConditionPathExists` — skips silently when the agent has never
//     been bootstrapped on this host (no config = no work).
//
// Note on routes that depend on wg0 being up: those can't be installed
// pre-network because wg0 doesn't exist yet. The runtime healer (which
// starts after wg-quick) handles those. This unit is for the static
// pieces — iptables rules and ip rule fwmark — that don't need any
// interface to exist.
const routingUnitTemplate = `[Unit]
Description=WireWarp routing restore (oneshot, pre-network)
DefaultDependencies=no
After=local-fs.target ufw.service netfilter-persistent.service
Before=network-pre.target sysinit.target
Wants=network-pre.target
ConditionPathExists=%s

[Service]
Type=oneshot
ExecStart=%s --restore-routing --config %s
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

// EnsureRoutingUnit writes the wirewarp-routing.service unit file and
// `systemctl enable`s it. Idempotent: writes only when the content
// changes, daemon-reload + enable are no-ops on second invocation.
//
// Called by wg_init (server) and wg_attach (client) handlers after a
// successful first-time setup. Errors are returned but the agent treats
// them as soft — the runtime healer + agent-startup ApplyGatewayRouting
// will keep things working even if the unit can't be installed.
func EnsureRoutingUnit(binaryPath, configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return EnsureRoutingUnitContext(ctx, binaryPath, configPath)
}

func EnsureRoutingUnitContext(ctx context.Context, binaryPath, configPath string) error {
	if binaryPath == "" || configPath == "" {
		return fmt.Errorf("binaryPath and configPath are both required")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl is required for persistent WireWarp routing")
	}

	if strings.ContainsAny(binaryPath+configPath, "\r\n\x00") {
		return fmt.Errorf("invalid routing restore unit path")
	}
	quote := func(value string) string {
		return `"` + strings.NewReplacer("\\", "\\\\", `"`, `\"`, "%", "%%", "$", "$$").Replace(value) + `"`
	}
	want := fmt.Sprintf(routingUnitTemplate, quote(configPath), quote(binaryPath), quote(configPath))
	if fi, err := os.Lstat(routingUnitFile); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("routing restore unit file is unsafe")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	current, err := os.ReadFile(routingUnitFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(current) > 0 && !strings.HasPrefix(string(current), "[Unit]\nDescription=WireWarp routing restore (oneshot, pre-network)\n") {
		return fmt.Errorf("routing restore unit is owned by another service")
	}
	if string(current) != want {
		if err := os.MkdirAll(filepath.Dir(routingUnitFile), 0755); err != nil {
			return fmt.Errorf("mkdir /etc/systemd/system: %w", err)
		}
		if err := writeRoutingUnit(want); err != nil {
			return fmt.Errorf("write %s: %w", routingUnitPath, err)
		}
		log.Printf("[systemd-unit] wrote %s", routingUnitPath)

		if out, err := firewall.Run(ctx, "", "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %w — %s", err, strings.TrimSpace(string(out)))
		}
	}

	// Always run enable — it's cheap and recovers from any manual
	// `systemctl disable`. We deliberately do NOT run `start`: the unit
	// is meant to execute at boot, not now (the agent already has the
	// state installed).
	if out, err := firewall.Run(ctx, "", "systemctl", "enable", routingUnitName); err != nil {
		return fmt.Errorf("systemctl enable %s: %w — %s", routingUnitName, err, strings.TrimSpace(string(out)))
	}
	if out, err := firewall.Run(ctx, "", "systemctl", "is-enabled", routingUnitName); err != nil || strings.TrimSpace(string(out)) != "enabled" {
		return fmt.Errorf("routing restore unit is not durably enabled")
	}
	return nil
}

func writeRoutingUnit(content string) error {
	f, err := os.CreateTemp(filepath.Dir(routingUnitFile), ".wirewarp-routing-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err == nil {
		_, err = f.WriteString(content)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), routingUnitFile); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(routingUnitFile))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
