package handlers

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// routingUnitPath is where the systemd unit file is installed. Standard
// location for distro-supplied user units. We don't write to /run because
// the unit must survive reboots.
const routingUnitPath = "/etc/systemd/system/wirewarp-routing.service"

// routingUnitName is the unit identifier `systemctl enable` accepts.
const routingUnitName = "wirewarp-routing.service"

// routingUnitTemplate is the oneshot service that re-installs runtime
// routing state on boot. Key decisions:
//
//   * `DefaultDependencies=no` + `Before=network-pre.target` — runs
//     before any networking comes up so workloads that race the agent
//     for first packets still find the iptables rules in place.
//   * `Type=oneshot` + `RemainAfterExit=yes` — the binary exits after
//     applying state; systemd treats the unit as still "active" so the
//     normal Wants/After chain doesn't trigger it twice.
//   * `ConditionPathExists` — skips silently when the agent has never
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
After=local-fs.target
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
	if binaryPath == "" || configPath == "" {
		return fmt.Errorf("binaryPath and configPath are both required")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		log.Printf("[systemd-unit] systemctl not found — skipping routing-restore unit install")
		return nil
	}

	want := fmt.Sprintf(routingUnitTemplate, configPath, binaryPath, configPath)
	current, _ := os.ReadFile(routingUnitPath)
	if string(current) != want {
		if err := os.MkdirAll("/etc/systemd/system", 0755); err != nil {
			return fmt.Errorf("mkdir /etc/systemd/system: %w", err)
		}
		if err := os.WriteFile(routingUnitPath, []byte(want), 0644); err != nil {
			return fmt.Errorf("write %s: %w", routingUnitPath, err)
		}
		log.Printf("[systemd-unit] wrote %s", routingUnitPath)

		if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %w — %s", err, strings.TrimSpace(string(out)))
		}
	}

	// Always run enable — it's cheap and recovers from any manual
	// `systemctl disable`. We deliberately do NOT run `start`: the unit
	// is meant to execute at boot, not now (the agent already has the
	// state installed).
	if out, err := exec.Command("systemctl", "enable", routingUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable %s: %w — %s", routingUnitName, err, strings.TrimSpace(string(out)))
	}
	return nil
}
