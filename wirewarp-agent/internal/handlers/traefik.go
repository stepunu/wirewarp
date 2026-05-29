package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// traefik install / config paths
const (
	traefikBinary      = "/usr/local/bin/traefik"
	traefikStaticCfg   = "/etc/traefik/traefik.yml"
	traefikDynamicDir  = "/etc/traefik/dynamic"
	traefikDynamicCfg  = "/etc/traefik/dynamic/wirewarp.yml"
	traefikUnitPath    = "/etc/systemd/system/traefik.service"
	traefikUnitName    = "traefik.service"
	traefikDownloadURL = "https://github.com/traefik/traefik/releases/download/v3.3.4/traefik_v3.3.4_linux_amd64.tar.gz"
)

const traefikInstallTimeout = 5 * time.Minute
const traefikPollInterval = 5 * time.Minute
const traefikCmdTimeout = 15 * time.Second

// traefikUnitTemplate is the systemd unit for Traefik. Like the routing
// unit, it runs as root with the static+dynamic config dirs the agent
// writes under /etc/traefik/. setcap CAP_NET_BIND_SERVICE is applied
// separately so the binary can bind :80/:443 without being root.
const traefikUnitTemplate = `[Unit]
Description=Traefik edge proxy (WireWarp-managed)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/traefik --configFile=/etc/traefik/traefik.yml
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

// --- install handler ---

// TraefikInstallParams carries the static config dict and optional metadata.
type TraefikInstallParams struct {
	StaticConfig map[string]any `json:"static_config"`
	LEEmail      string         `json:"le_email"`
	Version      string         `json:"version"` // reserved; ignored — binary is pinned
}

func (h *ServerHandlers) handleTraefikInstall(raw json.RawMessage) (string, error) {
	var p TraefikInstallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), traefikInstallTimeout)
	defer cancel()

	var logBuf strings.Builder
	logf := func(format string, args ...any) {
		fmt.Fprintf(&logBuf, format+"\n", args...)
	}

	// 1. Download + install binary (only when not already present).
	if _, err := os.Stat(traefikBinary); err != nil {
		logf("==> download Traefik binary")
		if out, err := runCmd(ctx,
			"bash", "-c",
			fmt.Sprintf(
				"set -e; "+
					"cd /tmp && "+
					"curl -fsSL %s -o traefik.tar.gz && "+
					"tar -xzf traefik.tar.gz traefik && "+
					"mv traefik %s && "+
					"rm -f traefik.tar.gz",
				traefikDownloadURL, traefikBinary,
			),
		); err != nil {
			return logBuf.String(), fmt.Errorf("download traefik: %w\n%s", err, tail(out, 8))
		}
		logBuf.WriteString("binary installed at " + traefikBinary + "\n")
	} else {
		logf("traefik binary already present — skipping download")
	}

	// 2. setcap so Traefik can bind :80/:443 without full root.
	logf("==> setcap cap_net_bind_service+ep %s", traefikBinary)
	if out, err := runCmd(ctx, "setcap", "cap_net_bind_service+ep", traefikBinary); err != nil {
		return logBuf.String(), fmt.Errorf("setcap: %w\n%s", err, tail(out, 4))
	}

	// 3. Write the static config dict the server built.
	logf("==> write static config %s", traefikStaticCfg)
	if err := writeYAML(traefikStaticCfg, p.StaticConfig); err != nil {
		return logBuf.String(), fmt.Errorf("write static config: %w", err)
	}

	// 4. Ensure the dynamic file-provider dir exists.
	if err := os.MkdirAll(traefikDynamicDir, 0755); err != nil {
		return logBuf.String(), fmt.Errorf("mkdir %s: %w", traefikDynamicDir, err)
	}

	// 5. Write the systemd unit.
	logf("==> install systemd unit %s", traefikUnitPath)
	current, _ := os.ReadFile(traefikUnitPath)
	if string(current) != traefikUnitTemplate {
		if err := os.MkdirAll("/etc/systemd/system", 0755); err != nil {
			return logBuf.String(), fmt.Errorf("mkdir /etc/systemd/system: %w", err)
		}
		if err := os.WriteFile(traefikUnitPath, []byte(traefikUnitTemplate), 0644); err != nil {
			return logBuf.String(), fmt.Errorf("write %s: %w", traefikUnitPath, err)
		}
		if out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return logBuf.String(), fmt.Errorf("daemon-reload: %w — %s", err, tail(out, 4))
		}
	}

	// 6. Enable + start (idempotent).
	logf("==> systemctl enable --now traefik")
	if out, err := runCmd(ctx, "systemctl", "enable", "--now", traefikUnitName); err != nil {
		return logBuf.String(), fmt.Errorf("enable traefik: %w\n%s", err, tail(out, 4))
	}

	// 7. Surface service state immediately in the response.
	if active, statusMsg := traefikServiceActive(); active {
		logf("==> traefik service is active")
	} else {
		logf("WARN: traefik service not active after install: %s", statusMsg)
	}

	// Push a fresh traefik_status frame so the dashboard card flips
	// without waiting for the next 5-min cycle.
	go h.EmitTraefikNow()

	return logBuf.String() + "\nOK — Traefik installed.", nil
}

// --- sync config handler ---

// TraefikSyncConfigParams carries the full dynamic config dict the server assembled.
type TraefikSyncConfigParams struct {
	DynamicConfig map[string]any `json:"dynamic_config"`
}

func (h *ServerHandlers) handleTraefikSyncConfig(raw json.RawMessage) (string, error) {
	var p TraefikSyncConfigParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if err := applyTraefikDynamicConfig(p.DynamicConfig); err != nil {
		return "", err
	}
	// A SIGHUP reloads Traefik's file-provider without losing existing
	// connections; if that fails, fall back to a full restart.
	reloadTraefik()
	go h.EmitTraefikNow()
	return fmt.Sprintf("dynamic config written to %s and traefik reloaded", traefikDynamicCfg), nil
}

// applyTraefikDynamicConfig writes the config dict verbatim as YAML to
// /etc/traefik/dynamic/wirewarp.yml. The agent is a dumb writer — the
// server owns the schema (mirrors writeWhitelist's pattern).
func applyTraefikDynamicConfig(cfg map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(traefikDynamicCfg), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(traefikDynamicCfg), err)
	}
	return writeYAML(traefikDynamicCfg, cfg)
}

// reloadTraefik sends SIGHUP to the traefik process, falling back to
// `systemctl reload` then `systemctl restart`. Soft errors are logged
// rather than returned — a failed reload just means the old config stays
// live, which is better than bubbling a non-fatal error to the caller.
func reloadTraefik() {
	ctx, cancel := context.WithTimeout(context.Background(), traefikCmdTimeout)
	defer cancel()

	sysctl := resolveBin("systemctl", "/usr/bin/systemctl", "/bin/systemctl")

	// Try reload (SIGHUP) first — preserves open connections.
	if out, err := exec.CommandContext(ctx, sysctl, "reload", traefikUnitName).CombinedOutput(); err != nil {
		log.Printf("[traefik] reload failed (%v: %s) — trying restart", err, tail(out, 2))
		if out2, err2 := exec.CommandContext(ctx, sysctl, "restart", traefikUnitName).CombinedOutput(); err2 != nil {
			log.Printf("[traefik] restart failed: %v — %s", err2, tail(out2, 2))
		}
	}
}

// writeYAML marshals v to YAML and writes it to path with a "do not edit"
// header. Uses gopkg.in/yaml.v3 which is already in go.mod.
func writeYAML(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	header := "# AUTO-GENERATED by wirewarp-agent — do not edit by hand.\n"
	return os.WriteFile(path, append([]byte(header), b...), 0644)
}

// --- crowdsec_appsec_enable handler ---

// CrowdSecAppSecParams carries the bouncer API key the server generated.
type CrowdSecAppSecParams struct {
	BouncerKey string `json:"bouncer_key"`
}

func (h *ServerHandlers) handleCrowdSecAppSecEnable(raw json.RawMessage) (string, error) {
	var p CrowdSecAppSecParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	if p.BouncerKey == "" {
		return "", fmt.Errorf("bouncer_key is required")
	}

	bin := resolveCSCli()
	if bin == "" {
		return "", fmt.Errorf("cscli not installed — run crowdsec_install first")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var logBuf strings.Builder
	logf := func(format string, args ...any) {
		fmt.Fprintf(&logBuf, format+"\n", args...)
	}

	// Register the bouncer key idempotently. cscli exits non-zero if the
	// name already exists; we treat that as success and move on.
	logf("==> cscli bouncers add wirewarp-traefik")
	if out, err := runCSCli(ctx, bin, "bouncers", "add", "wirewarp-traefik", "--key", p.BouncerKey); err != nil {
		if !strings.Contains(err.Error(), "already exist") {
			return logBuf.String(), fmt.Errorf("cscli bouncers add: %w\n%s", err, out)
		}
		logf("(bouncer already registered — key not updated)")
	} else {
		logBuf.WriteString(tail([]byte(out), 4))
	}

	// Install the AppSec virtual-patching collection.
	logf("==> cscli appsec-configs install crowdsecurity/crs")
	if out, err := runCSCli(ctx, bin, "appsec-configs", "install", "crowdsecurity/crs"); err != nil {
		// Already installed is fine.
		if !strings.Contains(err.Error(), "already install") {
			logf("WARN: appsec-config install: %v\n%s", err, out)
		}
	} else {
		logBuf.WriteString(tail([]byte(out), 4))
	}

	logf("==> cscli appsec-rules install crowdsecurity/appsec-virtual-patching")
	if out, err := runCSCli(ctx, bin, "appsec-rules", "install", "crowdsecurity/appsec-virtual-patching"); err != nil {
		if !strings.Contains(err.Error(), "already install") {
			logf("WARN: appsec-rules install: %v\n%s", err, out)
		}
	} else {
		logBuf.WriteString(tail([]byte(out), 4))
	}

	logf("==> systemctl reload crowdsec")
	if out, err := runCmd(ctx, "systemctl", "reload", "crowdsec"); err != nil {
		if out2, err2 := runCmd(ctx, "systemctl", "restart", "crowdsec"); err2 != nil {
			logf("WARN: reload+restart crowdsec: %v / %v\n%s\n%s", err, err2, tail(out, 4), tail(out2, 4))
		}
	}

	go h.EmitCrowdSecNow()
	return logBuf.String() + "\nOK — CrowdSec AppSec enabled.", nil
}

// --- traefik_status poller ---

// StartTraefikPoller fires off the per-tunnel-server Traefik snapshot loop.
// No-op on hosts without the Traefik binary — the first poll detects
// absence and the result frame carries installed=false.
func (h *ServerHandlers) StartTraefikPoller(ctx context.Context) {
	go h.traefikPollLoop(ctx)
}

// applyDiskTraefikConfig re-applies the last dynamic config from disk on
// startup so Traefik's file-provider is consistent with the agent's
// last-known state before the control server issues a fresh sync. Called
// from server-mode startup — mirrors offline-resilience for WireGuard.
func applyDiskTraefikConfig() {
	if _, err := os.Stat(traefikDynamicCfg); err != nil {
		return // no saved config yet — nothing to do
	}
	// Config already exists on disk; signal Traefik to reload it (it may
	// have been updated while Traefik was stopped). If Traefik isn't running
	// yet this is a no-op, which is fine — once it starts it reads the file.
	reloadTraefik()
	log.Printf("[traefik] re-applied dynamic config from disk: %s", traefikDynamicCfg)
}

func (h *ServerHandlers) traefikPollLoop(ctx context.Context) {
	// Apply disk config before the first WS handshake completes — ensures
	// Traefik is serving the right routes even if the agent restarts while
	// the control server is temporarily unreachable.
	applyDiskTraefikConfig()

	h.pollAndEmitTraefik(ctx, true)
	t := time.NewTicker(traefikPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.pollAndEmitTraefik(ctx, false)
		}
	}
}

func (h *ServerHandlers) pollAndEmitTraefik(ctx context.Context, retry bool) {
	payload := collectTraefik()
	if !h.tryEmitTraefik(payload) && retry {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			if h.tryEmitTraefik(payload) {
				return
			}
		}
	}
}

func (h *ServerHandlers) tryEmitTraefik(payload map[string]any) bool {
	p := h.emit.Load()
	if p == nil {
		return false
	}
	fn := *p
	if fn == nil {
		return false
	}
	return fn("traefik_status", payload) == nil
}

// EmitTraefikNow triggers an out-of-band Traefik snapshot + emit.
// Used by install / sync handlers so the dashboard reflects the new
// state immediately instead of waiting for the next 5-min cycle.
func (h *ServerHandlers) EmitTraefikNow() {
	ctx, cancel := context.WithTimeout(context.Background(), traefikCmdTimeout)
	defer cancel()
	h.pollAndEmitTraefik(ctx, true)
}

// collectTraefik checks whether the traefik binary + service are present and
// assembles the traefik_status payload that is sent to the control server.
func collectTraefik() map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)

	if _, err := os.Stat(traefikBinary); err != nil {
		return map[string]any{
			"installed":    false,
			"running":      false,
			"timestamp":    now,
		}
	}

	// Detect version from the binary itself (cheap: traefik version exits
	// quickly without a full daemon startup).
	version := resolveTraefikVersion()

	active, statusMsg := traefikServiceActive()
	if !active {
		result := map[string]any{
			"installed":    true,
			"running":      false,
			"version":      version,
			"routes_count": 0,
			"timestamp":    now,
		}
		if statusMsg != "" {
			result["error"] = statusMsg
		}
		return result
	}

	routesCount := countTraefikRoutes()

	return map[string]any{
		"installed":    true,
		"running":      true,
		"version":      version,
		"routes_count": routesCount,
		"timestamp":    now,
	}
}

// traefikServiceActive mirrors crowdSecServiceActive for the traefik unit.
func traefikServiceActive() (bool, string) {
	sysctl := resolveBin("systemctl", "/usr/bin/systemctl", "/bin/systemctl")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, sysctl, "is-active", traefikUnitName)
	c.Env = csCmdEnv()
	out, _ := c.CombinedOutput()
	state := strings.TrimSpace(string(out))
	if state == "active" {
		return true, ""
	}

	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	sc := exec.CommandContext(sctx, sysctl, "status", "--no-pager", "-n", "12", traefikUnitName)
	sc.Env = csCmdEnv()
	status, _ := sc.CombinedOutput()

	msg := "traefik service " + state
	if state == "" {
		msg = "traefik service state unknown"
	}
	if t := strings.TrimSpace(tail(status, 12)); t != "" {
		msg += ":\n" + t
	}
	return false, msg
}

// resolveTraefikVersion runs `traefik version` and extracts the version string.
func resolveTraefikVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, traefikBinary, "version")
	cmd.Env = csCmdEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	// Traefik version output:
	//   Version:      3.3.4
	//   Codename:     ...
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "version:") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// countTraefikRoutes counts the number of HTTP routers defined in the
// wirewarp dynamic config file. This is a best-effort count — we just
// count top-level keys under `http.routers` in the YAML.
func countTraefikRoutes() int {
	data, err := os.ReadFile(traefikDynamicCfg)
	if err != nil {
		return 0
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return 0
	}
	http, ok := root["http"].(map[string]any)
	if !ok {
		return 0
	}
	routers, ok := http["routers"].(map[string]any)
	if !ok {
		return 0
	}
	return len(routers)
}

// --- security_events emitter (crowdsec decisions) ---

// emitSecurityEvents reads current CrowdSec decisions and emits them as a
// `security_events` frame. Called opportunistically after crowdsec_install /
// crowdsec_appsec_enable so Events page data is fresh.
func (h *ServerHandlers) emitSecurityEvents(ctx context.Context) {
	bin := resolveCSCli()
	if bin == "" {
		return
	}
	raw, err := runCSCli(ctx, bin, "decisions", "list", "-o", "json")
	if err != nil {
		log.Printf("[security-events] decisions list: %v", err)
		return
	}

	events := decisionsToSecurityEvents(raw)
	if len(events) == 0 {
		return
	}

	p := h.emit.Load()
	if p == nil {
		return
	}
	fn := *p
	if fn == nil {
		return
	}
	_ = fn("security_events", map[string]any{
		"events": events,
	})
}

// decisionsToSecurityEvents converts `cscli decisions list -o json` output
// into a slice of security event maps that match the contract:
//
//	{source, kind, ip, value, action, occurred_at, raw}
func decisionsToSecurityEvents(raw string) []map[string]any {
	type decision struct {
		ID       int    `json:"id"`
		Value    string `json:"value"`
		Scope    string `json:"scope"`
		Type     string `json:"type"`    // "ban", "captcha", ...
		Scenario string `json:"reason"`  // maps to kind
		StartAt  string `json:"start_ip"` // not always present
		Until    string `json:"until"`
	}
	type alertEnvelope struct {
		Decisions []decision `json:"decisions"`
		Source    struct {
			IP string `json:"ip"`
		} `json:"source"`
		Scenario string `json:"scenario"` // top-level scenario name
	}

	var alerts []alertEnvelope
	if err := json.Unmarshal([]byte(raw), &alerts); err != nil {
		return nil
	}

	now := time.Now().UTC().Format(time.RFC3339)
	out := make([]map[string]any, 0)
	for _, a := range alerts {
		for _, d := range a.Decisions {
			if d.Value == "" {
				continue
			}
			kind := d.Scenario
			if kind == "" {
				kind = a.Scenario
			}
			action := d.Type
			if action == "" {
				action = "ban"
			}
			evt := map[string]any{
				"source":      "crowdsec",
				"kind":        kind,
				"ip":          d.Value,
				"value":       d.Value,
				"action":      action,
				"occurred_at": now,
				"raw":         map[string]any{"id": d.ID, "until": d.Until, "scope": d.Scope},
			}
			out = append(out, evt)
		}
	}
	return out
}
