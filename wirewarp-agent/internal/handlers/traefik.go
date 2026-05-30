package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// traefik install / config paths
const (
	traefikBinary           = "/usr/local/bin/traefik"
	traefikStaticCfg        = "/etc/traefik/traefik.yml"
	traefikDynamicDir       = "/etc/traefik/dynamic"
	traefikDynamicCfg       = "/etc/traefik/dynamic/wirewarp.yml"
	traefikEnvPath          = "/etc/traefik/traefik.env"
	traefikCFTokenPath      = "/etc/traefik/secrets/cloudflare_dns_api_token"
	traefikEventsCursorPath = "/etc/wirewarp/traefik-events.cursor"
	traefikUnitPath         = "/etc/systemd/system/traefik.service"
	traefikUnitName         = "traefik.service"
	traefikDownloadURL      = "https://github.com/traefik/traefik/releases/download/v3.3.4/traefik_v3.3.4_linux_amd64.tar.gz"
)

const traefikInstallTimeout = 5 * time.Minute
const traefikPollInterval = 5 * time.Minute
const traefikCmdTimeout = 15 * time.Second

var traefikAccessLogRE = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) HTTP/[^"]+" (\d{3}) \S+ "[^"]*" "[^"]*" \S+ "([^"]*)" "([^"]*)"`)

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
EnvironmentFile=-/etc/traefik/traefik.env
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
	staticChanged, err := writeYAMLChanged(traefikStaticCfg, p.StaticConfig)
	if err != nil {
		return logBuf.String(), fmt.Errorf("write static config: %w", err)
	}

	// 4. Ensure the dynamic file-provider dir exists.
	if err := os.MkdirAll(traefikDynamicDir, 0755); err != nil {
		return logBuf.String(), fmt.Errorf("mkdir %s: %w", traefikDynamicDir, err)
	}

	// 5. Write the systemd unit.
	logf("==> install systemd unit %s", traefikUnitPath)
	unitChanged := false
	current, _ := os.ReadFile(traefikUnitPath)
	if string(current) != traefikUnitTemplate {
		if err := os.MkdirAll("/etc/systemd/system", 0755); err != nil {
			return logBuf.String(), fmt.Errorf("mkdir /etc/systemd/system: %w", err)
		}
		if err := os.WriteFile(traefikUnitPath, []byte(traefikUnitTemplate), 0644); err != nil {
			return logBuf.String(), fmt.Errorf("write %s: %w", traefikUnitPath, err)
		}
		unitChanged = true
		if out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput(); err != nil {
			return logBuf.String(), fmt.Errorf("daemon-reload: %w — %s", err, tail(out, 4))
		}
	}

	// 6. Enable + start (idempotent).
	logf("==> systemctl enable --now traefik")
	if out, err := runCmd(ctx, "systemctl", "enable", "--now", traefikUnitName); err != nil {
		return logBuf.String(), fmt.Errorf("enable traefik: %w\n%s", err, tail(out, 4))
	}
	if staticChanged || unitChanged {
		logf("==> restart traefik after static/unit change")
		if out, err := runCmd(ctx, "systemctl", "restart", traefikUnitName); err != nil {
			return logBuf.String(), fmt.Errorf("restart traefik: %w\n%s", err, tail(out, 4))
		}
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
	changed, err := applyTraefikDynamicConfig(p.DynamicConfig)
	if err != nil {
		return "", err
	}
	if !changed {
		go h.EmitTraefikNow()
		return fmt.Sprintf("dynamic config already current at %s; traefik reload skipped", traefikDynamicCfg), nil
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
func applyTraefikDynamicConfig(cfg map[string]any) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(traefikDynamicCfg), 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(traefikDynamicCfg), err)
	}
	return writeYAMLChanged(traefikDynamicCfg, cfg)
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

func restartTraefik() {
	ctx, cancel := context.WithTimeout(context.Background(), traefikCmdTimeout)
	defer cancel()

	sysctl := resolveBin("systemctl", "/usr/bin/systemctl", "/bin/systemctl")
	if out, err := exec.CommandContext(ctx, sysctl, "restart", traefikUnitName).CombinedOutput(); err != nil {
		log.Printf("[traefik] restart failed: %v — %s", err, tail(out, 2))
	}
}

type TraefikACMEParams struct {
	CloudflareDNSToken string `json:"cloudflare_dns_api_token"`
}

func applyTraefikACMESecrets(p TraefikACMEParams, envPath string, tokenPath string) (bool, error) {
	if strings.TrimSpace(p.CloudflareDNSToken) == "" {
		changed := false
		for _, path := range []string{envPath, tokenPath} {
			if err := os.Remove(path); err == nil {
				changed = true
			} else if !os.IsNotExist(err) {
				return changed, fmt.Errorf("remove %s: %w", path, err)
			}
		}
		return changed, nil
	}

	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(tokenPath), err)
	}
	tokenChanged, err := writeBytesChanged(tokenPath, []byte(p.CloudflareDNSToken), 0600)
	if err != nil {
		return tokenChanged, fmt.Errorf("write ACME Cloudflare token: %w", err)
	}
	env := []byte("CF_DNS_API_TOKEN_FILE=" + tokenPath + "\n")
	envChanged, err := writeBytesChanged(envPath, env, 0644)
	if err != nil {
		return tokenChanged || envChanged, fmt.Errorf("write Traefik env file: %w", err)
	}
	return tokenChanged || envChanged, nil
}

// writeYAML marshals v to YAML and writes it to path with a "do not edit"
// header. Uses gopkg.in/yaml.v3 which is already in go.mod.
func writeYAML(path string, v any) error {
	_, err := writeYAMLChanged(path, v)
	return err
}

func writeYAMLChanged(path string, v any) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return false, fmt.Errorf("marshal yaml: %w", err)
	}
	header := "# AUTO-GENERATED by wirewarp-agent — do not edit by hand.\n"
	next := append([]byte(header), b...)
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, next) {
		return false, nil
	}
	return true, writeFileAtomic(path, next, 0644)
}

func writeBytesChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm() == perm {
			return false, nil
		}
	}
	return true, writeFileAtomic(path, data, perm)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmpDir := atomicTempDir(path)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", tmpDir, err)
	}
	tmp, err := os.CreateTemp(tmpDir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	cleanup = false
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func atomicTempDir(path string) string {
	dir := filepath.Dir(path)
	parent := filepath.Dir(dir)
	if parent == dir || parent == "." {
		return dir
	}
	return parent
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

	// Enable every AppSec config/rule the generated acquisition references.
	// Collections alone do not consistently enable appsec-default/crs on
	// existing hosts, so keep the explicit cscli commands here.
	for _, args := range appSecBootstrapCommands() {
		logf("==> cscli %s", strings.Join(args, " "))
		if out, err := runCSCli(ctx, bin, args...); err != nil {
			if !cscliAlreadySatisfied(err.Error() + "\n" + out) {
				logf("WARN: appsec bootstrap: %v\n%s", err, out)
			}
		} else {
			logBuf.WriteString(tail([]byte(out), 4))
		}
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

func appSecBootstrapCommands() [][]string {
	return [][]string{
		{"collections", "install", "crowdsecurity/appsec-virtual-patching"},
		{"collections", "install", "crowdsecurity/appsec-generic-rules"},
		{"collections", "install", "crowdsecurity/appsec-crs"},
		{"appsec-configs", "install", "crowdsecurity/appsec-default"},
		{"appsec-configs", "install", "crowdsecurity/crs"},
		{"appsec-rules", "install", "crowdsecurity/crs"},
	}
}

func cscliAlreadySatisfied(s string) bool {
	return strings.Contains(s, "already install") ||
		strings.Contains(s, "Nothing to install or remove") ||
		strings.Contains(s, "already enabled")
}

func appSecBootstrapFilesPresent() bool {
	for _, path := range []string{
		"/etc/crowdsec/appsec-configs/appsec-default.yaml",
		"/etc/crowdsec/appsec-configs/crs.yaml",
		"/etc/crowdsec/appsec-rules/crs.yaml",
		"/etc/crowdsec/appsec-configs/virtual-patching.yaml",
		"/etc/crowdsec/appsec-configs/generic-rules.yaml",
		"/etc/crowdsec/appsec-rules/experimental-no-user-agent.yaml",
	} {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
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
	if h.tryEmitTraefik(payload) {
		h.emitTraefikAccessEvents(ctx)
		return
	}
	if retry {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			if h.tryEmitTraefik(payload) {
				h.emitTraefikAccessEvents(ctx)
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
			"installed": false,
			"running":   false,
			"phase":     "pending",
			"timestamp": now,
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
			"phase":        "degraded",
			"timestamp":    now,
		}
		if statusMsg != "" {
			result["error"] = statusMsg
			result["last_error"] = statusMsg
		}
		return result
	}

	routesCount := countTraefikRoutes()

	return map[string]any{
		"installed":    true,
		"running":      true,
		"version":      version,
		"routes_count": routesCount,
		"phase":        "healthy",
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

// --- security_events emitters ---

func (h *ServerHandlers) emitTraefikAccessEvents(ctx context.Context) {
	raw, err := readTraefikAccessJournal(ctx)
	if err != nil {
		log.Printf("[security-events] traefik access log: %v", err)
		return
	}
	events, cursor := parseTraefikAccessSecurityEvents(raw)
	emitOK := false
	if len(events) == 0 {
		emitOK = true
	} else {
		p := h.emit.Load()
		if p != nil {
			if fn := *p; fn != nil {
				if err := fn("security_events", map[string]any{"events": events}); err != nil {
					log.Printf("[security-events] emit traefik access events: %v", err)
				} else {
					emitOK = true
				}
			}
		}
	}
	if cursor != "" && shouldAdvanceTraefikEventsCursor(len(events), emitOK) {
		if err := writeTraefikEventsCursor(cursor); err != nil {
			log.Printf("[security-events] write traefik cursor: %v", err)
		}
	}
	if len(events) == 0 {
		return
	}
}

func shouldAdvanceTraefikEventsCursor(eventCount int, emitOK bool) bool {
	return eventCount == 0 || emitOK
}

func readTraefikAccessJournal(ctx context.Context) (string, error) {
	args := []string{"-u", traefikUnitName, "--no-pager", "-o", "cat", "--show-cursor"}
	if cursor := readTraefikEventsCursor(); cursor != "" {
		args = append(args, "--after-cursor", cursor)
	} else {
		args = append(args, "--since", "5 minutes ago")
	}
	out, err := exec.CommandContext(ctx, "journalctl", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("journalctl %s: %w — %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

func readTraefikEventsCursor() string {
	data, err := os.ReadFile(traefikEventsCursorPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeTraefikEventsCursor(cursor string) error {
	if err := os.MkdirAll(filepath.Dir(traefikEventsCursorPath), 0700); err != nil {
		return err
	}
	return os.WriteFile(traefikEventsCursorPath, []byte(cursor+"\n"), 0600)
}

func parseTraefikAccessSecurityEvents(raw string) ([]map[string]any, string) {
	var cursor string
	events := make([]map[string]any, 0)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-- cursor:") {
			cursor = strings.TrimSpace(strings.TrimPrefix(line, "-- cursor:"))
			continue
		}
		evt, ok := parseTraefikAccessSecurityEvent(line)
		if ok {
			events = append(events, evt)
		}
	}
	return events, cursor
}

func parseTraefikAccessSecurityEvent(line string) (map[string]any, bool) {
	m := traefikAccessLogRE.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	status, err := strconv.Atoi(m[5])
	if err != nil || status != 429 {
		return nil, false
	}
	occurred, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		occurred = time.Now().UTC()
	}
	method := m[3]
	path := m[4]
	router := m[6]
	service := m[7]
	return map[string]any{
		"source":      "traefik",
		"kind":        "rate_limit",
		"ip":          m[1],
		"value":       router,
		"action":      "rate_limit",
		"occurred_at": occurred.UTC().Format(time.RFC3339),
		"raw": map[string]any{
			"method":  method,
			"path":    path,
			"status":  status,
			"router":  router,
			"service": service,
		},
	}, true
}

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
		Type     string `json:"type"`     // "ban", "captcha", ...
		Scenario string `json:"reason"`   // maps to kind
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
