package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// crowdSecPollInterval is how often the server agent re-snapshots the
// local cscli state. The counters move on a minute-scale not a
// second-scale (a single bruteforce decision typically lives for hours),
// so 5 minutes is the right cadence — fast enough that operators see
// the dashboard update within their attention span, slow enough that we
// don't spawn cscli on every heal cycle.
const crowdSecPollInterval = 5 * time.Minute

// crowdSecTopN caps how many entries each "top X" list carries up to
// the control server. Five is what fits comfortably in the UI card; a
// larger number just inflates the WS payload without helping anyone.
const crowdSecTopN = 5

// crowdSecCmdTimeout caps each cscli subprocess so a wedged cscli
// (broken DB, hung backend) can't stall the agent's WS loop. 45s is
// generous because cscli metrics on a busy LAPI can take 20s+ to
// assemble; the loop runs every 5 min so even a worst-case run is a
// small fraction of the cycle.
const crowdSecCmdTimeout = 45 * time.Second

// StartCrowdSecPoller fires off the per-tunnel-server CrowdSec snapshot
// loop. No-op on hosts without cscli — the first poll detects absence
// and the result frame carries running=false; subsequent polls keep
// confirming the same state until cscli appears (or doesn't).
//
// Server-mode agents only. Client-mode agents call this from main.go
// and the goroutine exits when ctx is done.
func (h *ServerHandlers) StartCrowdSecPoller(ctx context.Context) {
	go h.crowdSecPollLoop(ctx)
}

func (h *ServerHandlers) crowdSecPollLoop(ctx context.Context) {
	// Fire once immediately so the UI doesn't wait the full interval
	// before the first card has data. The "immediate" fire actually
	// races the WS connection coming up — Emit returns ErrNotConnected
	// for the first ~1 sec of agent life. Retry on a tight backoff
	// during that window; once we land one frame, settle into the
	// normal 5-min cadence.
	h.pollAndEmitCrowdSec(ctx, true)
	t := time.NewTicker(crowdSecPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.pollAndEmitCrowdSec(ctx, false)
		}
	}
}

// pollAndEmitCrowdSec collects + emits one snapshot. When `retry` is
// true and the emit returns ErrNotConnected, retry every 2s for up to
// 30s — covers the agent-startup race where the WS hasn't authed yet.
// Steady-state polls pass retry=false; a dropped frame just waits 5min.
func (h *ServerHandlers) pollAndEmitCrowdSec(ctx context.Context, retry bool) {
	payload := collectCrowdSec(ctx)
	if !h.tryEmitCrowdSec(payload) && retry {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			if h.tryEmitCrowdSec(payload) {
				return
			}
		}
	}
}

func (h *ServerHandlers) tryEmitCrowdSec(payload map[string]any) bool {
	p := h.emit.Load()
	if p == nil {
		return false
	}
	fn := *p
	if fn == nil {
		return false
	}
	return fn("crowdsec_status", payload) == nil
}

// EmitCrowdSecNow triggers an out-of-band crowdsec snapshot + emit on
// the calling goroutine. Used by the install handler so the dashboard
// flips from "not detected" to "running" the moment install finishes,
// rather than waiting for the next 5-min cycle.
func (h *ServerHandlers) EmitCrowdSecNow() {
	ctx, cancel := context.WithTimeout(context.Background(), crowdSecCmdTimeout)
	defer cancel()
	h.pollAndEmitCrowdSec(ctx, true)
}

// collectCrowdSec resolves cscli, checks the service state, and (when
// up) runs cscli (version, metrics, decisions) to assemble the status
// payload. It reports two distinct facts the dashboard can act on:
//
//   - installed: the cscli binary is present on the host.
//   - running:   the crowdsec systemd service is active.
//
// Splitting them is the fix for the "installed but reported as not
// detected" bug: a host where the apt install succeeded but the service
// failed to start now surfaces installed=true, running=false, and the
// `systemctl status` tail in `error` — instead of looking identical to a
// host with no CrowdSec at all. Detection is also made independent of
// the agent unit's inherited environment: cscli is invoked by absolute
// path with an explicit PATH/HOME (the unit pins a restricted capability
// set and provides no PATH), so a minimal service env can't make a
// working install read as absent.
func collectCrowdSec(parent context.Context) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)
	bin := resolveCSCli()
	if bin == "" {
		return map[string]any{"installed": false, "running": false, "phase": "pending", "timestamp": now}
	}

	// Binary present — is the daemon up? `cscli version` works without
	// the daemon, so the service state (not a cscli exit code) is what
	// "running" means.
	active, statusMsg := crowdSecServiceActive(parent)
	if !active {
		return map[string]any{
			"installed":      true,
			"running":        false,
			"version":        csVersion(parent, bin),
			"error":          statusMsg,
			"last_error":     statusMsg,
			"phase":          "degraded",
			"appsec_enabled": appSecAcquisitionPresent(),
			"timestamp":      now,
		}
	}

	version := csVersion(parent, bin)

	decisions, dErr := runCSCli(parent, bin, "decisions", "list", "-o", "json")
	if dErr != nil {
		return map[string]any{
			"installed":      true,
			"running":        true,
			"version":        version,
			"error":          "decisions list: " + dErr.Error(),
			"last_error":     "decisions list: " + dErr.Error(),
			"phase":          "degraded",
			"appsec_enabled": appSecAcquisitionPresent(),
			"timestamp":      now,
		}
	}
	totalDecisions, topIPs := summariseDecisions(decisions)

	scenarios, mErr := runCSCli(parent, bin, "metrics", "-o", "json")
	var topScenarios []map[string]any
	var metricsErr string
	if mErr != nil {
		metricsErr = "metrics: " + mErr.Error()
	} else {
		topScenarios = summariseScenarios(scenarios)
	}

	return map[string]any{
		"installed":       true,
		"running":         true,
		"version":         version,
		"total_decisions": totalDecisions,
		"top_scenarios":   topScenarios,
		"top_ips":         topIPs,
		"error":           metricsErr, // non-fatal — we still have decisions
		"last_error":      metricsErr,
		"phase":           "healthy",
		"appsec_enabled":  appSecAcquisitionPresent(),
		"timestamp":       now,
	}
}

func appSecAcquisitionPresent() bool {
	if fi, err := os.Stat(appSecAcquisitionFile); err == nil && !fi.IsDir() {
		return true
	}
	return false
}

// resolveCSCli returns the absolute path to cscli, or "" if it isn't
// installed. It falls back to the standard install locations when cscli
// isn't on the inherited PATH — the agent's systemd unit pins a
// restricted environment and may not export a PATH that includes
// /usr/bin, which would otherwise make exec.LookPath miss a perfectly
// installed binary.
func resolveCSCli() string {
	if p, err := exec.LookPath("cscli"); err == nil {
		return p
	}
	for _, c := range []string{"/usr/bin/cscli", "/usr/local/bin/cscli", "/usr/sbin/cscli"} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// resolveBin is resolveCSCli for tools we always expect to exist
// (systemctl): same PATH-independent lookup, but returns the bare name
// as a last resort so exec still yields a useful error.
func resolveBin(name string, candidates ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return name
}

// csCmdEnv builds the environment for cscli/systemctl invocations. The
// agent unit may provide no PATH (and no HOME) because it runs with a
// pinned capability set; cscli resolves helper tools and its own config
// relative to a sane environment, so we guarantee one. We replace rather
// than append PATH/HOME so the child sees a single, well-formed value.
func csCmdEnv() []string {
	const path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	src := os.Environ()
	out := make([]string, 0, len(src)+2)
	for _, e := range src {
		if strings.HasPrefix(e, "PATH=") || strings.HasPrefix(e, "HOME=") {
			continue
		}
		out = append(out, e)
	}
	return append(out, "PATH="+path, "HOME=/root")
}

// csVersion is a best-effort `cscli version` parse. It works without the
// daemon, so we can report a version even for an installed-but-stopped
// service; on any error we just return "".
func csVersion(parent context.Context, bin string) string {
	out, err := runCSCli(parent, bin, "version")
	if err != nil {
		return ""
	}
	return parseVersionLine(out)
}

// crowdSecServiceActive reports whether the crowdsec systemd unit is
// active. When it isn't, it returns a short `systemctl status` tail so
// the dashboard can show *why* (failed unit, broken config) instead of a
// bare "not detected". `is-active` and `status` are reads — no elevated
// capabilities needed — so they run directly (unlike the install path,
// which needs systemd-run to escape the agent's capability bounding set).
func crowdSecServiceActive(parent context.Context) (bool, string) {
	sysctl := resolveBin("systemctl", "/usr/bin/systemctl", "/bin/systemctl")

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, sysctl, "is-active", "crowdsec")
	c.Env = csCmdEnv()
	out, _ := c.CombinedOutput()
	state := strings.TrimSpace(string(out))
	if state == "active" {
		return true, ""
	}

	sctx, scancel := context.WithTimeout(parent, 10*time.Second)
	defer scancel()
	sc := exec.CommandContext(sctx, sysctl, "status", "--no-pager", "-n", "12", "crowdsec")
	sc.Env = csCmdEnv()
	status, _ := sc.CombinedOutput()

	msg := "crowdsec service " + state
	if state == "" {
		msg = "crowdsec service state unknown"
	}
	if t := strings.TrimSpace(tail(status, 12)); t != "" {
		msg += ":\n" + t
	}
	return false, msg
}

// runCSCli executes `<bin> <args>` with a hard timeout and an explicit
// environment, returning combined output. cscli prints errors on stdout
// in JSON mode anyway, so we don't try to separate streams here.
func runCSCli(parent context.Context, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, crowdSecCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = csCmdEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cscli %s: %w — %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// parseVersionLine pulls the first whitespace-separated token after
// "version" from `cscli version` output. The text format isn't
// machine-readable but the version line is stable enough across
// versions that a simple search beats parsing the whole banner.
func parseVersionLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "version:") {
			// "version: v1.6.4-debian-..."
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				return strings.TrimPrefix(parts[1], "v")
			}
		}
	}
	return ""
}

// summariseDecisions parses `cscli decisions list -o json` output and
// returns (total, topIPs). Top is by frequency of the `value` field
// (which is the banned IP for ip-scope decisions).
//
// cscli wraps every decision inside an alert envelope:
//
//	[
//	  {"capacity": ..., "decisions": [{"value": "1.2.3.4", "scope": "Ip", ...}], "events": ...},
//	  ...
//	]
//
// Older / non-default invocations sometimes emit a flat decision array
// or a `{decisions: [...]}` wrapper. Try all three shapes — first match
// wins — so a cscli upgrade that flips the format doesn't break us
// silently.
func summariseDecisions(raw string) (int, []map[string]any) {
	type decision struct {
		Value string `json:"value"`
		Scope string `json:"scope"`
	}
	type alertEnvelope struct {
		Decisions []decision `json:"decisions"`
	}

	var flat []decision

	// Shape A: array of alert envelopes, each with `decisions[]` nested.
	// This is the cscli default since at least 1.5.
	var alerts []alertEnvelope
	if err := json.Unmarshal([]byte(raw), &alerts); err == nil {
		anyNested := false
		for _, a := range alerts {
			if len(a.Decisions) > 0 {
				anyNested = true
				flat = append(flat, a.Decisions...)
			}
		}
		if !anyNested {
			flat = nil
		}
	}

	// Shape B: flat array of decisions (older cscli or `--no-aggregate`).
	if flat == nil {
		var direct []decision
		if err := json.Unmarshal([]byte(raw), &direct); err == nil {
			for _, d := range direct {
				if d.Value != "" {
					flat = direct
					break
				}
			}
		}
	}

	// Shape C: `{decisions: [...]}` top-level wrapper.
	if flat == nil {
		var wrapped struct {
			Decisions []decision `json:"decisions"`
		}
		if err := json.Unmarshal([]byte(raw), &wrapped); err == nil {
			flat = wrapped.Decisions
		}
	}

	if flat == nil {
		return 0, nil
	}

	counts := map[string]int{}
	for _, d := range flat {
		if d.Value == "" {
			continue
		}
		counts[d.Value]++
	}
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(counts))
	for k, v := range counts {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	if len(pairs) > crowdSecTopN {
		pairs = pairs[:crowdSecTopN]
	}
	top := make([]map[string]any, 0, len(pairs))
	for _, p := range pairs {
		top = append(top, map[string]any{"ip": p.k, "count": p.v})
	}
	return len(flat), top
}

// summariseScenarios extracts the top-N scenario names + bucket-pour
// counts from `cscli metrics -o json`. The metrics JSON shape changes
// across cscli versions; we look for any object whose values look like
// {name -> count} maps under common parent keys.
func summariseScenarios(raw string) []map[string]any {
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil
	}
	candidates := []string{"buckets", "scenarios", "Scenarios", "Buckets"}
	var scenarios map[string]any
	for _, key := range candidates {
		if v, ok := root[key]; ok {
			if m, ok := v.(map[string]any); ok {
				scenarios = m
				break
			}
		}
	}
	// Fallback: walk LocalAPI.Metrics.Scenarios shape.
	if scenarios == nil {
		if lapi, ok := root["LocalAPI"].(map[string]any); ok {
			if metrics, ok := lapi["Metrics"].(map[string]any); ok {
				if s, ok := metrics["Scenarios"].(map[string]any); ok {
					scenarios = s
				}
			}
		}
	}
	if scenarios == nil {
		return nil
	}
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(scenarios))
	for name, v := range scenarios {
		n := scenarioCount(v)
		if n <= 0 {
			continue
		}
		pairs = append(pairs, kv{name, n})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	if len(pairs) > crowdSecTopN {
		pairs = pairs[:crowdSecTopN]
	}
	out := make([]map[string]any, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, map[string]any{"name": p.k, "count": p.v})
	}
	return out
}

// scenarioCount unwraps cscli's per-scenario counters. Most versions
// expose either a number directly or a map containing a "pour" / "overflow"
// counter. We add what we can find.
func scenarioCount(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case map[string]any:
		var sum int
		for _, key := range []string{"pour", "Pour", "overflow", "Overflow", "instantiation", "Instantiation"} {
			if c, ok := t[key]; ok {
				switch n := c.(type) {
				case float64:
					sum += int(n)
				case int:
					sum += n
				}
			}
		}
		return sum
	}
	return 0
}
