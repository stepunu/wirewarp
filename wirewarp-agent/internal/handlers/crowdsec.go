package handlers

import (
	"context"
	"encoding/json"
	"fmt"
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
// (broken DB, hung backend) can't stall the agent's WS loop.
const crowdSecCmdTimeout = 15 * time.Second

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
	// before the first card has data.
	h.pollAndEmitCrowdSec(ctx)
	t := time.NewTicker(crowdSecPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.pollAndEmitCrowdSec(ctx)
		}
	}
}

func (h *ServerHandlers) pollAndEmitCrowdSec(ctx context.Context) {
	payload := collectCrowdSec(ctx)
	p := h.emit.Load()
	if p == nil {
		return
	}
	fn := *p
	if fn == nil {
		return
	}
	_ = fn("crowdsec_status", payload)
}

// collectCrowdSec runs cscli (version, metrics, decisions) and
// assembles the heartbeat payload. Errors are swallowed into the
// payload's `error` field — the UI will surface them, and a missing
// `cscli` binary results in `running: false` without an error.
func collectCrowdSec(parent context.Context) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := exec.LookPath("cscli"); err != nil {
		return map[string]any{"running": false, "timestamp": now}
	}

	version, vErr := runCSCli(parent, "version")
	if vErr != nil {
		return map[string]any{
			"running":   false,
			"error":     vErr.Error(),
			"timestamp": now,
		}
	}

	decisions, dErr := runCSCli(parent, "decisions", "list", "-o", "json")
	if dErr != nil {
		return map[string]any{
			"running":   true,
			"version":   parseVersionLine(version),
			"error":     "decisions list: " + dErr.Error(),
			"timestamp": now,
		}
	}
	totalDecisions, topIPs := summariseDecisions(decisions)

	scenarios, mErr := runCSCli(parent, "metrics", "-o", "json")
	var topScenarios []map[string]any
	var metricsErr string
	if mErr != nil {
		metricsErr = "metrics: " + mErr.Error()
	} else {
		topScenarios = summariseScenarios(scenarios)
	}

	return map[string]any{
		"running":         true,
		"version":         parseVersionLine(version),
		"total_decisions": totalDecisions,
		"top_scenarios":  topScenarios,
		"top_ips":        topIPs,
		"error":          metricsErr, // non-fatal — we still have decisions
		"timestamp":      now,
	}
}

// runCSCli executes `cscli <args>` with a hard timeout, returning
// combined stdout. cscli prints errors on stdout in JSON mode anyway,
// so we don't try to separate streams here.
func runCSCli(parent context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, crowdSecCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "cscli", args...).CombinedOutput()
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

// summariseDecisions parses `cscli decisions list -o json` output —
// an array of decision objects — and returns (total, topIPs).
// Top is by frequency of the `value` field (which is the banned IP
// for ip-scope decisions). cscli sometimes wraps the array; tolerate
// either shape.
func summariseDecisions(raw string) (int, []map[string]any) {
	type decision struct {
		Value string `json:"value"`
		Scope string `json:"scope"`
	}
	var list []decision
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		// Some cscli versions wrap the array: { "decisions": [...] }
		var wrapped struct {
			Decisions []decision `json:"decisions"`
		}
		if err2 := json.Unmarshal([]byte(raw), &wrapped); err2 != nil {
			return 0, nil
		}
		list = wrapped.Decisions
	}
	counts := map[string]int{}
	for _, d := range list {
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
	return len(list), top
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
