package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type EdgeDisableParams struct {
	PreserveState bool     `json:"preserve_state"`
	Services      []string `json:"services"`
}

var edgeSystemctl = func(ctx context.Context, args ...string) ([]byte, error) {
	sysctl := resolveBin("systemctl", "/usr/bin/systemctl", "/bin/systemctl")
	return exec.CommandContext(ctx, sysctl, args...).CombinedOutput()
}

func (h *ServerHandlers) handleEdgeDisable(raw json.RawMessage) (string, error) {
	var p EdgeDisableParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", fmt.Errorf("parse params: %w", err)
		}
	}
	services := normalizeEdgeServices(p.Services)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var stopped []string
	var skipped []string
	var failures []string
	for _, service := range services {
		unit, ok := edgeServiceUnit(service)
		if !ok {
			failures = append(failures, fmt.Sprintf("%s: unsupported service", service))
			continue
		}
		out, err := edgeSystemctl(ctx, "disable", "--now", unit)
		msg := strings.TrimSpace(string(out))
		if err == nil {
			stopped = append(stopped, unit)
			continue
		}
		if isMissingSystemdUnit(msg) {
			skipped = append(skipped, unit)
			continue
		}
		if msg == "" {
			msg = err.Error()
		}
		failures = append(failures, fmt.Sprintf("%s: %s", unit, msg))
	}
	if len(failures) > 0 {
		return "", fmt.Errorf("disable edge services: %s", strings.Join(failures, "; "))
	}

	parts := []string{}
	if len(stopped) > 0 {
		parts = append(parts, "stopped/disabled "+strings.Join(stopped, ", "))
	}
	if len(skipped) > 0 {
		parts = append(parts, "skipped missing "+strings.Join(skipped, ", "))
	}
	if len(parts) == 0 {
		parts = append(parts, "no edge services requested")
	}
	return strings.Join(parts, "; ") + "; preserved configs and saved desired state", nil
}

func normalizeEdgeServices(in []string) []string {
	if len(in) == 0 {
		return []string{"traefik", "crowdsec", "nginx"}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, service := range in {
		service = strings.TrimSpace(strings.ToLower(service))
		if service == "" || seen[service] {
			continue
		}
		seen[service] = true
		out = append(out, service)
	}
	return out
}

func edgeServiceUnit(service string) (string, bool) {
	switch service {
	case "traefik", "traefik.service":
		return traefikUnitName, true
	case "crowdsec", "crowdsec.service":
		return "crowdsec", true
	case "nginx", "nginx.service", "nginx_cache", "nginx-cache":
		return "nginx", true
	default:
		return "", false
	}
}

func isMissingSystemdUnit(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "could not be found") ||
		strings.Contains(output, "not found") ||
		strings.Contains(output, "not loaded") ||
		strings.Contains(output, "does not exist") ||
		strings.Contains(output, "no such file")
}
