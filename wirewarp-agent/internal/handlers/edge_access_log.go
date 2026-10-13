package handlers

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func (h *EdgeHandlers) collectTraefikAccessStatus(ctx context.Context, traefikRunning bool) map[string]any {
	h.accessLogMu.Lock()
	defer h.accessLogMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, traefikCmdTimeout)
	defer cancel()
	return collectAccessLogStatus(h.cfg.Snapshot().EdgeDisabled, traefikRunning,
		func() ([]byte, error) { return os.ReadFile(traefikStaticCfg) },
		func() error {
			out, err := edgeSystemctl(ctx, "show", traefikUnitName, "--property=StandardOutput", "--value")
			if err != nil {
				return fmt.Errorf("inspect Traefik journal output: %w", err)
			}
			output := strings.TrimSpace(string(out))
			if output != "journal" && output != "journal-or-kmsg" {
				return fmt.Errorf("Traefik output is %q; access collection requires journald", output)
			}
			return h.emitTraefikAccessEvents(ctx)
		})
}

// A successful collection cycle proves journal access, not that requests occurred.
func collectAccessLogStatus(disabled, traefikRunning bool, readConfig func() ([]byte, error), collect func() error) map[string]any {
	status := map[string]any{"installed": false, "running": false, "phase": "disabled"}
	if disabled {
		return status
	}
	data, err := readConfig()
	if os.IsNotExist(err) {
		return status
	}
	var cfg map[string]any
	if err == nil {
		err = yaml.Unmarshal(data, &cfg)
	}
	if err != nil {
		status["phase"] = "degraded"
		status["error"] = fmt.Sprintf("read Traefik access logging configuration: %v", err)
		return status
	}
	value, enabled := cfg["accessLog"]
	if !enabled {
		return status
	}
	status["installed"] = true
	status["phase"] = "degraded"
	logging, ok := value.(map[string]any)
	if !ok || logging["format"] != "json" || logging["filePath"] != nil && logging["filePath"] != "" {
		status["error"] = "access collection requires JSON access logs on standard output"
		return status
	}
	if !traefikRunning {
		status["error"] = "Traefik is not running; access collection is stopped"
		return status
	}
	if err := collect(); err != nil {
		status["error"] = err.Error()
		return status
	}
	status["running"] = true
	status["phase"] = "healthy"
	return status
}
