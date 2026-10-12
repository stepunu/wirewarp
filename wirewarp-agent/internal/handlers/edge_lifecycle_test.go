package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func TestStopEdgeServicesLeavesUnmanagedUnitsUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unit")
	old := edgeSystemctl
	var calls []string
	edgeSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args[len(args)-1])
		return nil, nil
	}
	t.Cleanup(func() { edgeSystemctl = old })
	h := NewEdge(&config.Config{Mode: "server", EdgeDisabled: true}, filepath.Join(t.TempDir(), "agent.yaml"))
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.managedService = func(unit string) (bool, error) {
		if unit != "traefik.service" {
			return false, nil
		}
		return managedFileContains(path, "Description=Traefik edge proxy (WireWarp-managed)")
	}
	for _, content := range []string{"", "Description=Unrelated reverse proxy\n"} {
		if content != "" {
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := h.stopEdgeServices(nil); err != nil {
			t.Fatal(err)
		}
		if len(calls) != 0 {
			t.Fatal("unmanaged service was stopped")
		}
	}
	if err := os.WriteFile(path, []byte("Description=Traefik edge proxy (WireWarp-managed)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.stopEdgeServices(nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"traefik.service"}) {
		t.Fatalf("unexpected stopped services: %v", calls)
	}
}

func TestHandleEdgeDisableStopsServicesAndPreservesDesiredState(t *testing.T) {
	var calls [][]string
	old := edgeSystemctl
	edgeSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return []byte("ok"), nil
	}
	t.Cleanup(func() { edgeSystemctl = old })

	h := &EdgeHandlers{
		managedService: func(string) (bool, error) { return true, nil },
		cfgPath:        filepath.Join(t.TempDir(), "agent.yaml"),
		cfg: &config.Config{
			EdgeDesired: &config.EdgeDesiredState{
				Whitelist: config.EdgeWhitelist{IPs: []string{"1.2.3.4"}},
				TraefikDynamicConfig: map[string]any{
					"http": map[string]any{"routers": map[string]any{}},
				},
			},
			EdgeBouncerKey: "saved-key",
		},
	}
	raw, _ := json.Marshal(map[string]any{
		"preserve_state": true,
		"services":       []string{"traefik", "crowdsec", "nginx"},
	})

	out, err := h.handleEdgeDisable(raw)
	if err != nil {
		t.Fatalf("handleEdgeDisable: %v", err)
	}
	want := [][]string{
		{"disable", "--now", "traefik.service"},
		{"disable", "--now", "crowdsec"},
		{"disable", "--now", "nginx"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("systemctl calls:\nwant %#v\ngot  %#v", want, calls)
	}
	if h.cfg.EdgeDesired == nil || h.cfg.EdgeBouncerKey != "saved-key" {
		t.Fatalf("disable must preserve desired config and secrets: %#v", h.cfg)
	}
	if out == "" {
		t.Fatal("expected human-readable output")
	}
}

func TestHandleEdgeDisableTreatsMissingOptionalUnitsAsSkipped(t *testing.T) {
	old := edgeSystemctl
	edgeSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		if args[len(args)-1] == "nginx" {
			return []byte("Unit nginx.service could not be found."), errors.New("missing")
		}
		return []byte("ok"), nil
	}
	t.Cleanup(func() { edgeSystemctl = old })

	h := &EdgeHandlers{managedService: func(string) (bool, error) { return true, nil }, cfg: &config.Config{}, cfgPath: filepath.Join(t.TempDir(), "agent.yaml")}
	raw, _ := json.Marshal(map[string]any{"services": []string{"nginx"}})

	if _, err := h.handleEdgeDisable(raw); err != nil {
		t.Fatalf("missing optional units should not fail disable: %v", err)
	}
}
