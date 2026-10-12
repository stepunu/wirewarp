package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
)

func edgeExecutor(t *testing.T, h *EdgeHandlers) (*executor.Executor, *[]executor.Result) {
	t.Helper()
	results := []executor.Result{}
	exec := executor.New(func(result executor.Result) error { results = append(results, result); return nil })
	h.Register(exec)
	return exec, &results
}

func dispatchEdge(exec *executor.Executor, command, params string) {
	exec.Dispatch(executor.Command{ID: "test", Type: command, Params: json.RawMessage(params)})
}

func TestDesiredStateSaveFailureRestoresCredentialFiles(t *testing.T) {
	for _, provider := range []string{"cloudflare", "rfc2136"} {
		t.Run(provider, func(t *testing.T) {
			dir := t.TempDir()
			env, token := filepath.Join(dir, "env"), filepath.Join(dir, "token")
			old := TraefikACMEParams{CloudflareDNSToken: "old-fixture-token"}
			next := TraefikACMEParams{RFC2136Nameserver: "127.0.0.1:53", RFC2136TSIGKey: "fixture.", RFC2136TSIGAlgorithm: "hmac-sha256", RFC2136TSIGSecret: "Zml4dHVyZQ=="}
			if provider == "rfc2136" {
				old, next = next, old
			}
			if _, err := applyTraefikACMESecrets(old, env, token); err != nil {
				t.Fatal(err)
			}
			// Preserve a pre-existing restart request exactly, including its mode.
			if err := os.WriteFile(env+".pending-restart", []byte("old request\n"), 0640); err != nil {
				t.Fatal(err)
			}
			paths := []string{env, token, filepath.Join(dir, "rfc2136_tsig_secret"), env + ".pending-restart"}
			if old.RFC2136Nameserver != "" {
				paths = append(paths, rfc2136CredentialPath(old, token))
			}
			before := map[string][]byte{}
			modes := map[string]os.FileMode{}
			for _, path := range paths {
				if data, err := os.ReadFile(path); err == nil {
					before[path] = data
					info, _ := os.Stat(path)
					modes[path] = info.Mode().Perm()
				}
			}
			cfg := &config.Config{Mode: "server", EdgeDisabled: true, EdgeDesired: &config.EdgeDesiredState{TraefikStaticConfig: map[string]any{"old": true}}, EdgeBouncerKey: "old-key"}
			h := NewEdge(cfg, t.TempDir()) // A directory cannot be replaced by the saved config file.
			h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
			h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
			h.persistSecrets = func(p TraefikACMEParams, save func() error) error {
				return persistTraefikACMESecrets(p, env, token, save)
			}
			h.applyDesired = func(context.Context) error { t.Fatal("failed save reconciled"); return nil }
			raw, _ := json.Marshal(EdgeDesiredStateParams{TraefikACME: next})
			if _, err := h.handleEdgeDesiredState(raw); err == nil {
				t.Fatal("save failure was masked")
			}
			for _, path := range paths {
				data, err := os.ReadFile(path)
				if original, exists := before[path]; exists {
					if err != nil || string(data) != string(original) {
						t.Fatal("credential transaction did not restore original file")
					}
					info, _ := os.Stat(path)
					if info.Mode().Perm() != modes[path] {
						t.Fatal("credential mode changed")
					}
				} else if !os.IsNotExist(err) {
					t.Fatal("new provider credential remained after failed save")
				}
			}
			state := cfg.Snapshot()
			if !state.EdgeDisabled || state.EdgeBouncerKey != "old-key" || state.EdgeDesired.TraefikStaticConfig["old"] != true {
				t.Fatal("failed save replaced old desired state")
			}
		})
	}
}

func TestGatewayEdgeWithoutAttachmentsDoesNotCreateServerNetwork(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	cfg := &config.Config{Mode: "client"}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewEdge(cfg, path)
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.managedService = func(string) (bool, error) { return false, nil }
	secretWrites, serviceApplies := 0, 0
	h.persistSecrets = func(p TraefikACMEParams, save func() error) error { secretWrites++; return save() }
	h.applyDesired = func(context.Context) error {
		serviceApplies++
		state := cfg.Snapshot()
		if state.Server != nil || len(state.Attachments) != 0 || state.EdgeDesired == nil || state.EdgeBouncerKey == "" {
			t.Fatal("edge enablement changed tunnel networking or omitted persisted state")
		}
		return nil
	}
	exec, results := edgeExecutor(t, h)
	dispatchEdge(exec, "edge_node_role", `{"is_gateway":true,"lan_ip":"192.168.20.110","lan_network":"192.168.20.0/24"}`)
	if serviceApplies != 0 || secretWrites != 0 {
		t.Fatal("gateway role automatically enabled services")
	}
	dispatchEdge(exec, "edge_desired_state", `{"whitelist":{"ips":["192.168.20.1"]},"traefik_static_config":{"entryPoints":{"lan":{"address":"192.168.20.110:80"}}},"traefik_acme":{"rfc2136_tsig_secret":"do-not-store"}}`)
	if !(*results)[1].Success || serviceApplies != 1 || secretWrites != 1 {
		t.Fatalf("gateway edge failed: %+v", *results)
	}
	saved, err := config.Load(path)
	if err != nil || !saved.Gateway() || saved.EdgeDisabled || saved.Server != nil || len(saved.Attachments) != 0 {
		t.Fatal("gateway state was not saved independently")
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "do-not-store") || strings.Contains(string(data), "traefik_acme") {
		t.Fatal("ACME credentials were saved in agent YAML")
	}
}

func TestPlainClientRejectsEveryEdgeCommandBeforeEffects(t *testing.T) {
	h := NewEdge(&config.Config{Mode: "client"}, filepath.Join(t.TempDir(), "agent.yaml"))
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.managedService = func(string) (bool, error) { return true, nil }
	h.persistSecrets = func(TraefikACMEParams, func() error) error { t.Fatal("plain client wrote secrets"); return nil }
	h.applyDesired = func(context.Context) error { t.Fatal("plain client applied services"); return nil }
	exec, results := edgeExecutor(t, h)
	for _, command := range []string{"edge_desired_state", "edge_disable", "edge_cache_test", "edge_cache_purge", "traefik_install", "traefik_sync_config", "crowdsec_install", "crowdsec_sync_whitelist", "crowdsec_appsec_enable"} {
		dispatchEdge(exec, command, `{}`)
		if (*results)[len(*results)-1].Success || !strings.Contains((*results)[len(*results)-1].Output, "requires a server or gateway") {
			t.Fatalf("plain client accepted %s", command)
		}
	}
	if err := h.edgeReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.cfgPath); !os.IsNotExist(err) {
		t.Fatal("plain client edge request created config")
	}
}

func TestDisableAndDemotionPersistAcrossRestart(t *testing.T) {
	var stopped []string
	old := edgeSystemctl
	edgeSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		stopped = append(stopped, args[len(args)-1])
		return nil, nil
	}
	t.Cleanup(func() { edgeSystemctl = old })
	gateway := true
	cfg := &config.Config{Mode: "client", IsGateway: &gateway, EdgeDesired: &config.EdgeDesiredState{}, EdgeBouncerKey: "preserved"}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewEdge(cfg, path)
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.managedService = func(string) (bool, error) { return true, nil }
	h.applyDesired = func(context.Context) error { t.Fatal("disabled edge reconciled"); return nil }
	exec, results := edgeExecutor(t, h)
	dispatchEdge(exec, "edge_disable", `{"preserve_state":true}`)
	if !(*results)[0].Success || len(stopped) != 3 {
		t.Fatal("edge disable did not stop managed services")
	}
	saved, err := config.Load(path)
	if err != nil || !saved.EdgeDisabled || saved.EdgeDesired == nil || saved.EdgeBouncerKey != "preserved" {
		t.Fatal("disable did not retain persisted state")
	}
	restarted := NewEdge(saved, path)
	restarted.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	restarted.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	restarted.managedService = func(string) (bool, error) { return true, nil }
	restarted.applyDesired = h.applyDesired
	if err := restarted.edgeReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(stopped) != 6 {
		t.Fatal("restart did not converge disabled services")
	}
	dispatchEdge(exec, "edge_node_role", `{"is_gateway":false}`)
	if !(*results)[1].Success || len(stopped) != 9 || cfg.Snapshot().Gateway() {
		t.Fatal("gateway demotion did not stop and disable the edge")
	}
	dispatchEdge(exec, "edge_node_role", `{"is_gateway":true}`)
	if !(*results)[2].Success || !cfg.Snapshot().EdgeDisabled {
		t.Fatal("promotion automatically enabled edge services")
	}
	if err := h.edgeReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.persistSecrets = func(_ TraefikACMEParams, save func() error) error { return save() }
	reenabled := 0
	h.applyDesired = func(context.Context) error { reenabled++; return nil }
	dispatchEdge(exec, "edge_desired_state", `{}`)
	if !(*results)[3].Success || reenabled != 1 || cfg.Snapshot().EdgeDisabled {
		t.Fatal("explicit desired state did not re-enable the edge")
	}
}

func TestEdgeSaveFailureDoesNotEnableDisabledState(t *testing.T) {
	gateway := true
	cfg := &config.Config{Mode: "client", IsGateway: &gateway, EdgeDisabled: true}
	h := NewEdge(cfg, t.TempDir())
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.managedService = func(string) (bool, error) { return true, nil }
	h.persistSecrets = func(_ TraefikACMEParams, save func() error) error { return save() }
	h.applyDesired = func(context.Context) error { t.Fatal("failed save applied services"); return nil }
	exec, results := edgeExecutor(t, h)
	dispatchEdge(exec, "edge_desired_state", `{}`)
	if (*results)[0].Success || !cfg.Snapshot().EdgeDisabled || cfg.Snapshot().EdgeDesired != nil {
		t.Fatal("failed desired save published enabled state")
	}
}

func TestFailedServiceStopRemainsDisabled(t *testing.T) {
	old := edgeSystemctl
	edgeSystemctl = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("service stop failed") }
	t.Cleanup(func() { edgeSystemctl = old })
	h := NewEdge(&config.Config{Mode: "server", EdgeDesired: &config.EdgeDesiredState{}}, filepath.Join(t.TempDir(), "agent.yaml"))
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.managedService = func(string) (bool, error) { return true, nil }
	exec, results := edgeExecutor(t, h)
	dispatchEdge(exec, "edge_disable", `{}`)
	if (*results)[0].Success || !h.cfg.Snapshot().EdgeDisabled {
		t.Fatal("failed service stop lost disable intent")
	}
}

func TestConcurrentEdgeReconciliationAndConfigUpdates(t *testing.T) {
	gateway := true
	cfg := &config.Config{Mode: "client", IsGateway: &gateway, EdgeDesired: &config.EdgeDesiredState{}}
	h := NewEdge(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.managedService = func(string) (bool, error) { return true, nil }
	h.applyDesired = func(context.Context) error {
		state := cfg.Snapshot()
		if !state.Gateway() || state.EdgeDesired == nil {
			t.Error("reconcile lost gateway state")
		}
		return nil
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for index := 0; index < 30; index++ {
			if err := h.edgeReconcileOnce(context.Background()); err != nil {
				t.Error(err)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for index := 0; index < 30; index++ {
			if err := cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
				next.AgentJWT = "saved"
				next.UpsertAttachment(config.AttachmentState{WGInterface: "wg0"})
				return nil
			}); err != nil {
				t.Error(err)
			}
		}
	}()
	workers.Wait()
	if state := cfg.Snapshot(); state.EdgeDesired == nil || state.AgentJWT != "saved" || len(state.Attachments) != 1 {
		t.Fatal("edge reconciliation lost a config update")
	}
}

func TestGatewayEdgeTelemetryUsesSharedEmit(t *testing.T) {
	gateway := true
	h := NewEdge(&config.Config{Mode: "client", IsGateway: &gateway}, filepath.Join(t.TempDir(), "agent.yaml"))
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.managedService = func(string) (bool, error) { return true, nil }
	events := []string{}
	h.SetEmit(func(eventType string, payload map[string]any) error {
		events = append(events, eventType)
		if payload["phase"] != "healthy" {
			t.Fatal("edge telemetry payload changed")
		}
		return nil
	})
	payload := map[string]any{"phase": "healthy"}
	if !h.tryEmitCrowdSec(payload) || !h.tryEmitTraefik(payload) || !h.tryEmitNginxCache(payload) {
		t.Fatal("gateway telemetry did not emit")
	}
	if strings.Join(events, ",") != "crowdsec_status,traefik_status,edge_cache_status" {
		t.Fatalf("unexpected telemetry events: %v", events)
	}
}

func TestDisabledEdgeRetriesStopAfterPersistedCrashWindow(t *testing.T) {
	old := edgeSystemctl
	calls := 0
	fail := true
	edgeSystemctl = func(context.Context, ...string) ([]byte, error) {
		calls++
		if fail {
			return nil, errors.New("stop unavailable")
		}
		return nil, nil
	}
	t.Cleanup(func() { edgeSystemctl = old })
	for _, mode := range []string{"client", "server"} {
		gateway := false
		cfg := &config.Config{Mode: mode, IsGateway: &gateway, EdgeDisabled: true, EdgeBouncerKey: "preserved"}
		if mode == "client" {
			cfg.EdgeDesired = &config.EdgeDesiredState{}
		}
		path := filepath.Join(t.TempDir(), "agent.yaml")
		if err := cfg.Save(path); err != nil {
			t.Fatal(err)
		}
		saved, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		h := NewEdge(saved, path)
		h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
		h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
		h.managedService = func(string) (bool, error) { return true, nil }
		h.applyDesired = func(context.Context) error { t.Fatal("disabled edge applied desired services"); return nil }
		fail = true
		before := calls
		if err := h.edgeReconcileOnce(context.Background()); err == nil {
			t.Fatal("stop failure was hidden")
		}
		fail = false
		if err := h.edgeReconcileOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if calls != before+6 || !saved.Snapshot().EdgeDisabled || saved.Snapshot().EdgeBouncerKey != "preserved" {
			t.Fatal("disabled services did not retry without losing saved state")
		}
		if mode == "client" && saved.Snapshot().EdgeDesired == nil {
			t.Fatal("retry removed desired state")
		}
	}
}
