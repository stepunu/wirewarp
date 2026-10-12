package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func gatewayRuntimeFixture() (*config.Config, *config.EdgeDesiredState) {
	gateway := true
	cfg := &config.Config{Mode: "client", IsGateway: &gateway, Attachments: []config.AttachmentState{{IsGateway: true, WGInterface: "wg0", VPSTunnelIP: "10.20.0.1", TunnelIP: "10.20.0.2/32", LANIP: "192.168.20.110"}}}
	desired := &config.EdgeDesiredState{RuntimeMode: "security_edge", PublicIngress: []config.EdgePublicIngress{{Interface: "wg0", SourceIP: "10.20.0.1", ListenIP: "10.20.0.2"}}, TraefikStaticConfig: map[string]any{"entryPoints": map[string]any{
		"web":       map[string]any{"address": "10.20.0.2:80", "proxyProtocol": map[string]any{"trustedIPs": []any{"10.20.0.1"}}},
		"websecure": map[string]any{"address": "10.20.0.2:443", "proxyProtocol": map[string]any{"trustedIPs": []any{"10.20.0.1/32"}}},
		"lan":       map[string]any{"address": "192.168.20.110:80"}, "lansecure": map[string]any{"address": "192.168.20.110:443"},
	}}}
	return cfg, desired
}

func TestEdgeRuntimePreflightRejectsTamperingBeforeEffects(t *testing.T) {
	cases := map[string]func(*config.Config, *config.EdgeDesiredState){
		"plain client":       func(c *config.Config, d *config.EdgeDesiredState) { value := false; c.IsGateway = &value },
		"unknown mode":       func(c *config.Config, d *config.EdgeDesiredState) { d.RuntimeMode = "other" },
		"gateway relay mode": func(c *config.Config, d *config.EdgeDesiredState) { d.RuntimeMode = "relay_only" },
		"wrong source":       func(c *config.Config, d *config.EdgeDesiredState) { d.PublicIngress[0].SourceIP = "10.20.0.3" },
		"wrong interface":    func(c *config.Config, d *config.EdgeDesiredState) { d.PublicIngress[0].Interface = "wg1" },
		"invalid interface":  func(c *config.Config, d *config.EdgeDesiredState) { d.PublicIngress[0].Interface = "wg0\n-A INPUT" },
		"wrong bind":         func(c *config.Config, d *config.EdgeDesiredState) { d.PublicIngress[0].ListenIP = "10.20.0.4" },
		"IPv6":               func(c *config.Config, d *config.EdgeDesiredState) { d.PublicIngress[0].SourceIP = "fd00::1" },
		"duplicate": func(c *config.Config, d *config.EdgeDesiredState) {
			d.PublicIngress = append(d.PublicIngress, d.PublicIngress[0])
		},
		"wildcard bind": func(c *config.Config, d *config.EdgeDesiredState) { runtimeEP(d, "web")["address"] = ":80" },
		"UDP bind": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "websecure")["address"] = "10.20.0.2:443/udp"
		},
		"missing port": func(c *config.Config, d *config.EdgeDesiredState) {
			delete(d.TraefikStaticConfig["entryPoints"].(map[string]any), "web")
		},
		"wrong proxy source": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "web")["proxyProtocol"] = map[string]any{"trustedIPs": []any{"10.20.0.9"}}
		},
		"proxy CIDR": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "web")["proxyProtocol"] = map[string]any{"trustedIPs": []any{"10.20.0.0/24"}}
		},
		"insecure proxy": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "web")["proxyProtocol"].(map[string]any)["insecure"] = true
		},
		"LAN proxy": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "lan")["proxyProtocol"] = map[string]any{}
		},
		"forwarded trust": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "web")["forwardedHeaders"] = map[string]any{"trustedIPs": []any{"10.20.0.1"}}
		},
		"LAN insecure forwarding": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "lan")["forwardedHeaders"] = map[string]any{"insecure": true}
		},
		"HTTP3": func(c *config.Config, d *config.EdgeDesiredState) {
			runtimeEP(d, "websecure")["http3"] = map[string]any{}
		},
		"missing ingress": func(c *config.Config, d *config.EdgeDesiredState) { d.PublicIngress = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, desired := gatewayRuntimeFixture()
			mutate(cfg, desired)
			h := NewEdge(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
			h.persistSecrets = func(TraefikACMEParams, func() error) error { t.Fatal("invalid state changed credentials"); return nil }
			h.applyIngress = func(context.Context, []config.EdgePublicIngress) error {
				t.Fatal("invalid state changed firewall")
				return nil
			}
			h.snapshotRuntime = func() (func() error, error) { t.Fatal("invalid state entered file transaction"); return nil, nil }
			raw, _ := json.Marshal(EdgeDesiredStateParams{RuntimeMode: desired.RuntimeMode, PublicIngress: desired.PublicIngress, TraefikStaticConfig: desired.TraefikStaticConfig})
			if _, err := h.handleEdgeDesiredState(raw); err == nil {
				t.Fatal("invalid payload accepted")
			}
			if cfg.Snapshot().EdgeDesired != nil {
				t.Fatal("invalid desired state persisted")
			}
		})
	}
}

func runtimeEP(d *config.EdgeDesiredState, name string) map[string]any {
	return d.TraefikStaticConfig["entryPoints"].(map[string]any)[name].(map[string]any)
}

func TestGatewayRuntimeAcceptsExactAttachmentAndLANOnly(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	if err := validateEdgeRuntime(cfg, desired); err != nil {
		t.Fatal(err)
	}
	desired.PublicIngress = nil
	delete(desired.TraefikStaticConfig["entryPoints"].(map[string]any), "web")
	delete(desired.TraefikStaticConfig["entryPoints"].(map[string]any), "websecure")
	cfg.Attachments = nil
	lanIP := "192.168.20.110"
	cfg.GatewayLANIP = &lanIP
	if err := validateEdgeRuntime(cfg, desired); err != nil {
		t.Fatal("unattached LAN-only gateway rejected:", err)
	}
}

func TestGatewayLANRoleMetadataIsAuthoritativeAndLegacyCompatible(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	h := NewEdge(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	if _, err := h.handleNodeRole(json.RawMessage(`{"is_gateway":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := validateEdgeRuntime(cfg.Snapshot(), desired); err != nil {
		t.Fatal("legacy LAN attachment fallback rejected:", err)
	}
	if _, err := h.handleNodeRole(json.RawMessage(`{"is_gateway":true,"lan_ip":"192.168.20.111","lan_network":"192.168.20.0/24"}`)); err != nil {
		t.Fatal(err)
	}
	if err := validateEdgeRuntime(cfg.Snapshot(), desired); err == nil {
		t.Fatal("legacy attachment overrode authoritative LAN IP")
	}
	before := cfg.Snapshot()
	if _, err := h.handleNodeRole(json.RawMessage(`{"is_gateway":true,"lan_ip":"192.168.20.110","lan_network":"192.168.30.0/24"}`)); err == nil {
		t.Fatal("LAN network mismatch accepted")
	}
	if *cfg.Snapshot().GatewayLANIP != *before.GatewayLANIP {
		t.Fatal("invalid LAN metadata changed saved state")
	}
	if _, err := h.handleNodeRole(json.RawMessage(`{"is_gateway":true,"lan_ip":null,"lan_network":null}`)); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GatewayLANIP == nil || *loaded.GatewayLANIP != "" {
		t.Fatal("explicit missing LAN metadata did not persist")
	}
	if err := validateEdgeRuntime(loaded, desired); err == nil {
		t.Fatal("cleared authoritative LAN metadata fell back to stale attachment")
	}
}

func TestEdgeDisableKeepsIngressWhenStopFails(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	cfg.EdgeDesired = desired
	cfg.EdgeIngressGuard = desired.PublicIngress
	h := NewEdge(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.managedService = func(unit string) (bool, error) { return unit == traefikUnitName, nil }
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error {
		t.Fatal("stop failure removed ingress guard")
		return nil
	}
	old := edgeSystemctl
	edgeSystemctl = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("stop failed") }
	t.Cleanup(func() { edgeSystemctl = old })
	if _, err := h.handleEdgeDisable(nil); err == nil {
		t.Fatal("stop failure masked")
	}
	state := cfg.Snapshot()
	if !state.EdgeDisabled || !reflect.DeepEqual(state.EdgeIngressGuard, desired.PublicIngress) {
		t.Fatal("stop failure lost persistent guard")
	}
}

func TestUnpublicationKeepsOldGuardUntilRuntimeChanged(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	cfg.EdgeDesired = desired
	h := NewEdge(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.snapshotRuntime = func() (func() error, error) { return func() error { return nil }, nil }
	h.persistSecrets = func(_ TraefikACMEParams, save func() error) error { return save() }
	h.managedService = func(string) (bool, error) { return false, nil }
	oldListenerActive := true
	h.applyIngress = func(_ context.Context, rows []config.EdgePublicIngress) error {
		if oldListenerActive && len(rows) == 0 {
			t.Fatal("live old listener lost guard")
		}
		return nil
	}
	h.applyDesired = func(context.Context) error {
		if len(cfg.Snapshot().EdgeIngressGuard) != 1 || !cfg.Snapshot().EdgeRuntimePending {
			t.Fatal("transition guard was not saved before runtime change")
		}
		oldListenerActive = false
		return nil
	}
	raw, _ := json.Marshal(EdgeDesiredStateParams{TraefikStaticConfig: map[string]any{"entryPoints": map[string]any{"lan": map[string]any{"address": "192.168.20.110:80"}}}})
	if _, err := h.handleEdgeDesiredState(raw); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Snapshot().EdgeIngressGuard) != 0 || cfg.Snapshot().EdgeRuntimePending {
		t.Fatal("successful transition did not clear old guard")
	}
}

func TestFreshEnableFailureStopsServicesBeforeRemovingOwnershipMarkers(t *testing.T) {
	for _, stopFails := range []bool{false, true} {
		t.Run(fmt.Sprint(stopFails), func(t *testing.T) {
			cfg, desired := gatewayRuntimeFixture()
			path := filepath.Join(t.TempDir(), "unit")
			h := NewEdge(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
			h.snapshotRuntime = func() (func() error, error) { return snapshotEdgeFiles([]string{path}) }
			h.persistSecrets = func(_ TraefikACMEParams, save func() error) error { return save() }
			h.managedService = func(unit string) (bool, error) {
				if unit != traefikUnitName {
					return false, nil
				}
				return managedFileContains(path, "WireWarp-managed")
			}
			listenerActive := false
			h.applyIngress = func(_ context.Context, rows []config.EdgePublicIngress) error {
				if listenerActive && len(rows) == 0 {
					t.Fatal("failed new listener lost guard")
				}
				return nil
			}
			h.applyDesired = func(context.Context) error {
				if err := os.WriteFile(path, []byte("WireWarp-managed"), 0644); err != nil {
					t.Fatal(err)
				}
				listenerActive = true
				return errors.New("first enable failed")
			}
			old := edgeSystemctl
			stopCalls := 0
			fail := stopFails
			edgeSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
				if _, err := os.Stat(path); err != nil {
					t.Fatal("ownership marker removed before stop")
				}
				stopCalls++
				if fail {
					return nil, errors.New("stop failed")
				}
				listenerActive = false
				return nil, nil
			}
			t.Cleanup(func() { edgeSystemctl = old })
			raw, _ := json.Marshal(EdgeDesiredStateParams{PublicIngress: desired.PublicIngress, TraefikStaticConfig: desired.TraefikStaticConfig})
			if _, err := h.handleEdgeDesiredState(raw); err == nil {
				t.Fatal("fresh enable failure masked")
			}
			state := cfg.Snapshot()
			if stopCalls != 1 || !state.EdgeDisabled || state.EdgeDesired != nil {
				t.Fatal("failed fresh enable did not disable and stop owned service")
			}
			if stopFails {
				if !state.EdgeRuntimePending || len(state.EdgeIngressGuard) != 1 {
					t.Fatal("failed stop lost retry or guard")
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatal("failed stop removed ownership marker")
				}
				fail = false
				if err := h.edgeReconcileOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
				if listenerActive || cfg.Snapshot().EdgeRuntimePending {
					t.Fatal("offline retry did not stop failed fresh enable")
				}
			} else if _, err := os.Stat(path); !os.IsNotExist(err) || listenerActive {
				t.Fatal("successful stop did not restore absent marker")
			}
		})
	}
}

func TestRelayOnlyReconcileStopsOwnedServicesWithoutWAFOrCacheInstall(t *testing.T) {
	cfg := &config.Config{Mode: "server", EdgeDesired: &config.EdgeDesiredState{RuntimeMode: "relay_only", TraefikStaticConfig: map[string]any{}, TraefikDynamicConfig: map[string]any{}}}
	h := NewEdge(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.applyIngress = func(context.Context, []config.EdgePublicIngress) error { return nil }
	h.managedService = func(unit string) (bool, error) { return unit == "crowdsec", nil }
	old := edgeSystemctl
	var stops []string
	edgeSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		stops = append(stops, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { edgeSystemctl = old })
	traefik := 0
	h.applyTraefik = func(context.Context, *config.Config) error { traefik++; return nil }
	if err := h.reconcileDesiredEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if traefik != 1 || !reflect.DeepEqual(stops, []string{"disable --now crowdsec"}) {
		t.Fatalf("wrong relay service lifecycle: %d %v", traefik, stops)
	}
	for _, mutate := range []func(*config.EdgeDesiredState){func(d *config.EdgeDesiredState) { d.NginxCacheConfig = map[string]any{"enabled": true} }, func(d *config.EdgeDesiredState) {
		d.TraefikDynamicConfig = map[string]any{"http": map[string]any{"middlewares": map[string]any{"waf": map[string]any{"plugin": map[string]any{"bouncer": map[string]any{}}}}}}
	}} {
		d := cfg.Snapshot().EdgeDesired
		mutate(d)
		if err := validateEdgeRuntime(cfg, d); err == nil {
			t.Fatal("relay accepted WAF/cache")
		}
	}
}

func TestDesiredRuntimeFailureRestoresFilesStateAndIngress(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	cfg.EdgeDesired = desired
	cfg.EdgeBouncerKey = "old-key"
	dir := t.TempDir()
	file := filepath.Join(dir, "dynamic.yml")
	if err := os.WriteFile(file, []byte("old config"), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewEdge(cfg, filepath.Join(dir, "agent.yaml"))
	h.snapshotRuntime = func() (func() error, error) { return snapshotEdgeFiles([]string{file}) }
	h.persistSecrets = func(_ TraefikACMEParams, save func() error) error { return save() }
	var ingress [][]config.EdgePublicIngress
	h.applyIngress = func(_ context.Context, p []config.EdgePublicIngress) error {
		ingress = append(ingress, append([]config.EdgePublicIngress(nil), p...))
		return nil
	}
	h.managedService = func(string) (bool, error) { return false, nil }
	apply := 0
	h.applyDesired = func(context.Context) error {
		apply++
		if apply == 1 {
			if err := os.WriteFile(file, []byte("broken config"), 0600); err != nil {
				t.Fatal(err)
			}
			return errors.New("runtime refused config")
		}
		return nil
	}
	raw, _ := json.Marshal(EdgeDesiredStateParams{RuntimeMode: "security_edge", TraefikStaticConfig: map[string]any{"entryPoints": map[string]any{"lan": map[string]any{"address": "192.168.20.110:80"}}}})
	output, err := h.handleEdgeDesiredState(raw)
	if err == nil || !strings.Contains(output, "previous state restored") {
		t.Fatalf("runtime failure masked: %s %v", output, err)
	}
	data, _ := os.ReadFile(file)
	if string(data) != "old config" {
		t.Fatal("previous runtime file was not restored")
	}
	if cfg.Snapshot().EdgeDesired.PublicIngress[0] != desired.PublicIngress[0] || apply != 2 || len(ingress) != 3 || !reflect.DeepEqual(ingress[0], desired.PublicIngress) || !reflect.DeepEqual(ingress[2], desired.PublicIngress) {
		t.Fatal("previous accepted state was not restored")
	}
}

func TestPersistedGatewayIngressReconcilesOfflineAndRemovesOnDisable(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	cfg.EdgeDesired = desired
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := NewEdge(loaded, path)
	var calls [][]config.EdgePublicIngress
	h.applyIngress = func(_ context.Context, p []config.EdgePublicIngress) error {
		calls = append(calls, append([]config.EdgePublicIngress(nil), p...))
		return nil
	}
	h.applyDesired = func(ctx context.Context) error {
		return h.applyIngress(ctx, loaded.Snapshot().EdgeDesired.PublicIngress)
	}
	h.managedService = func(string) (bool, error) { return false, nil }
	if err := h.edgeReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.handleEdgeDisable(nil); err != nil {
		t.Fatal(err)
	}
	if err := h.edgeReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 5 || len(calls[0]) != 1 || len(calls[1]) != 1 || len(calls[2]) != 1 || len(calls[3]) != 0 || len(calls[4]) != 0 {
		t.Fatalf("wrong offline/disable ACL lifecycle: %v", calls)
	}
	loaded, err = config.Load(path)
	if err != nil || !loaded.EdgeDisabled || !reflect.DeepEqual(loaded.EdgeDesired.PublicIngress, desired.PublicIngress) {
		t.Fatal("disabled state removed saved ingress or failed to persist")
	}
}
