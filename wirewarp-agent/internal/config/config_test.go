package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentUpdatesPreserveEdgeAttachmentsVPNAndAuthentication(t *testing.T) {
	cfg := &Config{Mode: "client"}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	var workers sync.WaitGroup
	for index := 0; index < 12; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for iteration := 0; iteration < 8; iteration++ {
				if err := cfg.UpdateAndSave(path, func(next *Config) error {
					switch index % 4 {
					case 0:
						next.UpsertAttachment(AttachmentState{WGInterface: fmt.Sprintf("wg%d", index), ServerEndpoint: fmt.Sprintf("server:%d", iteration)})
					case 1:
						next.UpsertVpnEndpoint(VpnEndpointState{WGInterface: fmt.Sprintf("wg-vpn%d", index), DNSServers: []string{"192.168.20.1"}})
					case 2:
						next.EdgeDesired = &EdgeDesiredState{Whitelist: EdgeWhitelist{IPs: []string{"192.168.20.1"}}}
						next.EdgeBouncerKey = "bouncer"
					case 3:
						next.AgentJWT = "registered-jwt"
						next.AgentID = "registered-agent"
					}
					return nil
				}); err != nil {
					t.Errorf("concurrent update: %v", err)
					return
				}
				_ = cfg.Snapshot()
			}
		}(index)
	}
	workers.Wait()
	saved, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []*Config{cfg.Snapshot(), saved} {
		if len(state.Attachments) != 3 || len(state.VpnEndpoints) != 3 || state.EdgeBouncerKey != "bouncer" || state.AgentJWT != "registered-jwt" || state.AgentID != "registered-agent" {
			t.Fatal("concurrent persistence lost an unrelated update")
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("configuration must remain private")
	}
}

func TestFailedUpdateDoesNotPublishOrReplaceFile(t *testing.T) {
	cfg := &Config{Mode: "client", AgentID: "original"}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := cfg.UpdateAndSave(path, func(next *Config) error {
		next.AgentID = "changed"
		return fmt.Errorf("mutation rejected")
	}); err == nil {
		t.Fatal("expected rejected mutation")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) || cfg.Snapshot().AgentID != "original" {
		t.Fatal("rejected update changed stored state")
	}
	if err := cfg.UpdateAndSave(filepath.Dir(path), func(next *Config) error {
		next.AgentID = "changed"
		return nil
	}); err == nil {
		t.Fatal("expected failed atomic rename")
	}
	if cfg.Snapshot().AgentID != "original" {
		t.Fatal("failed write published state")
	}
}

func TestSnapshotDoesNotShareMutableState(t *testing.T) {
	gateway := true
	cfg := &Config{IsGateway: &gateway, Server: &ServerState{PublicIface: "eth0"},
		Attachments:  []AttachmentState{{WGInterface: "wg0"}},
		VpnEndpoints: []VpnEndpointState{{DNSServers: []string{"192.168.20.1"}}},
		EdgeDesired:  &EdgeDesiredState{TraefikDynamicConfig: map[string]any{"http": map[string]any{"domains": []any{"original"}}}},
	}
	snapshot := cfg.Snapshot()
	*snapshot.IsGateway = false
	snapshot.Server.PublicIface = "changed"
	snapshot.Attachments[0].WGInterface = "changed"
	snapshot.VpnEndpoints[0].DNSServers[0] = "changed"
	snapshot.EdgeDesired.TraefikDynamicConfig["http"].(map[string]any)["domains"].([]any)[0] = "changed"
	original := cfg.Snapshot()
	if !*original.IsGateway || original.Server.PublicIface != "eth0" || original.Attachments[0].WGInterface != "wg0" || original.VpnEndpoints[0].DNSServers[0] != "192.168.20.1" || original.EdgeDesired.TraefikDynamicConfig["http"].(map[string]any)["domains"].([]any)[0] != "original" {
		t.Fatal("snapshot shared mutable state")
	}
}

func TestGatewayRoleLegacyInferenceAndExplicitDemotion(t *testing.T) {
	cfg := &Config{Attachments: []AttachmentState{{IsGateway: true}}}
	if !cfg.Snapshot().Gateway() {
		t.Fatal("legacy gateway must remain eligible")
	}
	demoted := false
	cfg.IsGateway = &demoted
	if cfg.Snapshot().Gateway() {
		t.Fatal("explicit role must override attachment inference")
	}
}
