package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
	"gopkg.in/yaml.v3"
)

func TestEdgeBootGuardRestoresBeforeRuntimeAndFailsClosed(t *testing.T) {
	oldRun, oldRestore := edgeIPTables, edgeIPTablesRestore
	t.Cleanup(func() { edgeIPTables, edgeIPTablesRestore = oldRun, oldRestore })
	edgeIPTables = func(_ context.Context, args ...string) ([]byte, error) {
		if args[1] == "INPUT" {
			return []byte("-P INPUT ACCEPT\n"), nil
		}
		return []byte("No chain/target/match by that name."), errors.New("absent")
	}
	commits := 0
	edgeIPTablesRestore = func(_ context.Context, body string) error {
		commits++
		if !strings.Contains(body, "-I INPUT 1") || !strings.Contains(body, "10.20.0.2/32") || !strings.Contains(body, "-j DROP") {
			t.Fatalf("missing boot guard: %s", body)
		}
		return nil
	}
	cfg, desired := gatewayRuntimeFixture()
	cfg.EdgeDesired = desired
	path := filepath.Join(t.TempDir(), "static.yml")
	data, _ := yaml.Marshal(desired.TraefikStaticConfig)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareEdgeStart(context.Background(), cfg, path); err != nil {
		t.Fatal(err)
	}
	if commits != 1 {
		t.Fatal("boot did not reconstruct empty firewall")
	}
	// Persistent disable still restores the guard before networking, while the
	// systemd pre-start check refuses to launch its old public listener.
	cfg.EdgeDisabled = true
	if err := RestoreEdgeIngressGuard(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := prepareEdgeStart(context.Background(), cfg, path); err == nil {
		t.Fatal("disabled proxy startup permitted")
	}
	cfg.EdgeDisabled = false
	cfg.EdgeDesired.PublicIngress = nil
	if err := prepareEdgeStart(context.Background(), cfg, path); err == nil {
		t.Fatal("missing public guard permitted")
	}
	cfg.EdgeDesired = desired
	desired.PublicIngress = []config.EdgePublicIngress{{Interface: "wg0", SourceIP: "10.20.0.1", ListenIP: "10.20.0.2"}}
	if err := os.WriteFile(path, []byte("entryPoints:\n  web:\n    address: ':80'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareEdgeStart(context.Background(), cfg, path); err == nil {
		t.Fatal("installed unguarded listener permitted")
	}
	cfg.EdgeIngressGuard = []config.EdgePublicIngress{{Interface: "bad\nrule", SourceIP: "10.20.0.1", ListenIP: "10.20.0.2"}}
	if err := RestoreEdgeIngressGuard(context.Background(), cfg); err == nil {
		t.Fatal("malformed persisted guard accepted")
	}
}

func TestTraefikUnitRunsGuardWithLiteralConfigArgument(t *testing.T) {
	unit, err := edgeTraefikUnit(`/etc/wire warp/$secret%config".yaml`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, `ExecStartPre=/usr/local/bin/wirewarp-agent --restore-edge-ingress --config "/etc/wire warp/$$secret%%config\".yaml"`) {
		t.Fatal(unit)
	}
	if strings.Index(unit, "ExecStartPre=") > strings.Index(unit, "ExecStart=") {
		t.Fatal("guard runs after listener")
	}
	for _, path := range []string{"", "a\nb", "a\x00b"} {
		if _, err := edgeTraefikUnit(path); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
}

func TestPublishedAttachmentReplayAndMutationGuard(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	cfg.EdgeDesired = desired
	cfg.Attachments[0].AttachmentID = "selected"
	cfg.Attachments[0].ServerPublicKey = "old-key"
	old := cfg.Attachments[0]
	if err := validatePublishedAttachmentChange(cfg, old); err != nil {
		t.Fatal("unchanged replay refused:", err)
	}
	for _, change := range []func(*config.AttachmentState){func(a *config.AttachmentState) { a.AttachmentID = "other" }, func(a *config.AttachmentState) { a.WGInterface = "wg1" }, func(a *config.AttachmentState) { a.ServerPublicKey = "new-key" }, func(a *config.AttachmentState) { a.TunnelIP = "10.20.0.3/32" }, func(a *config.AttachmentState) { a.VPSTunnelIP = "10.20.0.4" }, func(a *config.AttachmentState) { a.IsGateway = false }} {
		next := old
		change(&next)
		if err := validatePublishedAttachmentChange(cfg, next); err == nil {
			t.Fatal("published tuple mutation allowed")
		}
	}
	// A pending old guard still protects attachment identity after unpublication
	// was saved but before the old listener was confirmed stopped.
	cfg.EdgeIngressGuard = desired.PublicIngress
	cfg.EdgeDesired = nil
	next := old
	next.ServerPublicKey = "new-key"
	if err := validatePublishedAttachmentChange(cfg, next); err == nil {
		t.Fatal("pending guard bypassed")
	}
	cfg.EdgeIngressGuard = nil
	if err := validatePublishedAttachmentChange(cfg, next); err != nil {
		t.Fatal("unpublished attachment could not change")
	}
}

func TestPublishedAttachmentCommandsRejectBeforeNetworkEffects(t *testing.T) {
	cfg, desired := gatewayRuntimeFixture()
	cfg.EdgeDesired = desired
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg.Attachments[0].AttachmentID = "selected"
	cfg.Attachments[0].ServerPublicKey = key
	cfg.Attachments[0].TunnelIP = "10.20.0.2"
	h := &ClientHandlers{cfg: cfg, cfgPath: filepath.Join(t.TempDir(), "must-not-exist.yaml")}
	p := wgAttachParams{AttachmentID: "selected", WGInterface: "wg0", TunnelIP: "10.20.0.2", VPSTunnelIP: "10.20.0.1", ServerPublicKey: key, ServerEndpoint: "192.0.2.1:51820", LANIP: "192.168.20.110", IsGateway: false}
	raw, _ := json.Marshal(p)
	if _, err := h.handleWGAttach(raw); err == nil || !strings.Contains(err.Error(), "unpublish") {
		t.Fatalf("unsafe attach reached network effects: %v", err)
	}
	raw, _ = json.Marshal(wgDetachParams{AttachmentID: "selected", WGInterface: "wg0"})
	if _, err := h.handleWGDetach(raw); err == nil || !strings.Contains(err.Error(), "unpublish") {
		t.Fatalf("unsafe detach reached network effects: %v", err)
	}
	if _, err := os.Stat(h.cfgPath); !os.IsNotExist(err) {
		t.Fatal("rejected command persisted a mutation")
	}
	if !cfg.Snapshot().Attachments[0].IsGateway {
		t.Fatal("rejected command changed attachment")
	}
}
