package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func TestHandleReconcileLANSNATValidatesFullPayloadBeforeMutation(t *testing.T) {
	binDir := t.TempDir()
	mutationLog := filepath.Join(t.TempDir(), "mutation.log")
	iptablesSave := filepath.Join(binDir, "iptables-save")
	if err := os.WriteFile(iptablesSave, []byte(`#!/bin/sh
printf 'iptables-save\n' >> "$MUTATION_LOG"
`), 0755); err != nil {
		t.Fatalf("write iptables-save stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("MUTATION_LOG", mutationLog)
	h := &ServerHandlers{cfg: &config.Config{Server: &config.ServerState{
		Initialized: true,
		PublicIface: "eth0",
	}}}

	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing pins", raw: `{}`},
		{name: "null pins", raw: `{"pins":null}`},
		{name: "invalid later pin", raw: `{"pins":[{"lan_ip":"192.168.10.2","public_ip":"203.0.113.2"},{"lan_ip":"not-an-ip","public_ip":"203.0.113.3"}]}`},
		{name: "duplicate LAN IP", raw: `{"pins":[{"lan_ip":"192.168.10.2","public_ip":"203.0.113.2"},{"lan_ip":"192.168.10.2","public_ip":"203.0.113.3"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := h.handleReconcileLANSNAT(json.RawMessage(tt.raw)); err == nil {
				t.Fatal("expected validation failure")
			}
			if data, err := os.ReadFile(mutationLog); err == nil && len(data) > 0 {
				t.Fatalf("validation mutated iptables: %s", data)
			}
		})
	}
}

func TestHandleReconcileLANSNATEmptyPinsClearsAndSaves(t *testing.T) {
	binDir := t.TempDir()
	mutationLog := filepath.Join(t.TempDir(), "mutation.log")
	iptablesSave := filepath.Join(binDir, "iptables-save")
	if err := os.WriteFile(iptablesSave, []byte(`#!/bin/sh
printf 'iptables-save %s\n' "$*" >> "$MUTATION_LOG"
`), 0755); err != nil {
		t.Fatalf("write iptables-save stub: %v", err)
	}
	netfilterPersistent := filepath.Join(binDir, "netfilter-persistent")
	if err := os.WriteFile(netfilterPersistent, []byte(`#!/bin/sh
printf 'netfilter-persistent %s\n' "$*" >> "$MUTATION_LOG"
`), 0755); err != nil {
		t.Fatalf("write netfilter-persistent stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("MUTATION_LOG", mutationLog)
	h := &ServerHandlers{cfg: &config.Config{Server: &config.ServerState{
		Initialized: true,
		PublicIface: "eth0",
	}}}

	output, err := h.handleReconcileLANSNAT(json.RawMessage(`{"pins":[]}`))
	if err != nil {
		t.Fatalf("reconcile empty LAN SNAT: %v", err)
	}
	if output != "reconciled 0 LAN SNAT pin(s)" {
		t.Fatalf("unexpected output: %q", output)
	}
	data, err := os.ReadFile(mutationLog)
	if err != nil {
		t.Fatalf("read mutation log: %v", err)
	}
	want := "iptables-save -t nat\nnetfilter-persistent save"
	if strings.TrimSpace(string(data)) != want {
		t.Fatalf("mutations\nwant %q\n got %q", want, strings.TrimSpace(string(data)))
	}
}

func TestHandleReconcileLANSNATReturnsSaveFailure(t *testing.T) {
	binDir := t.TempDir()
	iptablesSave := filepath.Join(binDir, "iptables-save")
	if err := os.WriteFile(iptablesSave, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write iptables-save stub: %v", err)
	}
	netfilterPersistent := filepath.Join(binDir, "netfilter-persistent")
	if err := os.WriteFile(netfilterPersistent, []byte("#!/bin/sh\necho save failed\nexit 2\n"), 0755); err != nil {
		t.Fatalf("write netfilter-persistent stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	h := &ServerHandlers{cfg: &config.Config{Server: &config.ServerState{
		Initialized: true,
		PublicIface: "eth0",
	}}}

	_, err := h.handleReconcileLANSNAT(json.RawMessage(`{"pins":[]}`))
	if err == nil || !strings.Contains(err.Error(), "save failed") {
		t.Fatalf("expected save failure, got %v", err)
	}
}

func TestHandleWGInitCleansOldPublicIfaceBeforeSetupAndRetainsConfigOnFailure(t *testing.T) {
	binDir := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "commands.log")
	iptablesSave := filepath.Join(binDir, "iptables-save")
	if err := os.WriteFile(iptablesSave, []byte(`#!/bin/sh
printf '%s\n' '-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10'
`), 0755); err != nil {
		t.Fatalf("write iptables-save stub: %v", err)
	}
	iptablesPath := filepath.Join(binDir, "iptables")
	if err := os.WriteFile(iptablesPath, []byte(`#!/bin/sh
printf 'iptables %s\n' "$*" >> "$COMMAND_LOG"
case " $* " in
  *" -D POSTROUTING -s 192.168.10.2/32 "*) echo cleanup-failed; exit 2 ;;
  *" -C "*) exit 1 ;;
esac
exit 0
`), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	wgPath := filepath.Join(binDir, "wg")
	if err := os.WriteFile(wgPath, []byte(`#!/bin/sh
printf 'wg %s\n' "$*" >> "$COMMAND_LOG"
exit 2
`), 0755); err != nil {
		t.Fatalf("write wg stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("COMMAND_LOG", commandLog)

	oldServer := &config.ServerState{
		Initialized: true,
		WGInterface: "wg0",
		PublicIface: "eth0",
		PublicIP:    "203.0.113.10",
	}
	h := &ServerHandlers{
		cfgPath: filepath.Join(t.TempDir(), "agent.yaml"),
		cfg:     &config.Config{Server: oldServer},
	}
	raw := json.RawMessage(`{
		"wg_interface":"wg9",
		"wg_port":51820,
		"tunnel_network":"10.20.0.0/24",
		"tunnel_ip":"10.20.0.1",
		"public_iface":"eth1",
		"public_ip":"203.0.113.20"
	}`)

	_, err := h.handleWGInit(raw)
	if err == nil || !strings.Contains(err.Error(), "cleanup-failed") {
		t.Fatalf("expected old interface cleanup failure, got %v", err)
	}
	if h.cfg.Server != oldServer || h.cfg.Server.PublicIface != "eth0" {
		t.Fatalf("saved server config changed after cleanup failure: %#v", h.cfg.Server)
	}
	data, readErr := os.ReadFile(commandLog)
	if readErr != nil {
		t.Fatalf("read command log: %v", readErr)
	}
	commands := string(data)
	if strings.Contains(commands, "wg ") {
		t.Fatalf("WireGuard setup ran before cleanup succeeded:\n%s", commands)
	}
	if !strings.Contains(commands, "iptables -t nat -D POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT") {
		t.Fatalf("old interface cleanup did not run:\n%s", commands)
	}
}

func TestConfigureWGInitRuntimeReturnsNewMasqueradeFailure(t *testing.T) {
	binDir := t.TempDir()
	sysctlPath := filepath.Join(binDir, "sysctl")
	if err := os.WriteFile(sysctlPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write sysctl stub: %v", err)
	}
	iptablesPath := filepath.Join(binDir, "iptables")
	if err := os.WriteFile(iptablesPath, []byte(`#!/bin/sh
case "$*" in
  "-t nat -C POSTROUTING -o eth1 -m comment --comment wirewarp-server-masquerade -j MASQUERADE") exit 1 ;;
  "-t nat -A POSTROUTING -o eth1 -m comment --comment wirewarp-server-masquerade -j MASQUERADE") echo masquerade-failed; exit 2 ;;
esac
exit 64
`), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	t.Setenv("PATH", binDir)

	err := configureWGInitRuntime(wgInitParams{Interface: "wg0", PublicIface: "eth1"})
	if err == nil || !strings.Contains(err.Error(), "masquerade-failed") {
		t.Fatalf("expected new masquerade failure, got %v", err)
	}
}

func TestSaveWGInitStateRestoresOldStateOnConfigSaveFailure(t *testing.T) {
	oldServer := &config.ServerState{
		Initialized: true,
		WGInterface: "wg0",
		PublicIface: "eth0",
	}
	nextServer := &config.ServerState{
		Initialized: true,
		WGInterface: "wg1",
		PublicIface: "eth1",
	}
	h := &ServerHandlers{
		cfgPath: t.TempDir(),
		cfg:     &config.Config{Server: oldServer},
	}

	err := h.saveWGInitState(nextServer)
	if err == nil {
		t.Fatal("expected config save failure")
	}
	if h.cfg.Server != oldServer {
		t.Fatalf("in-memory server state was not restored: %#v", h.cfg.Server)
	}
}
