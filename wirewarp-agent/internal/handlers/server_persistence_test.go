package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func TestServerMutationHandlersReturnPersistenceFailures(t *testing.T) {
	binDir := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "commands.log")
	iptablesSave := filepath.Join(binDir, "iptables-save")
	if err := os.WriteFile(iptablesSave, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write iptables-save stub: %v", err)
	}
	iptablesPath := filepath.Join(binDir, "iptables")
	if err := os.WriteFile(iptablesPath, []byte(`#!/bin/sh
printf '%s\n' "$*" >> "$COMMAND_LOG"
case " $* " in
  *" -C "*) exit 1 ;;
  *" -A "*|*" -I "*) exit 0 ;;
esac
exit 0
`), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	netfilterPath := filepath.Join(binDir, "netfilter-persistent")
	if err := os.WriteFile(netfilterPath, []byte("#!/bin/sh\necho persist-failed\nexit 2\n"), 0755); err != nil {
		t.Fatalf("write netfilter-persistent stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("COMMAND_LOG", commandLog)
	h := &ServerHandlers{cfg: &config.Config{Server: &config.ServerState{
		Initialized: true,
		PublicIface: "eth0",
		PublicIP:    "203.0.113.2",
	}}}

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "add forward",
			run: func() error {
				_, err := h.handleAddForward(json.RawMessage(`{"protocol":"tcp","public_port":8080,"destination_ip":"10.21.0.2","destination_port":80}`))
				return err
			},
		},
		{
			name: "set LAN SNAT",
			run: func() error {
				_, err := h.handleSetLANSNAT(json.RawMessage(`{"lan_ip":"192.168.10.2","public_ip":"203.0.113.3","action":"set"}`))
				return err
			},
		},
		{
			name: "clear LAN SNAT",
			run: func() error {
				_, err := h.handleSetLANSNAT(json.RawMessage(`{"lan_ip":"192.168.10.2","action":"clear"}`))
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), "persist-failed") {
				t.Fatalf("expected persistence failure, got %v", err)
			}
		})
	}
}
