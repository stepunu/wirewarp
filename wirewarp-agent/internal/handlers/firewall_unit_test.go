package handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedFirewallRestoreUnitIsRequiredAndDurable(t *testing.T) {
	old := routingUnitFile
	defer func() { routingUnitFile = old }()
	dir := t.TempDir()
	routingUnitFile = filepath.Join(dir, "unit.service")
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$1\" in\n daemon-reload) exit 0 ;;\n enable) if [ \"$UNIT_FAIL\" = yes ]; then echo enable-denied; exit 1; fi; exit 0 ;;\n is-enabled) echo enabled; exit 0 ;;\nesac\nexit 2\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if err := EnsureRoutingUnitContext(context.Background(), "/usr/local/bin/wirewarp-agent", "/etc/wirewarp/agent.yaml"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(routingUnitFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"After=local-fs.target ufw.service netfilter-persistent.service", "Before=network-pre.target sysinit.target", `ExecStart="/usr/local/bin/wirewarp-agent" --restore-routing --config "/etc/wirewarp/agent.yaml"`} {
		if !strings.Contains(string(data), want) {
			t.Fatal("missing boot restore contract", want, string(data))
		}
	}
	t.Setenv("UNIT_FAIL", "yes")
	if err := EnsureRoutingUnitContext(context.Background(), "/usr/local/bin/wirewarp-agent", "/etc/wirewarp/agent.yaml"); err == nil || !strings.Contains(err.Error(), "enable-denied") {
		t.Fatal("unit failure masked", err)
	}
}

func TestOwnedFirewallRestoreUnitRejectsForeignFile(t *testing.T) {
	old := routingUnitFile
	defer func() { routingUnitFile = old }()
	dir := t.TempDir()
	routingUnitFile = filepath.Join(dir, "unit.service")
	foreign := "[Unit]\nDescription=Foreign service\n"
	if err := os.WriteFile(routingUnitFile, []byte(foreign), 0644); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRoutingUnitContext(context.Background(), "/usr/local/bin/wirewarp-agent", "/etc/wirewarp/agent.yaml"); err == nil {
		t.Fatal("foreign unit overwritten")
	}
	data, _ := os.ReadFile(routingUnitFile)
	if string(data) != foreign {
		t.Fatal("foreign unit altered")
	}
}
