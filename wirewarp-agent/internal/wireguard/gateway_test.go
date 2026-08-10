package wireguard

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGatewayLANMasqueradeRuleCoversAllTunnelIngress(t *testing.T) {
	cfg := GatewayConfig{
		TunnelIface: "wg1",
		LANIface:    "eth0",
		Fwmark:      "0x102",
		WGSubnet:    "10.22.0.0/24",
	}

	got := gatewayLANMasqueradeRule(cfg)
	want := []string{
		"-t", "nat", "POSTROUTING",
		"-m", "connmark", "--mark", "0x102",
		"-o", "eth0",
		"-j", "MASQUERADE",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway LAN masquerade rule\nwant %#v\n got %#v", want, got)
	}
	if !shouldApplyGatewayLANMasquerade(cfg) {
		t.Fatalf("expected non-public tunnel mark %s to allow LAN masquerade", cfg.Fwmark)
	}
}

func TestGatewayLANMasqueradeSkippedForPublicInboundTunnelMark(t *testing.T) {
	cfg := GatewayConfig{
		TunnelIface: "wg0",
		LANIface:    "eth0",
		Fwmark:      "0x101",
		WGSubnet:    "10.21.0.0/24",
	}

	if shouldApplyGatewayLANMasquerade(cfg) {
		t.Fatalf("expected public inbound tunnel mark %s to skip LAN masquerade", cfg.Fwmark)
	}
}

func TestPublicInboundTunnelMarkAcceptsDecimalConfigValue(t *testing.T) {
	cfg := GatewayConfig{
		TunnelIface: "wg0",
		LANIface:    "eth0",
		Fwmark:      "257",
	}

	if shouldApplyGatewayLANMasquerade(cfg) {
		t.Fatalf("expected decimal public inbound tunnel mark %s to skip LAN masquerade", cfg.Fwmark)
	}
}

func TestRemoveGatewayOnlyRulesDeletesBothDirectionsAndIsIdempotent(t *testing.T) {
	logPath, statePath := installGatewayOnlyIPTablesStub(t)
	cfg := GatewayConfig{TunnelIface: "wg1", LANIface: "eth0"}

	if err := RemoveGatewayOnlyRules(cfg); err != nil {
		t.Fatalf("remove gateway-only rules: %v", err)
	}
	if err := RemoveGatewayOnlyRules(cfg); err != nil {
		t.Fatalf("idempotent gateway-only cleanup: %v", err)
	}
	want := []string{
		"-C DOCKER-USER -i wg1 -o eth0 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-D DOCKER-USER -i wg1 -o eth0 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i wg1 -o eth0 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i eth0 -o wg1 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-D DOCKER-USER -i eth0 -o wg1 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i eth0 -o wg1 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i wg1 -o eth0 -j ACCEPT",
		"-D DOCKER-USER -i wg1 -o eth0 -j ACCEPT",
		"-C DOCKER-USER -i wg1 -o eth0 -j ACCEPT",
		"-C DOCKER-USER -i eth0 -o wg1 -j ACCEPT",
		"-D DOCKER-USER -i eth0 -o wg1 -j ACCEPT",
		"-C DOCKER-USER -i eth0 -o wg1 -j ACCEPT",
		"-C DOCKER-USER -i wg1 -o eth0 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i eth0 -o wg1 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i wg1 -o eth0 -j ACCEPT",
		"-C DOCKER-USER -i eth0 -o wg1 -j ACCEPT",
	}
	assertGatewayOnlyIPTablesLog(t, logPath, want)
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read gateway rule state: %v", err)
	}
	wantOperator := `-A DOCKER-USER -i wg1 -o eth0 -m comment --comment operator-rule -j ACCEPT`
	if strings.TrimSpace(string(data)) != wantOperator {
		t.Fatalf("operator rule changed or removed:\n%s", data)
	}
}

func TestRemoveGatewayOnlyRulesAttemptsBothDirectionsAfterFailure(t *testing.T) {
	logPath, _ := installGatewayOnlyIPTablesStub(t)
	t.Setenv("DOCKER_FAIL_DIRECTION", "inbound")

	err := RemoveGatewayOnlyRules(GatewayConfig{TunnelIface: "wg1", LANIface: "eth0"})
	if err == nil || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("expected inbound deletion failure, got %v", err)
	}
	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("read iptables log: %v", readErr)
	}
	for _, call := range []string{
		"-D DOCKER-USER -i wg1 -o eth0 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-D DOCKER-USER -i eth0 -o wg1 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-D DOCKER-USER -i eth0 -o wg1 -j ACCEPT",
	} {
		if !strings.Contains(string(data), call) {
			t.Fatalf("cleanup did not attempt %q after failure:\n%s", call, data)
		}
	}
}

func TestPlainClientReplayRemovesPersistedGatewayRules(t *testing.T) {
	_, statePath := installGatewayOnlyIPTablesStub(t)
	cfg := GatewayConfig{TunnelIface: "wg1", LANIface: "eth0", IsGateway: false}

	if err := applyGatewayDockerRules(cfg); err != nil {
		t.Fatalf("plain-client gateway rule replay: %v", err)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read gateway rule state: %v", err)
	}
	wantOperator := `-A DOCKER-USER -i wg1 -o eth0 -m comment --comment operator-rule -j ACCEPT`
	if strings.TrimSpace(string(data)) != wantOperator {
		t.Fatalf("plain-client replay left managed rules or changed operator rule:\n%s", data)
	}
}

func installGatewayOnlyIPTablesStub(t *testing.T) (string, string) {
	t.Helper()
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "iptables.log")
	statePath := filepath.Join(t.TempDir(), "iptables.state")
	initialState := `-A DOCKER-USER -i wg1 -o eth0 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT
-A DOCKER-USER -i eth0 -o wg1 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT
-A DOCKER-USER -i wg1 -o eth0 -j ACCEPT
-A DOCKER-USER -i eth0 -o wg1 -j ACCEPT
-A DOCKER-USER -i wg1 -o eth0 -m comment --comment operator-rule -j ACCEPT
`
	if err := os.WriteFile(statePath, []byte(initialState), 0600); err != nil {
		t.Fatalf("write initial iptables state: %v", err)
	}
	iptablesPath := filepath.Join(binDir, "iptables")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IPTABLES_LOG"
action="$1"
shift
rule="-A $*"
case "$rule" in
  *"-i wg1 -o eth0"*) direction=inbound ;;
  *"-i eth0 -o wg1"*) direction=outbound ;;
  *) exit 64 ;;
esac
case "$action" in
  -C)
    while IFS= read -r line; do
      if [ "$line" = "$rule" ]; then exit 0; fi
    done < "$DOCKER_RULE_STATE"
    exit 1
    ;;
  -D)
    if [ "$DOCKER_FAIL_DIRECTION" = "$direction" ]; then
      echo delete failed
      exit 2
    fi
    tmp="$DOCKER_RULE_STATE.tmp"
    found=0
    : > "$tmp"
    while IFS= read -r line; do
      if [ "$found" = 0 ] && [ "$line" = "$rule" ]; then
        found=1
      else
        printf '%s\n' "$line" >> "$tmp"
      fi
    done < "$DOCKER_RULE_STATE"
    mv "$tmp" "$DOCKER_RULE_STATE"
    if [ "$found" = 1 ]; then exit 0; fi
    exit 1
    ;;
esac
exit 64
`
	if err := os.WriteFile(iptablesPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("IPTABLES_LOG", logPath)
	t.Setenv("DOCKER_RULE_STATE", statePath)
	return logPath, statePath
}

func assertGatewayOnlyIPTablesLog(t *testing.T, logPath string, want []string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read iptables log: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("iptables calls\nwant %#v\n got %#v", want, got)
	}
}
