package wireguard

import (
	"reflect"
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
