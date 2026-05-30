package wireguard

import (
	"reflect"
	"testing"
)

func TestGatewayLANMasqueradeRuleCoversAllTunnelIngress(t *testing.T) {
	cfg := GatewayConfig{
		TunnelIface: "wg1",
		LANIface:    "eth0",
		WGSubnet:    "10.22.0.0/24",
	}

	got := gatewayLANMasqueradeRule(cfg)
	want := []string{
		"-t", "nat", "POSTROUTING",
		"-i", "wg1",
		"-o", "eth0",
		"-j", "MASQUERADE",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway LAN masquerade rule\nwant %#v\n got %#v", want, got)
	}
}
