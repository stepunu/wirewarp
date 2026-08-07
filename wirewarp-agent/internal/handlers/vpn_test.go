package handlers

import (
	"strings"
	"testing"
)

func TestDefaultRouteIfaceFromRequiresUsableDefaultRoute(t *testing.T) {
	routes := strings.NewReader(`Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
wg0 00000000 0100000A 0001 0 0 0 00000000 0 0 0
eth0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0
`)
	if got := defaultRouteIfaceFrom(routes); got != "eth0" {
		t.Fatalf("default route interface: want eth0, got %q", got)
	}
}

func TestDefaultRouteIfaceFromReturnsEmptyWithoutDefault(t *testing.T) {
	routes := strings.NewReader(`Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0 0001A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0
`)
	if got := defaultRouteIfaceFrom(routes); got != "" {
		t.Fatalf("expected no default route, got %q", got)
	}
}
