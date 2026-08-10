package handlers

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/wireguard"
)

func TestRemovePeerRoutesUsesExactInterfaceRoute(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "ip.log")
	ipPath := filepath.Join(binDir, "ip")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
if [ "$3" = "$IP_ROUTE_MISSING" ]; then
  echo "RTNETLINK answers: No such process"
  exit 2
fi
if [ "$3" = "$IP_ROUTE_FAIL" ]; then
  echo "RTNETLINK answers: Operation not permitted"
  exit 2
fi
exit 0
`
	if err := os.WriteFile(ipPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write ip stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IP_ROUTE_LOG", logPath)
	t.Setenv("IP_ROUTE_MISSING", "192.168.20.0/24")

	err := wireguard.RemovePeerRoutes([]string{"192.168.10.0/24", "192.168.20.0/24"}, "wg7")
	if err != nil {
		t.Fatalf("remove peer routes: %v", err)
	}
	want := []string{
		"route del 192.168.10.0/24 dev wg7",
		"route del 192.168.20.0/24 dev wg7",
	}
	assertIPRouteCalls(t, logPath, want)
}

func TestRemovePeerRoutesAttemptsAllRoutesAndReturnsFailure(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "ip.log")
	ipPath := filepath.Join(binDir, "ip")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
if [ "$3" = "$IP_ROUTE_FAIL" ]; then
  echo "RTNETLINK answers: Operation not permitted"
  exit 2
fi
exit 0
`
	if err := os.WriteFile(ipPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write ip stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IP_ROUTE_LOG", logPath)
	t.Setenv("IP_ROUTE_FAIL", "192.168.10.0/24")

	err := wireguard.RemovePeerRoutes([]string{"192.168.10.0/24", "192.168.20.0/24"}, "wg7")
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("expected route deletion failure, got %v", err)
	}
	want := []string{
		"route del 192.168.10.0/24 dev wg7",
		"route del 192.168.20.0/24 dev wg7",
	}
	assertIPRouteCalls(t, logPath, want)
}

func TestRestartPrunesOldLANRouteBeforeReplayAddsCurrentRoute(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "ip.log")
	ipPath := filepath.Join(binDir, "ip")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
exit 0
`
	if err := os.WriteFile(ipPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write ip stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IP_ROUTE_LOG", logPath)

	oldPeerRoutes := []string{"10.21.0.2/32", "192.168.10.0/24"}
	if err := wireguard.PruneStalePeerRoutes(oldPeerRoutes, "wg0", "10.21.0.0/24"); err != nil {
		t.Fatalf("prune stale routes: %v", err)
	}
	if err := wireguard.EnsurePeerRoute("192.168.20.0/24", "wg0"); err != nil {
		t.Fatalf("add replay route: %v", err)
	}

	want := []string{
		"route del 192.168.10.0/24 dev wg0",
		"route add 192.168.20.0/24 dev wg0",
	}
	assertIPRouteCalls(t, logPath, want)
}

func TestAddRouteIfMissingFailureReturnsAndRetryConverges(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "ip.log")
	countPath := filepath.Join(t.TempDir(), "ip.count")
	ipPath := filepath.Join(binDir, "ip")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
count=0
if [ -f "$IP_ROUTE_COUNT" ]; then read -r count < "$IP_ROUTE_COUNT"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$IP_ROUTE_COUNT"
if [ "$count" = 1 ]; then
  echo "RTNETLINK answers: Operation not permitted"
  exit 2
fi
exit 0
`
	if err := os.WriteFile(ipPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write ip stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IP_ROUTE_LOG", logPath)
	t.Setenv("IP_ROUTE_COUNT", countPath)

	err := wireguard.EnsurePeerRoute("192.168.20.0/24", "wg0")
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("expected route add failure, got %v", err)
	}
	if err := wireguard.EnsurePeerRoute("192.168.20.0/24", "wg0"); err != nil {
		t.Fatalf("retry route add: %v", err)
	}
	assertIPRouteCalls(t, logPath, []string{
		"route add 192.168.20.0/24 dev wg0",
		"route add 192.168.20.0/24 dev wg0",
	})
}

func assertIPRouteCalls(t *testing.T, logPath string, want []string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read ip route log: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ip route calls\nwant %#v\n got %#v", want, got)
	}
}
