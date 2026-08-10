package wireguard

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRoutesToRemoveBeforePeerUpdate(t *testing.T) {
	current := Peer{
		PublicKey: "peer-a",
		TunnelIP:  "10.21.0.2",
		AllowedIPs: []string{
			"10.21.0.2/32",
			"192.168.10.0/24",
		},
	}

	tests := []struct {
		name    string
		updated Peer
		want    []string
	}{
		{
			name: "gateway becomes client",
			updated: Peer{
				PublicKey:  "peer-a",
				TunnelIP:   "10.21.0.2",
				AllowedIPs: []string{"10.21.0.2/32"},
			},
			want: []string{"192.168.10.0/24"},
		},
		{
			name: "gateway network changes",
			updated: Peer{
				PublicKey: "peer-a",
				TunnelIP:  "10.21.0.2",
				AllowedIPs: []string{
					"10.21.0.2/32",
					"192.168.20.0/24",
				},
			},
			want: []string{"192.168.10.0/24"},
		},
		{
			name:    "authoritative replay is unchanged",
			updated: current,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{peers: map[string]Peer{current.PublicKey: current}}
			got := server.RoutesToRemoveBeforePeerUpdate(tt.updated)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("routes to remove\nwant %#v\n got %#v", tt.want, got)
			}
		})
	}
}

func TestRoutesToRemoveBeforePeerRemoval(t *testing.T) {
	removed := Peer{
		PublicKey: "peer-a",
		TunnelIP:  "10.21.0.2",
		AllowedIPs: []string{
			"10.21.0.2/32",
			"192.168.10.0/24",
			"192.168.10.0/24",
		},
	}

	t.Run("removes the last owner of a LAN route", func(t *testing.T) {
		server := &Server{peers: map[string]Peer{removed.PublicKey: removed}}
		got, err := server.RoutesToRemoveBeforePeerRemoval(removed.PublicKey)
		if err != nil {
			t.Fatalf("route plan: %v", err)
		}
		want := []string{"192.168.10.0/24"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("routes to remove\nwant %#v\n got %#v", want, got)
		}
	})

	t.Run("keeps a route required by another peer", func(t *testing.T) {
		shared := Peer{
			PublicKey:  "peer-b",
			TunnelIP:   "10.21.0.3",
			AllowedIPs: []string{"192.168.10.7/24"},
		}
		server := &Server{peers: map[string]Peer{
			removed.PublicKey: removed,
			shared.PublicKey:  shared,
		}}
		got, err := server.RoutesToRemoveBeforePeerRemoval(removed.PublicKey)
		if err != nil {
			t.Fatalf("route plan: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("shared route must remain, got removals %#v", got)
		}
	})
}

func TestAddPeerFailurePreservesOldPeerState(t *testing.T) {
	old := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"10.21.0.2/32", "192.168.10.0/24"},
	}
	updated := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"10.21.0.2/32", "192.168.20.0/24"},
	}

	for _, failure := range []string{"write", "sync"} {
		t.Run(failure, func(t *testing.T) {
			server := &Server{peers: map[string]Peer{old.PublicKey: old}}
			var writes []map[string]Peer
			writeFailed := false
			server.peerConfigWriter = func(peers map[string]Peer) error {
				if failure == "write" && !writeFailed {
					writeFailed = true
					return errors.New("write failed")
				}
				writes = append(writes, clonePeers(peers))
				return nil
			}
			syncCalls := 0
			server.peerConfigSyncer = func() error {
				syncCalls++
				if failure == "sync" && syncCalls == 1 {
					return errors.New("sync failed")
				}
				return nil
			}

			if err := server.AddPeer(updated); err == nil {
				t.Fatal("expected peer update failure")
			}
			if !reflect.DeepEqual(server.peers, map[string]Peer{old.PublicKey: old}) {
				t.Fatalf("old peer state was not preserved: %#v", server.peers)
			}
			wantCleanup := []string{"192.168.10.0/24"}
			if got := server.RoutesToRemoveBeforePeerUpdate(updated); !reflect.DeepEqual(got, wantCleanup) {
				t.Fatalf("retry cleanup plan\nwant %#v\n got %#v", wantCleanup, got)
			}
			if failure == "sync" {
				if len(writes) != 2 || !reflect.DeepEqual(writes[1], map[string]Peer{old.PublicKey: old}) {
					t.Fatalf("old config was not restored after sync failure: %#v", writes)
				}
			}
			if err := server.AddPeer(updated); err != nil {
				t.Fatalf("peer update retry: %v", err)
			}
			if !reflect.DeepEqual(server.peers, map[string]Peer{updated.PublicKey: updated}) {
				t.Fatalf("retry did not commit updated peer: %#v", server.peers)
			}
		})
	}
}

func TestRemovePeerFailurePreservesOldPeerState(t *testing.T) {
	old := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"10.21.0.2/32", "192.168.10.0/24"},
	}

	for _, failure := range []string{"write", "sync"} {
		t.Run(failure, func(t *testing.T) {
			server := &Server{peers: map[string]Peer{old.PublicKey: old}}
			var writes []map[string]Peer
			writeFailed := false
			server.peerConfigWriter = func(peers map[string]Peer) error {
				if failure == "write" && !writeFailed {
					writeFailed = true
					return errors.New("write failed")
				}
				writes = append(writes, clonePeers(peers))
				return nil
			}
			syncCalls := 0
			server.peerConfigSyncer = func() error {
				syncCalls++
				if failure == "sync" && syncCalls == 1 {
					return errors.New("sync failed")
				}
				return nil
			}

			if err := server.RemovePeer(old.PublicKey); err == nil {
				t.Fatal("expected peer removal failure")
			}
			if !reflect.DeepEqual(server.peers, map[string]Peer{old.PublicKey: old}) {
				t.Fatalf("old peer state was not preserved: %#v", server.peers)
			}
			wantCleanup := []string{"192.168.10.0/24"}
			got, err := server.RoutesToRemoveBeforePeerRemoval(old.PublicKey)
			if err != nil || !reflect.DeepEqual(got, wantCleanup) {
				t.Fatalf("removal retry cleanup plan: got %#v, err %v", got, err)
			}
			if failure == "sync" {
				if len(writes) != 2 || !reflect.DeepEqual(writes[1], map[string]Peer{old.PublicKey: old}) {
					t.Fatalf("old config was not restored after sync failure: %#v", writes)
				}
			}
			if err := server.RemovePeer(old.PublicKey); err != nil {
				t.Fatalf("peer removal retry: %v", err)
			}
			if len(server.peers) != 0 {
				t.Fatalf("retry did not remove peer: %#v", server.peers)
			}
		})
	}
}

func TestPeerMutationFailureRestoresRemovedOldRoutes(t *testing.T) {
	old := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"10.21.0.2/32", "192.168.10.0/24"},
	}
	updated := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"10.21.0.2/32", "192.168.20.0/24"},
	}

	for _, operation := range []string{"update", "remove"} {
		for _, failure := range []string{"write", "sync"} {
			t.Run(operation+"-"+failure, func(t *testing.T) {
				logPath := installPeerRouteIPStub(t, "")
				server := &Server{peers: map[string]Peer{old.PublicKey: old}}
				failed := false
				server.peerConfigWriter = func(map[string]Peer) error {
					if failure == "write" && !failed {
						failed = true
						return errors.New("write failed")
					}
					return nil
				}
				syncCalls := 0
				server.peerConfigSyncer = func() error {
					syncCalls++
					if failure == "sync" && syncCalls == 1 {
						return errors.New("sync failed")
					}
					return nil
				}

				var err error
				if operation == "update" {
					err = server.AddPeerAndRoutes(updated, "wg0")
				} else {
					err = server.RemovePeerAndRoutes(old.PublicKey, "wg0")
				}
				if err == nil || !strings.Contains(err.Error(), failure+" failed") {
					t.Fatalf("expected peer %s failure, got %v", operation, err)
				}
				if !reflect.DeepEqual(server.peers, map[string]Peer{old.PublicKey: old}) {
					t.Fatalf("old peer state changed: %#v", server.peers)
				}
				assertPeerRouteLog(t, logPath, []string{
					"route del 192.168.10.0/24 dev wg0",
					"route add 192.168.10.0/24 dev wg0",
				})
			})
		}
	}
}

func TestAddPeerAndRoutesRollsBackAfterNewRouteFailureAndRetryConverges(t *testing.T) {
	old := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"10.21.0.2/32", "192.168.10.0/24"},
	}
	updated := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"10.21.0.2/32", "192.168.20.0/24"},
	}
	logPath := installPeerRouteIPStub(t, "192.168.20.0/24")
	server := &Server{
		peers:            map[string]Peer{old.PublicKey: old},
		peerConfigWriter: func(map[string]Peer) error { return nil },
		peerConfigSyncer: func() error { return nil },
	}

	err := server.AddPeerAndRoutes(updated, "wg0")
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("expected route add failure, got %v", err)
	}
	if !reflect.DeepEqual(server.peers, map[string]Peer{old.PublicKey: old}) {
		t.Fatalf("route failure did not restore old peer: %#v", server.peers)
	}
	if err := server.AddPeerAndRoutes(updated, "wg0"); err != nil {
		t.Fatalf("peer update retry: %v", err)
	}
	if !reflect.DeepEqual(server.peers, map[string]Peer{updated.PublicKey: updated}) {
		t.Fatalf("retry did not commit updated peer: %#v", server.peers)
	}
	assertPeerRouteLog(t, logPath, []string{
		"route del 192.168.10.0/24 dev wg0",
		"route add 192.168.20.0/24 dev wg0",
		"route del 192.168.20.0/24 dev wg0",
		"route add 192.168.10.0/24 dev wg0",
		"route del 192.168.10.0/24 dev wg0",
		"route add 192.168.20.0/24 dev wg0",
	})
}

func TestPeerMutationRestoresFullPlanAfterPartialRouteDelete(t *testing.T) {
	old := Peer{
		PublicKey:  "peer-a",
		TunnelIP:   "10.21.0.2",
		AllowedIPs: []string{"192.168.10.0/24", "192.168.11.0/24"},
	}
	updated := Peer{PublicKey: "peer-a", TunnelIP: "10.21.0.2"}

	for _, operation := range []string{"update", "remove"} {
		t.Run(operation, func(t *testing.T) {
			binDir := t.TempDir()
			logPath := filepath.Join(t.TempDir(), "ip.log")
			ipPath := filepath.Join(binDir, "ip")
			stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
if [ "$2" = "del" ] && [ "$3" = "192.168.11.0/24" ]; then
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
			peerMutationCalled := false
			server := &Server{
				peers: map[string]Peer{old.PublicKey: old},
				peerConfigWriter: func(map[string]Peer) error {
					peerMutationCalled = true
					return nil
				},
			}

			var err error
			if operation == "update" {
				err = server.AddPeerAndRoutes(updated, "wg0")
			} else {
				err = server.RemovePeerAndRoutes(old.PublicKey, "wg0")
			}
			if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
				t.Fatalf("expected partial route deletion failure, got %v", err)
			}
			if peerMutationCalled {
				t.Fatal("peer config changed after route deletion failure")
			}
			if !reflect.DeepEqual(server.peers, map[string]Peer{old.PublicKey: old}) {
				t.Fatalf("old peer state changed: %#v", server.peers)
			}
			assertPeerRouteLog(t, logPath, []string{
				"route del 192.168.10.0/24 dev wg0",
				"route del 192.168.11.0/24 dev wg0",
				"route add 192.168.10.0/24 dev wg0",
				"route add 192.168.11.0/24 dev wg0",
			})
		})
	}
}

func TestPruneFailureRetainsCapturedOwnershipForRetry(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "ip.log")
	failMarker := filepath.Join(t.TempDir(), "failed.once")
	ipPath := filepath.Join(binDir, "ip")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
if [ ! -f "$FAIL_MARKER" ]; then
  : > "$FAIL_MARKER"
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
	t.Setenv("FAIL_MARKER", failMarker)
	server := &Server{
		cfg: ServerConfig{
			Interface:     "wg0",
			TunnelNetwork: "10.21.0.0/24",
		},
		startupPeerRoutes: []string{"192.168.10.0/24"},
	}

	if err := server.PruneStalePeerRoutes(); err == nil {
		t.Fatal("expected first prune to fail")
	}
	if err := server.PruneStalePeerRoutes(); err != nil {
		t.Fatalf("prune retry: %v", err)
	}
	assertPeerRouteLog(t, logPath, []string{
		"route del 192.168.10.0/24 dev wg0",
		"route del 192.168.10.0/24 dev wg0",
	})
}

func TestColdBootPruneTreatsAbsentWireGuardInterfaceAsClean(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "ip.log")
	ipPath := filepath.Join(binDir, "ip")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
echo 'Cannot find device "wg0"'
exit 1
`
	if err := os.WriteFile(ipPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write ip stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IP_ROUTE_LOG", logPath)

	err := PruneStalePeerRoutes([]string{"10.21.0.2/32", "192.168.10.0/24"}, "wg0", "10.21.0.0/24")
	if err != nil {
		t.Fatalf("cold-boot stale route prune: %v", err)
	}
	assertPeerRouteLog(t, logPath, []string{
		"route del 192.168.10.0/24 dev wg0",
	})
}

func installPeerRouteIPStub(t *testing.T, failAddOnce string) string {
	t.Helper()
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "ip.log")
	failMarker := filepath.Join(t.TempDir(), "failed.once")
	ipPath := filepath.Join(binDir, "ip")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IP_ROUTE_LOG"
if [ "$2" = "add" ] && [ "$3" = "$FAIL_ADD_ONCE" ] && [ ! -f "$FAIL_MARKER" ]; then
  : > "$FAIL_MARKER"
  echo "RTNETLINK answers: Operation not permitted"
  exit 2
fi
if [ "$2" = "del" ] && [ "$3" = "$FAIL_ADD_ONCE" ]; then
  echo "RTNETLINK answers: No such process"
  exit 2
fi
exit 0
`
	if err := os.WriteFile(ipPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write ip stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IP_ROUTE_LOG", logPath)
	t.Setenv("FAIL_ADD_ONCE", failAddOnce)
	t.Setenv("FAIL_MARKER", failMarker)
	return logPath
}

func assertPeerRouteLog(t *testing.T, logPath string, want []string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read route log: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("route calls\nwant %#v\n got %#v", want, got)
	}
}

func TestParseStartupPeerRoutesUsesOnlyPriorPeerAllowedIPs(t *testing.T) {
	config := `[Interface]
Address = 10.21.0.1/24
PostUp = ip route add 172.16.0.0/16 dev wg0

[Peer]
PublicKey = peer-a
AllowedIPs = 10.21.0.2/32, 192.168.10.0/24

[Peer]
PublicKey = peer-b
AllowedIPs = 10.21.0.3/32, 192.168.10.7/24 # duplicate LAN network
`
	want := []string{"10.21.0.2/32", "192.168.10.0/24", "10.21.0.3/32"}
	got, err := parseStartupPeerRoutes(config)
	if err != nil {
		t.Fatalf("parse startup routes: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("startup peer routes\nwant %#v\n got %#v", want, got)
	}
}
