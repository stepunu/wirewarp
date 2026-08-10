package iptables

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLANSNATDeleteRulesMatchesOwnedLegacyAndTaggedRules(t *testing.T) {
	saveOutput := `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
-A POSTROUTING -s 192.168.10.3/32 -o eth0 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.11
-A POSTROUTING -s 192.168.10.4/32 -o eth1 -j SNAT --to-source 203.0.113.12
-A POSTROUTING -s 192.168.10.5/32 -o eth0 -m comment --comment "operator-rule" -j SNAT --to-source 203.0.113.13
-A POSTROUTING -s 192.168.20.0/24 -o eth0 -j SNAT --to-source 203.0.113.14
-A OUTPUT -s 192.168.10.6/32 -o eth0 -j SNAT --to-source 203.0.113.15
-A POSTROUTING -o eth0 -j MASQUERADE
`
	want := [][]string{
		{"-t", "nat", "-D", "POSTROUTING", "-s", "192.168.10.2/32", "-o", "eth0", "-j", "SNAT", "--to-source", "203.0.113.10"},
		{"-t", "nat", "-D", "POSTROUTING", "-s", "192.168.10.3/32", "-o", "eth0", "-m", "comment", "--comment", "wirewarp-lan-snat", "-j", "SNAT", "--to-source", "203.0.113.11"},
	}
	if got := lanSNATDeleteRules(saveOutput, "eth0"); !reflect.DeepEqual(got, want) {
		t.Fatalf("delete rules\nwant %#v\n got %#v", want, got)
	}
}

func TestReconcileLANSNATReplacesOwnedRulesWithSortedDesiredState(t *testing.T) {
	logPath := installSNATCommandStubs(t, `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
-A POSTROUTING -s 192.168.10.3/32 -o eth0 -m comment --comment "wirewarp-lan-snat" -j SNAT --to-source 203.0.113.11
-A POSTROUTING -s 192.168.99.2/32 -o eth1 -j SNAT --to-source 203.0.113.99
`, "")

	err := ReconcileLANSNAT("eth0", []LANSNATPin{
		{LANIP: "192.168.10.3", PublicIP: "203.0.113.31"},
		{LANIP: "192.168.20.2", PublicIP: "203.0.113.22"},
	})
	if err != nil {
		t.Fatalf("reconcile LAN SNAT: %v", err)
	}
	want := []string{
		"-t nat -D POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10",
		"-t nat -D POSTROUTING -s 192.168.10.3/32 -o eth0 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.11",
		"-t nat -C POSTROUTING -o eth0 -s 192.168.10.3 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.31",
		"-t nat -I POSTROUTING -o eth0 -s 192.168.10.3 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.31",
		"-t nat -C POSTROUTING -o eth0 -s 192.168.20.2 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.22",
		"-t nat -I POSTROUTING -o eth0 -s 192.168.20.2 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.22",
	}
	assertSNATCommandLog(t, logPath, want)
}

func TestReconcileLANSNATEmptyDesiredStateClearsOwnedRules(t *testing.T) {
	logPath := installSNATCommandStubs(t, `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
-A POSTROUTING -o eth0 -j MASQUERADE
`, "")

	if err := ReconcileLANSNAT("eth0", []LANSNATPin{}); err != nil {
		t.Fatalf("clear LAN SNAT: %v", err)
	}
	want := []string{
		"-t nat -D POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10",
	}
	assertSNATCommandLog(t, logPath, want)
}

func TestReconcileLANSNATCleanupFailureAttemptsAllAndSkipsAdds(t *testing.T) {
	logPath := installSNATCommandStubs(t, `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
-A POSTROUTING -s 192.168.10.3/32 -o eth0 -j SNAT --to-source 203.0.113.11
`, "192.168.10.2/32")

	err := ReconcileLANSNAT("eth0", []LANSNATPin{{LANIP: "192.168.20.2", PublicIP: "203.0.113.22"}})
	if err == nil || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("expected cleanup failure, got %v", err)
	}
	want := []string{
		"-t nat -D POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10",
		"-t nat -D POSTROUTING -s 192.168.10.3/32 -o eth0 -j SNAT --to-source 203.0.113.11",
	}
	assertSNATCommandLog(t, logPath, want)
}

func TestReconcileLANSNATReturnsAddFailure(t *testing.T) {
	logPath := installSNATCommandStubs(t, "", "insert")
	err := ReconcileLANSNAT("eth0", []LANSNATPin{{LANIP: "192.168.20.2", PublicIP: "203.0.113.22"}})
	if err == nil || !strings.Contains(err.Error(), "insert failed") {
		t.Fatalf("expected add failure, got %v", err)
	}
	want := []string{
		"-t nat -C POSTROUTING -o eth0 -s 192.168.20.2 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.22",
		"-t nat -I POSTROUTING -o eth0 -s 192.168.20.2 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.22",
	}
	assertSNATCommandLog(t, logPath, want)
}

func TestCleanupServerNATRemovesLegacyTaggedAndExactMasquerade(t *testing.T) {
	logPath := installSNATCommandStubs(t, `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
-A POSTROUTING -s 192.168.10.3/32 -o eth0 -m comment --comment "wirewarp-lan-snat" -j SNAT --to-source 203.0.113.11
-A POSTROUTING -s 192.168.10.4/32 -o eth1 -j SNAT --to-source 203.0.113.12
-A POSTROUTING -o eth0 -j MASQUERADE
-A POSTROUTING -o eth0 -m comment --comment "operator-masquerade" -j MASQUERADE
-A POSTROUTING -o eth0 -m comment --comment "wirewarp-server-masquerade" -j MASQUERADE
-A POSTROUTING -o eth1 -j MASQUERADE
`, "")
	t.Setenv("IPTABLES_MASQUERADE_PRESENT", "1")

	if err := CleanupServerNAT("eth0"); err != nil {
		t.Fatalf("clean up server NAT: %v", err)
	}
	want := []string{
		"-t nat -D POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10",
		"-t nat -D POSTROUTING -s 192.168.10.3/32 -o eth0 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.11",
		"-t nat -C POSTROUTING -o eth0 -m comment --comment wirewarp-server-masquerade -j MASQUERADE",
		"-t nat -D POSTROUTING -o eth0 -m comment --comment wirewarp-server-masquerade -j MASQUERADE",
	}
	assertSNATCommandLog(t, logPath, want)
}

func TestCleanupServerNATIsHealthyWhenRulesAreAbsent(t *testing.T) {
	logPath := installSNATCommandStubs(t, "", "")
	t.Setenv("IPTABLES_MASQUERADE_PRESENT", "0")

	if err := CleanupServerNAT("eth0"); err != nil {
		t.Fatalf("clean up absent server NAT: %v", err)
	}
	assertSNATCommandLog(t, logPath, []string{
		"-t nat -C POSTROUTING -o eth0 -m comment --comment wirewarp-server-masquerade -j MASQUERADE",
	})
}

func TestCleanupServerNATReportsFailureAndAttemptsMasquerade(t *testing.T) {
	logPath := installSNATCommandStubs(t, `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
`, "192.168.10.2/32")
	t.Setenv("IPTABLES_MASQUERADE_PRESENT", "1")

	err := CleanupServerNAT("eth0")
	if err == nil || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("expected cleanup failure, got %v", err)
	}
	want := []string{
		"-t nat -D POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10",
		"-t nat -C POSTROUTING -o eth0 -m comment --comment wirewarp-server-masquerade -j MASQUERADE",
		"-t nat -D POSTROUTING -o eth0 -m comment --comment wirewarp-server-masquerade -j MASQUERADE",
	}
	assertSNATCommandLog(t, logPath, want)
}

func TestCleanupServerNATReportsMasqueradeDeleteFailure(t *testing.T) {
	logPath := installSNATCommandStubs(t, "", "MASQUERADE")
	t.Setenv("IPTABLES_MASQUERADE_PRESENT", "1")

	err := CleanupServerNAT("eth0")
	if err == nil || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("expected masquerade cleanup failure, got %v", err)
	}
	assertSNATCommandLog(t, logPath, []string{
		"-t nat -C POSTROUTING -o eth0 -m comment --comment wirewarp-server-masquerade -j MASQUERADE",
		"-t nat -D POSTROUTING -o eth0 -m comment --comment wirewarp-server-masquerade -j MASQUERADE",
	})
}

func TestReconcileLANSNATAndSaveRestoresPreStateAfterFailures(t *testing.T) {
	tests := []struct {
		name          string
		failDeleteAt  string
		failInsertAt  string
		failSaveAt    string
		wantSaveCount string
	}{
		{name: "mid-delete", failDeleteAt: "1", wantSaveCount: "1"},
		{name: "mid-add", failInsertAt: "2", wantSaveCount: "1"},
		{name: "save", failSaveAt: "1", wantSaveCount: "2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statePath, saveCountPath := installTransactionalSNATStubs(t, transactionalSNATPreState)
			t.Setenv("FAIL_DELETE_AT", tt.failDeleteAt)
			t.Setenv("FAIL_INSERT_AT", tt.failInsertAt)
			t.Setenv("FAIL_SAVE_AT", tt.failSaveAt)

			err := ReconcileLANSNATAndSave("eth0", []LANSNATPin{
				{LANIP: "192.168.20.2", PublicIP: "203.0.113.20"},
				{LANIP: "192.168.20.3", PublicIP: "203.0.113.21"},
			})
			if err == nil || !strings.Contains(err.Error(), "previous state restored") {
				t.Fatalf("expected restored-state failure, got %v", err)
			}
			assertTransactionalSNATPreState(t, statePath)
			assertCounterFile(t, saveCountPath, tt.wantSaveCount)
		})
	}
}

func TestReconcileLANSNATAndSaveReportsRollbackFailure(t *testing.T) {
	statePath, _ := installTransactionalSNATStubs(t, transactionalSNATPreState)
	t.Setenv("FAIL_INSERT_AT", "1")
	t.Setenv("FAIL_ROLLBACK_INSERT", "1")

	err := ReconcileLANSNATAndSave("eth0", []LANSNATPin{
		{LANIP: "192.168.20.2", PublicIP: "203.0.113.20"},
	})
	if err == nil || !strings.Contains(err.Error(), "insert failed") || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected original and rollback failure context, got %v", err)
	}
	data, readErr := os.ReadFile(statePath)
	if readErr != nil {
		t.Fatalf("read NAT state: %v", readErr)
	}
	if !strings.Contains(string(data), "-A POSTROUTING -p tcp --dport 443 -j ACCEPT") {
		t.Fatalf("rollback removed unrelated rule:\n%s", data)
	}
}

func TestSetLANSNATAndSaveRestoresFullPreStateAfterFailures(t *testing.T) {
	tests := []struct {
		name          string
		clear         bool
		failDeleteAt  string
		failInsertAt  string
		failSaveAt    string
		wantSaveCount string
	}{
		{name: "partial delete", failDeleteAt: "1", wantSaveCount: "1"},
		{name: "add", failInsertAt: "1", wantSaveCount: "1"},
		{name: "set persistence", failSaveAt: "1", wantSaveCount: "2"},
		{name: "clear persistence", clear: true, failSaveAt: "1", wantSaveCount: "2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statePath, saveCountPath := installTransactionalSNATStubs(t, perSourceSNATPreState)
			t.Setenv("FAIL_DELETE_AT", tt.failDeleteAt)
			t.Setenv("FAIL_INSERT_AT", tt.failInsertAt)
			t.Setenv("FAIL_SAVE_AT", tt.failSaveAt)

			err := SetLANSNATAndSave("eth0", "192.168.10.2", "203.0.113.30", tt.clear)
			if err == nil || !strings.Contains(err.Error(), "previous state restored") {
				t.Fatalf("expected restored-state failure, got %v", err)
			}
			assertManagedLANSNATState(t, statePath, perSourceSNATPreState)
			assertCounterFile(t, saveCountPath, tt.wantSaveCount)
		})
	}
}

const transactionalSNATPreState = `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
-A POSTROUTING -p tcp --dport 443 -j ACCEPT
-A POSTROUTING -s 192.168.10.3/32 -o eth0 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.11
-A POSTROUTING -s 192.168.99.2/32 -o eth1 -j SNAT --to-source 203.0.113.99
-A POSTROUTING -o eth0 -j MASQUERADE
`

const perSourceSNATPreState = `-A POSTROUTING -s 192.168.10.2/32 -o eth0 -j SNAT --to-source 203.0.113.10
-A POSTROUTING -s 192.168.10.2/32 -o eth0 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.12
-A POSTROUTING -s 192.168.10.3/32 -o eth0 -m comment --comment wirewarp-lan-snat -j SNAT --to-source 203.0.113.11
-A POSTROUTING -p tcp --dport 443 -j ACCEPT
-A POSTROUTING -o eth0 -j MASQUERADE
`

func installTransactionalSNATStubs(t *testing.T, initialState string) (string, string) {
	t.Helper()
	binDir := t.TempDir()
	statePath := filepath.Join(t.TempDir(), "nat.state")
	deleteCountPath := filepath.Join(t.TempDir(), "delete.count")
	insertCountPath := filepath.Join(t.TempDir(), "insert.count")
	saveCountPath := filepath.Join(t.TempDir(), "save.count")
	originalFailedPath := filepath.Join(t.TempDir(), "original.failed")
	if err := os.WriteFile(statePath, []byte(initialState), 0600); err != nil {
		t.Fatalf("write initial NAT state: %v", err)
	}
	iptablesSave := filepath.Join(binDir, "iptables-save")
	if err := os.WriteFile(iptablesSave, []byte(`#!/bin/sh
cat "$NAT_STATE"
`), 0755); err != nil {
		t.Fatalf("write iptables-save stub: %v", err)
	}
	iptablesPath := filepath.Join(binDir, "iptables")
	if err := os.WriteFile(iptablesPath, []byte(`#!/bin/sh
if [ "$1" != "-t" ] || [ "$2" != "nat" ]; then exit 64; fi
action="$3"
chain="$4"
shift 4
rule="-A $chain $*"
bump() {
  count=0
  if [ -f "$1" ]; then read -r count < "$1"; fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$1"
  BUMPED_COUNT="$count"
}
case "$action" in
  -C)
    while IFS= read -r line; do
      if [ "$line" = "$rule" ]; then exit 0; fi
    done < "$NAT_STATE"
    exit 1
    ;;
  -D)
    bump "$DELETE_COUNT"
    if [ "$BUMPED_COUNT" = "$FAIL_DELETE_AT" ]; then
      echo delete failed
      exit 2
    fi
    tmp="$NAT_STATE.tmp"
    found=0
    : > "$tmp"
    while IFS= read -r line; do
      if [ "$found" = 0 ] && [ "$line" = "$rule" ]; then
        found=1
      else
        printf '%s\n' "$line" >> "$tmp"
      fi
    done < "$NAT_STATE"
    mv "$tmp" "$NAT_STATE"
    if [ "$found" = 1 ]; then exit 0; fi
    exit 1
    ;;
  -I)
    bump "$INSERT_COUNT"
    if [ "$BUMPED_COUNT" = "$FAIL_INSERT_AT" ]; then
      printf '1\n' > "$ORIGINAL_FAILED"
      echo insert failed
      exit 2
    fi
    if [ -s "$ORIGINAL_FAILED" ] && [ "$FAIL_ROLLBACK_INSERT" = 1 ]; then
      echo rollback insert failed
      exit 2
    fi
    tmp="$NAT_STATE.tmp"
    printf '%s\n' "$rule" > "$tmp"
    cat "$NAT_STATE" >> "$tmp"
    mv "$tmp" "$NAT_STATE"
    exit 0
    ;;
esac
exit 64
`), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	netfilterPersistent := filepath.Join(binDir, "netfilter-persistent")
	if err := os.WriteFile(netfilterPersistent, []byte(`#!/bin/sh
count=0
if [ -f "$SAVE_COUNT" ]; then read -r count < "$SAVE_COUNT"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$SAVE_COUNT"
if [ "$count" = "$FAIL_SAVE_AT" ]; then
  echo save failed
  exit 2
fi
exit 0
`), 0755); err != nil {
		t.Fatalf("write netfilter-persistent stub: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("NAT_STATE", statePath)
	t.Setenv("DELETE_COUNT", deleteCountPath)
	t.Setenv("INSERT_COUNT", insertCountPath)
	t.Setenv("SAVE_COUNT", saveCountPath)
	t.Setenv("ORIGINAL_FAILED", originalFailedPath)
	return statePath, saveCountPath
}

func assertTransactionalSNATPreState(t *testing.T, statePath string) {
	t.Helper()
	assertManagedLANSNATState(t, statePath, transactionalSNATPreState)
}

func assertManagedLANSNATState(t *testing.T, statePath, preState string) {
	t.Helper()
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read NAT state: %v", err)
	}
	gotManaged := lanSNATRules(string(data), "eth0")
	wantManaged := lanSNATRules(preState, "eth0")
	if !reflect.DeepEqual(gotManaged, wantManaged) {
		t.Fatalf("managed LAN SNAT state\nwant %#v\n got %#v\nfull state:\n%s", wantManaged, gotManaged, data)
	}
	for _, unrelated := range strings.Split(strings.TrimSpace(preState), "\n") {
		if len(lanSNATRules(unrelated, "eth0")) != 0 {
			continue
		}
		if !strings.Contains(string(data), unrelated) {
			t.Fatalf("unrelated rule changed or removed: %s\n%s", unrelated, data)
		}
	}
}

func assertCounterFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read counter %s: %v", path, err)
	}
	if strings.TrimSpace(string(data)) != want {
		t.Fatalf("counter %s: want %s, got %s", path, want, strings.TrimSpace(string(data)))
	}
}

func installSNATCommandStubs(t *testing.T, saveOutput, fail string) string {
	t.Helper()
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "iptables.log")
	iptablesSave := filepath.Join(binDir, "iptables-save")
	if err := os.WriteFile(iptablesSave, []byte(`#!/bin/sh
printf '%s\n' "$IPTABLES_SAVE_OUTPUT"
`), 0755); err != nil {
		t.Fatalf("write iptables-save stub: %v", err)
	}
	iptables := filepath.Join(binDir, "iptables")
	if err := os.WriteFile(iptables, []byte(`#!/bin/sh
printf '%s\n' "$*" >> "$IPTABLES_LOG"
case " $* " in
  *" -C POSTROUTING "*" --comment wirewarp-server-masquerade -j MASQUERADE "*)
    if [ "$IPTABLES_MASQUERADE_PRESENT" = "1" ]; then exit 0; fi
    exit 1
    ;;
  *" -D "*)
    if [ "$IPTABLES_FAIL" != "" ] && { [ "$IPTABLES_FAIL" = "insert" ] || printf '%s' "$*" | grep -q "$IPTABLES_FAIL"; }; then
      if [ "$IPTABLES_FAIL" != "insert" ]; then echo "delete failed"; exit 2; fi
    fi
    exit 0
    ;;
  *" -C "*) exit 1 ;;
  *" -I "*)
    if [ "$IPTABLES_FAIL" = "insert" ]; then echo "insert failed"; exit 2; fi
    exit 0
    ;;
esac
exit 0
`), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("IPTABLES_SAVE_OUTPUT", saveOutput)
	t.Setenv("IPTABLES_LOG", logPath)
	t.Setenv("IPTABLES_FAIL", fail)
	return logPath
}

func assertSNATCommandLog(t *testing.T, logPath string, want []string) {
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
