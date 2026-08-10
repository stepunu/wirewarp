package iptables

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRemoveForwardBothAbsentIsSuccess(t *testing.T) {
	logPath := installForwardIPTablesStub(t, false, false, "")
	if err := RemoveForward(testForwardPublicIP(), testForwardRule()); err != nil {
		t.Fatalf("remove absent forward: %v", err)
	}
	want := []string{testDNATCheck(), testForwardCheck()}
	assertForwardCommandLog(t, logPath, want)
}

func TestRemoveForwardDeletesBothPresentRulesWithExactArgs(t *testing.T) {
	logPath := installForwardIPTablesStub(t, true, true, "")
	if err := RemoveForward(testForwardPublicIP(), testForwardRule()); err != nil {
		t.Fatalf("remove forward: %v", err)
	}
	want := []string{testDNATCheck(), testDNATDelete(), testForwardCheck(), testForwardDelete()}
	assertForwardCommandLog(t, logPath, want)
}

func TestRemoveForwardDNATFailureStillAttemptsForward(t *testing.T) {
	logPath := installForwardIPTablesStub(t, true, true, "dnat")
	err := RemoveForward(testForwardPublicIP(), testForwardRule())
	if err == nil || !strings.Contains(err.Error(), "DNAT rule") || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("expected DNAT delete failure, got %v", err)
	}
	want := []string{testDNATCheck(), testDNATDelete(), testForwardCheck(), testForwardDelete()}
	assertForwardCommandLog(t, logPath, want)
}

func TestRemoveForwardReturnsForwardFailure(t *testing.T) {
	logPath := installForwardIPTablesStub(t, true, true, "forward")
	err := RemoveForward(testForwardPublicIP(), testForwardRule())
	if err == nil || !strings.Contains(err.Error(), "FORWARD rule") || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("expected FORWARD delete failure, got %v", err)
	}
	want := []string{testDNATCheck(), testDNATDelete(), testForwardCheck(), testForwardDelete()}
	assertForwardCommandLog(t, logPath, want)
}

func TestRemoveForwardRetryAfterPartialSuccessIsIdempotent(t *testing.T) {
	logPath := installForwardIPTablesStub(t, true, true, "forward-once")
	if err := RemoveForward(testForwardPublicIP(), testForwardRule()); err == nil {
		t.Fatal("expected first removal to fail")
	}
	if err := RemoveForward(testForwardPublicIP(), testForwardRule()); err != nil {
		t.Fatalf("retry removal: %v", err)
	}
	want := []string{
		testDNATCheck(), testDNATDelete(), testForwardCheck(), testForwardDelete(),
		testDNATCheck(), testForwardCheck(), testForwardDelete(),
	}
	assertForwardCommandLog(t, logPath, want)
}

func TestRemoveForwardAndSaveRestoresExactRulesAfterSaveFailure(t *testing.T) {
	logPath := installForwardIPTablesStub(t, true, true, "")
	t.Setenv("SAVE_FAIL_ONCE", "1")

	err := RemoveForwardAndSave(testForwardPublicIP(), testForwardRule())
	if err == nil || !strings.Contains(err.Error(), "save failed") || !strings.Contains(err.Error(), "previous state restored") {
		t.Fatalf("expected save failure with restored state, got %v", err)
	}
	if err := RemoveForward(testForwardPublicIP(), testForwardRule()); err != nil {
		t.Fatalf("restored forward was not removable: %v", err)
	}
	want := []string{
		testDNATCheck(), testForwardCheck(),
		testDNATCheck(), testDNATDelete(), testForwardCheck(), testForwardDelete(),
		testDNATCheck(), testDNATAppend(), testForwardCheck(), testForwardAppend(),
		testDNATCheck(), testDNATDelete(), testForwardCheck(), testForwardDelete(),
	}
	assertForwardCommandLog(t, logPath, want)
}

func TestRemoveForwardAndSaveReportsRollbackFailure(t *testing.T) {
	logPath := installForwardIPTablesStub(t, true, true, "rollback-dnat")
	t.Setenv("SAVE_FAIL_ONCE", "1")

	err := RemoveForwardAndSave(testForwardPublicIP(), testForwardRule())
	if err == nil || !strings.Contains(err.Error(), "save failed") || !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(err.Error(), "restore failed") {
		t.Fatalf("expected original and rollback failure context, got %v", err)
	}
	want := []string{
		testDNATCheck(), testForwardCheck(),
		testDNATCheck(), testDNATDelete(), testForwardCheck(), testForwardDelete(),
		testDNATCheck(), testDNATAppend(), testForwardCheck(), testForwardAppend(),
	}
	assertForwardCommandLog(t, logPath, want)
}

func installForwardIPTablesStub(t *testing.T, dnatPresent, forwardPresent bool, fail string) string {
	t.Helper()
	binDir := t.TempDir()
	stateDir := t.TempDir()
	logPath := filepath.Join(stateDir, "iptables.log")
	dnatState := filepath.Join(stateDir, "dnat.state")
	forwardState := filepath.Join(stateDir, "forward.state")
	writeForwardState(t, dnatState, dnatPresent)
	writeForwardState(t, forwardState, forwardPresent)
	iptablesPath := filepath.Join(binDir, "iptables")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IPTABLES_LOG"
action=""
chain=""
for value in "$@"; do
  case "$value" in
    -C|-D|-A) action="$value" ;;
    PREROUTING|FORWARD) chain="$value" ;;
  esac
done
if [ "$chain" = "PREROUTING" ]; then
  state_path="$DNAT_STATE"
  failure="dnat"
else
  state_path="$FORWARD_STATE"
  failure="forward"
fi
state="0"
if [ -f "$state_path" ]; then read -r state < "$state_path"; fi
if [ "$action" = "-C" ]; then
  if [ "$state" = "1" ]; then exit 0; fi
  exit 1
fi
if [ "$action" = "-D" ]; then
  if [ "$IPTABLES_FAIL" = "$failure" ]; then
    echo "delete failed"
    exit 2
  fi
  if [ "$IPTABLES_FAIL" = "forward-once" ] && [ "$failure" = "forward" ] && [ ! -f "$FAIL_MARKER" ]; then
    : > "$FAIL_MARKER"
    echo "delete failed once"
    exit 2
  fi
  printf '0\n' > "$state_path"
  exit 0
fi
if [ "$action" = "-A" ]; then
  if [ "$IPTABLES_FAIL" = "rollback-dnat" ] && [ "$failure" = "dnat" ]; then
    echo "restore failed"
    exit 2
  fi
  printf '1\n' > "$state_path"
  exit 0
fi
exit 2
`
	if err := os.WriteFile(iptablesPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	netfilterPath := filepath.Join(binDir, "netfilter-persistent")
	netfilterStub := `#!/bin/sh
count=0
if [ -f "$SAVE_COUNT" ]; then read -r count < "$SAVE_COUNT"; fi
count=$((count + 1))
printf '%s\n' "$count" > "$SAVE_COUNT"
if [ "$SAVE_FAIL_ONCE" = 1 ] && [ "$count" = 1 ]; then
  echo "save failed"
  exit 2
fi
exit 0
`
	if err := os.WriteFile(netfilterPath, []byte(netfilterStub), 0755); err != nil {
		t.Fatalf("write netfilter-persistent stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IPTABLES_LOG", logPath)
	t.Setenv("DNAT_STATE", dnatState)
	t.Setenv("FORWARD_STATE", forwardState)
	t.Setenv("FAIL_MARKER", filepath.Join(stateDir, "failed.once"))
	t.Setenv("SAVE_COUNT", filepath.Join(stateDir, "save.count"))
	t.Setenv("IPTABLES_FAIL", fail)
	return logPath
}

func writeForwardState(t *testing.T, path string, present bool) {
	t.Helper()
	value := "0\n"
	if present {
		value = "1\n"
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatalf("write forward state: %v", err)
	}
}

func testForwardRule() ForwardRule {
	return ForwardRule{Protocol: "tcp", PublicPort: 8080, DestIP: "10.21.0.2", DestPort: 80}
}

func testForwardPublicIP() string {
	return "203.0.113.2"
}

func testDNATCheck() string {
	return "-t nat -C PREROUTING -p tcp -j DNAT --to-destination 10.21.0.2:80 --dport 8080 -d 203.0.113.2"
}

func testDNATDelete() string {
	return "-t nat -D PREROUTING -p tcp -j DNAT --to-destination 10.21.0.2:80 --dport 8080 -d 203.0.113.2"
}

func testDNATAppend() string {
	return "-t nat -A PREROUTING -p tcp -j DNAT --to-destination 10.21.0.2:80 --dport 8080 -d 203.0.113.2"
}

func testForwardCheck() string {
	return "-C FORWARD -p tcp -d 10.21.0.2 --dport 80 -j ACCEPT"
}

func testForwardDelete() string {
	return "-D FORWARD -p tcp -d 10.21.0.2 --dport 80 -j ACCEPT"
}

func testForwardAppend() string {
	return "-A FORWARD -p tcp -d 10.21.0.2 --dport 80 -j ACCEPT"
}

func assertForwardCommandLog(t *testing.T, logPath string, want []string) {
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
