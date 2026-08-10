package wireguard

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEnsureOutputConnmarkAndReportUsesValidIPTablesCommands(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "iptables.log")
	iptablesPath := filepath.Join(binDir, "iptables")
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$IPTABLES_LOG"
case "$*" in
  "-t mangle -C OUTPUT -j CONNMARK --restore-mark"|\
  "-t mangle -C PREROUTING ! -i wg+ -j CONNMARK --restore-mark")
    if [ "$IPTABLES_RULES_PRESENT" = "1" ]; then exit 0; fi
    exit 1
    ;;
  "-t mangle -A OUTPUT -j CONNMARK --restore-mark"|\
  "-t mangle -A PREROUTING ! -i wg+ -j CONNMARK --restore-mark")
    exit 0
    ;;
  *)
    exit 64
    ;;
esac
`
	if err := os.WriteFile(iptablesPath, []byte(stub), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IPTABLES_LOG", logPath)

	t.Run("repairs missing rules", func(t *testing.T) {
		t.Setenv("IPTABLES_RULES_PRESENT", "0")

		healed, err := ensureOutputConnmarkAndReport()
		if err != nil {
			t.Fatalf("ensure output connmark: %v", err)
		}
		wantHealed := []string{"output-connmark-restore", "prerouting-connmark-restore"}
		if !reflect.DeepEqual(healed, wantHealed) {
			t.Fatalf("healed rules\nwant %#v\n got %#v", wantHealed, healed)
		}

		wantCalls := []string{
			"-t mangle -C OUTPUT -j CONNMARK --restore-mark",
			"-t mangle -A OUTPUT -j CONNMARK --restore-mark",
			"-t mangle -C PREROUTING ! -i wg+ -j CONNMARK --restore-mark",
			"-t mangle -A PREROUTING ! -i wg+ -j CONNMARK --restore-mark",
		}
		assertIPTablesCalls(t, logPath, wantCalls)
	})

	t.Run("leaves existing rules unchanged", func(t *testing.T) {
		if err := os.WriteFile(logPath, nil, 0600); err != nil {
			t.Fatalf("clear iptables log: %v", err)
		}
		t.Setenv("IPTABLES_RULES_PRESENT", "1")

		healed, err := ensureOutputConnmarkAndReport()
		if err != nil {
			t.Fatalf("ensure output connmark: %v", err)
		}
		if len(healed) != 0 {
			t.Fatalf("expected no healed rules, got %#v", healed)
		}

		wantCalls := []string{
			"-t mangle -C OUTPUT -j CONNMARK --restore-mark",
			"-t mangle -C PREROUTING ! -i wg+ -j CONNMARK --restore-mark",
		}
		assertIPTablesCalls(t, logPath, wantCalls)
	})
}

func assertIPTablesCalls(t *testing.T, logPath string, want []string) {
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
