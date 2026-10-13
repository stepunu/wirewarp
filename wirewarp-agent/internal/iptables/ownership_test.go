package iptables

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyVPNAllowAdoptionPrecedesDefaultDropAndUFW(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	marker := filepath.Join(dir, "adopted")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
case "$*" in
 "-C FORWARD -s 10.0.0.2/32 -d 192.168.20.0/24 -j ACCEPT") exit 0 ;;
 "-D FORWARD -s 10.0.0.2/32 -d 192.168.20.0/24 -j ACCEPT") exit 0 ;;
 "-w 5 -t filter -S FORWARD")
  printf '%s\n' '-P FORWARD DROP' '-A FORWARD -m comment --comment wirewarp-site-links -j WW-SITE-FWD' '-A FORWARD -s 10.0.0.0/24 -m comment --comment wirewarp-vpn-drop -j DROP' '-A FORWARD -j ufw-before-forward'; exit 0 ;;
 "-I FORWARD 2 -s 10.0.0.2/32 -d 192.168.20.0/24 -m comment --comment wirewarp-vpn-peer -j ACCEPT") : > "$ADOPTED"; exit 0 ;;
esac
exit 64
`
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("CALLS", log)
	t.Setenv("ADOPTED", marker)
	args := []string{"FORWARD", "-s", "10.0.0.2/32", "-d", "192.168.20.0/24", "-m", "comment", "--comment", "wirewarp-vpn-peer", "-j", "ACCEPT"}
	if err := adoptExactLegacy(args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "-I FORWARD 2 ") || strings.Contains(string(data), "-A FORWARD ") {
		t.Fatal("legacy acceptance appended behind deny", string(data))
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("owned replacement not applied", err)
	}
}

func TestLegacyVPNDenySurvivesFailedAdoption(t *testing.T) {
	for _, kind := range []string{"displaced-guard", "insert-failure"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			state := filepath.Join(dir, "deny")
			if err := os.WriteFile(state, []byte("legacy-deny"), 0600); err != nil {
				t.Fatal(err)
			}
			script := `#!/bin/sh
case "$*" in
 "-C FORWARD -s 10.0.0.0/24 -j DROP") exit 0 ;;
 "-D FORWARD -s 10.0.0.0/24 -j DROP") printf removed > "$DENY_STATE"; exit 0 ;;
 "-w 5 -t filter -S FORWARD")
   if [ "$FAIL_KIND" = displaced-guard ]; then printf '%s\n' '-A FORWARD -j ufw-before-forward' '-A FORWARD -m comment --comment wirewarp-site-links -j WW-SITE-FWD'; else printf '%s\n' '-A FORWARD -m comment --comment wirewarp-site-links -j WW-SITE-FWD' '-A FORWARD -s 10.0.0.0/24 -j DROP'; fi; exit 0 ;;
 "-I FORWARD 2 -s 10.0.0.0/24 -m comment --comment wirewarp-vpn-drop -j DROP") echo insert-denied; exit 2 ;;
esac
exit 64
`
			if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			t.Setenv("DENY_STATE", state)
			t.Setenv("FAIL_KIND", kind)
			if err := adoptExactLegacy([]string{"FORWARD", "-s", "10.0.0.0/24", "-m", "comment", "--comment", "wirewarp-vpn-drop", "-j", "DROP"}); err == nil {
				t.Fatal("failed adoption masked")
			}
			data, err := os.ReadFile(state)
			if err != nil || string(data) != "legacy-deny" {
				t.Fatal("old deny removed before replacement succeeded", err, string(data))
			}
		})
	}
}
