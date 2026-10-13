package handlers

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerPreservesEnabledUFWBeforeMutation(t *testing.T) {
	data, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "wirewarp_select_persistence() {")
	end := strings.Index(source, "\nwirewarp_select_persistence /etc/ufw/ufw.conf /etc/default/ufw")
	if start < 0 || end < start || end > strings.Index(source, "==> Cleaning up") {
		t.Fatal("persistence preflight must precede installation effects")
	}
	function := source[start:end]
	for _, test := range []struct {
		name, enabled, manage, want string
		ok                          bool
	}{{"enabled", "yes", "no", "1", true}, {"inline-comment", "yes # enabled", "no # preserve", "1", true}, {"last-assignment", "no\nENABLED=yes # active", "yes\nMANAGE_BUILTINS=no", "1", true}, {"unknown", "", "no", "", false}, {"disabled", "no", "yes", "0", true}, {"unsafe", "yes", "yes", "", false}, {"missing-default", "yes", "", "", false}} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			conf, defaults := filepath.Join(dir, "ufw.conf"), filepath.Join(dir, "ufw.defaults")
			if err := os.WriteFile(conf, []byte("ENABLED="+test.enabled+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(defaults, []byte("MANAGE_BUILTINS="+test.manage+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+function+"\nwirewarp_select_persistence \"$1\" \"$2\"\nprintf '%s' \"$PRESERVE_UFW\"", "proof", conf, defaults)
			out, err := cmd.CombinedOutput()
			if test.ok {
				if err != nil || string(out) != test.want {
					t.Fatal(err, string(out))
				}
			} else if err == nil || !strings.Contains(string(out), "before any changes") {
				t.Fatal("unsafe installer accepted", err, string(out))
			}
		})
	}
	if !strings.Contains(source, `if [[ "$PRESERVE_UFW" == 1 ]]`) || strings.Contains(source, "netfilter-persistent iptables-persistent >/dev/null 2>&1 || true") {
		t.Fatal("persistence package selection/failures not enforced")
	}
}
