package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, map[string]string, *[]string) {
	t.Helper()
	dir := t.TempDir()
	config, defaults := filepath.Join(dir, "ufw.conf"), filepath.Join(dir, "ufw.defaults")
	if err := os.WriteFile(config, []byte("ENABLED=yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaults, []byte("MANAGE_BUILTINS=no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tables := map[string]string{"filter": "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N ufw-user-input\n-A INPUT -j ufw-user-input\n", "nat": "-P PREROUTING ACCEPT\n-P POSTROUTING ACCEPT\n-P OUTPUT ACCEPT\n", "mangle": "-P PREROUTING ACCEPT\n-P POSTROUTING ACCEPT\n-P OUTPUT ACCEPT\n-P FORWARD ACCEPT\n"}
	calls := []string{}
	s := &Store{Path: filepath.Join(dir, "state", "firewall.json"), UFWConfig: config, UFWDefaults: defaults, Owner: func() (string, string) { return "agent-a", "/etc/wirewarp/agent.yaml" }, UnitReady: func(context.Context) error { return nil }}
	s.Run = func(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
		calls = append(calls, binary+" "+strings.Join(args, " ")+"\n"+input)
		if binary == "iptables" {
			return []byte(tables[args[3]]), nil
		}
		return nil, nil
	}
	return s, tables, &calls
}

func TestOwnedSaveExcludesForeignPoliciesAndRules(t *testing.T) {
	s, tables, calls := testStore(t)
	tables["nat"] += "-A POSTROUTING -s 10.1.0.0/24 -m comment --comment wirewarp-server-masquerade -j MASQUERADE\n"
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ufw-") || strings.Contains(string(data), "-P ") {
		t.Fatalf("foreign firewall persisted: %s", data)
	}
	fi, _ := os.Stat(s.Path)
	if fi.Mode().Perm() != 0600 {
		t.Fatal(fi.Mode())
	}
	*calls = nil
	if err := s.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range *calls {
		if strings.Contains(call, "iptables-restore") && (strings.Contains(call, "ufw-") || strings.Contains(call, "-P ") || strings.Contains(call, "*filter")) {
			t.Fatal(call)
		}
	}
}

func TestAuthenticatedIdentityCannotAdoptForeignJournal(t *testing.T) {
	s, _, calls := testStore(t)
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	*calls = nil
	if err := s.ValidateIdentity("foreign", "/etc/wirewarp/agent.yaml"); err == nil {
		t.Fatal("foreign journal accepted")
	}
	if err := s.ValidateIdentity("agent-a", "/etc/wirewarp/another.yaml"); err == nil {
		t.Fatal("another installation journal accepted")
	}
	if err := s.ValidateIdentity("agent-a", "/etc/wirewarp/agent.yaml"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(s.Path)
	if err != nil || string(before) != string(after) || len(*calls) != 0 {
		t.Fatal("identity check changed journal or firewall", err)
	}
}

func TestAuthenticatedIdentityAbsentJournalDoesNotCreateState(t *testing.T) {
	s, _, calls := testStore(t)
	if err := s.ValidateIdentity("agent-a", "/etc/wirewarp/agent.yaml"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(s.Path)); !os.IsNotExist(err) || len(*calls) != 0 {
		t.Fatal("identity check created persistence state", err)
	}
}

func TestPersistenceRejectsUnsafeUFWAndUnitFailure(t *testing.T) {
	for _, kind := range []string{"unsafe", "unit"} {
		t.Run(kind, func(t *testing.T) {
			s, _, calls := testStore(t)
			if kind == "unsafe" {
				if err := os.WriteFile(s.UFWDefaults, []byte("MANAGE_BUILTINS=yes\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				s.UnitReady = func(context.Context) error { return errors.New("enable denied") }
			}
			if s.Save(context.Background()) == nil {
				t.Fatal("accepted unsafe persistence")
			}
			for _, call := range *calls {
				if !strings.HasPrefix(call, "iptables ") {
					t.Fatal("effects before validation", *calls)
				}
			}
		})
	}
}

func TestTraditionalPersistenceStillReportsSaveFailure(t *testing.T) {
	s, _, _ := testStore(t)
	if err := os.WriteFile(s.UFWConfig, []byte("ENABLED=no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Run = func(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
		if binary != "netfilter-persistent" || strings.Join(args, " ") != "save" {
			t.Fatal(binary, args)
		}
		return []byte("disk error"), errors.New("exit 1")
	}
	if err := s.Save(context.Background()); err == nil || !strings.Contains(err.Error(), "disk error") {
		t.Fatal(err)
	}
}

func TestTraditionalTransitionIgnoresThenRetiresOldJournal(t *testing.T) {
	s, tables, calls := testStore(t)
	tables["filter"] += "-A FORWARD -i wg0 -o eth0 -m comment --comment wirewarp-gateway-forward -j ACCEPT\n"
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.UFWConfig, []byte("ENABLED=no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	if err := s.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatal("stale journal replayed with traditional backend", *calls)
	}
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path); !os.IsNotExist(err) {
		t.Fatal("old journal not retired", err)
	}
	if err := os.WriteFile(s.UFWConfig, []byte("ENABLED=yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	if err := s.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatal("retired inventory revived", *calls)
	}
}

func TestJournalRejectsForeignChainCollisionBeforeEffects(t *testing.T) {
	s, tables, calls := testStore(t)
	tables["filter"] += "-N WW-EDGE-INGRESS\n-A WW-EDGE-INGRESS -j ACCEPT\n"
	if err := s.Save(context.Background()); err == nil {
		t.Fatal("accepted foreign reserved chain")
	}
	for _, call := range *calls {
		if strings.Contains(call, "iptables-restore") {
			t.Fatal(call)
		}
	}
	if _, err := os.Stat(s.Path); !os.IsNotExist(err) {
		t.Fatal("journal published", err)
	}
}

func TestOwnershipPreflightAcceptsOnlyExactSavedLegacyRules(t *testing.T) {
	s, tables, calls := testStore(t)
	legacy := "-A WW-EDGE-INGRESS -d 10.20.0.2/32 -p tcp -m multiport --dports 80,443 -j DROP"
	tables["filter"] += "-N WW-EDGE-INGRESS\n-A INPUT -m comment --comment wirewarp-edge-ingress -j WW-EDGE-INGRESS\n" + legacy + "\n"
	if err := s.Preflight(context.Background(), nil); err == nil {
		t.Fatal("unmarked reserved rule accepted without saved ownership")
	}
	if err := s.Preflight(context.Background(), map[string][]string{"filter": {legacy}}); err != nil {
		t.Fatal("exact saved legacy guard rejected", err)
	}
	tables["filter"] += "-A WW-EDGE-INGRESS -j ACCEPT\n"
	if err := s.Preflight(context.Background(), map[string][]string{"filter": {legacy}}); err == nil {
		t.Fatal("foreign rule admitted by legacy ownership")
	}
	for _, call := range *calls {
		if strings.Contains(call, "iptables-restore") {
			t.Fatal("ownership preflight changed firewall", call)
		}
	}
}

func TestDeferredDockerInventorySurvivesAndCanBeDeleted(t *testing.T) {
	s, tables, calls := testStore(t)
	rule := "-A DOCKER-USER -i wg0 -o eth0 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT\n"
	tables["filter"] += "-N DOCKER-USER\n" + rule
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	tables["filter"] = strings.ReplaceAll(tables["filter"], "-N DOCKER-USER\n"+rule, "")
	s.DockerAllowed = func(in, out string) bool { return in == "wg0" && out == "eth0" }
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, err := s.load("agent-a", "/etc/wirewarp/agent.yaml")
	if err != nil || len(j.Tables["filter"].Rules) != 1 {
		t.Fatal(j, err)
	}
	*calls = nil
	if err := s.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range *calls {
		if strings.Contains(call, "iptables-restore") && strings.Contains(call, "DOCKER-USER") {
			t.Fatal("missing parent restored", call)
		}
	}
	tables["filter"] += "-N DOCKER-USER\n"
	*calls = nil
	if err := s.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, call := range *calls {
		if strings.Contains(call, "iptables-restore --wait") && strings.Contains(call, "-I DOCKER-USER") {
			found = true
		}
	}
	if !found {
		t.Fatal("deferred rule not restored", *calls)
	}
	tables["filter"] = strings.ReplaceAll(tables["filter"], "-N DOCKER-USER\n", "")
	s.DockerAllowed = func(string, string) bool { return false }
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, err = s.load("agent-a", "/etc/wirewarp/agent.yaml")
	if err != nil || len(j.Tables["filter"].Rules) != 0 {
		t.Fatal(j, err)
	}
}

func TestJournalOwnerModeAndSchemaAreChecked(t *testing.T) {
	for _, kind := range []string{"owner", "mode", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			s, _, calls := testStore(t)
			if err := s.Save(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "owner":
				s.Owner = func() (string, string) { return "other", "/etc/wirewarp/agent.yaml" }
			case "mode":
				if err := os.Chmod(s.Path, 0644); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				data, _ := os.ReadFile(s.Path)
				if err := os.WriteFile(s.Path, []byte(strings.Replace(string(data), "\"schema\":1", "\"schema\":1,\"foreign\":true", 1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			*calls = nil
			if s.Restore(context.Background()) == nil {
				t.Fatal("accepted invalid journal")
			}
			if len(*calls) != 0 {
				t.Fatal("effects before journal validation", *calls)
			}
		})
	}
}

func TestPersistenceLockWaitHonorsCancellation(t *testing.T) {
	s, _, _ := testStore(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := s.Save(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestJournalIOFailureIsReportedWithoutFirewallEffects(t *testing.T) {
	s, _, calls := testStore(t)
	block := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(block, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	s.Path = filepath.Join(block, "journal.json")
	if err := s.Save(context.Background()); err == nil {
		t.Fatal("journal I/O failure hidden")
	}
	if len(*calls) != 0 {
		t.Fatal("firewall inspected/applied after failed journal lock", *calls)
	}
	data, err := os.ReadFile(block)
	if err != nil || string(data) != "foreign" {
		t.Fatal("foreign filesystem data changed", err, string(data))
	}
}

func TestRestorePreflightsEveryTableBeforeMutation(t *testing.T) {
	s, tables, calls := testStore(t)
	tables["filter"] += "-A FORWARD -i wg0 -o eth0 -m comment --comment wirewarp-gateway-forward -j ACCEPT\n"
	tables["nat"] += "-A POSTROUTING -s 10.1.0.0/24 -m comment --comment wirewarp-server-masquerade -j MASQUERADE\n"
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	run := s.Run
	s.Run = func(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
		if binary == "iptables-restore" && strings.Contains(input, "*nat") {
			return nil, errors.New("preflight denied")
		}
		return run(ctx, input, binary, args...)
	}
	*calls = nil
	if s.Restore(context.Background()) == nil {
		t.Fatal("masked preflight failure")
	}
	for _, call := range *calls {
		if strings.Contains(call, "iptables-restore --wait") {
			t.Fatal("mutation before complete preflight", call)
		}
	}
}
