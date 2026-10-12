package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wirewarp/agent/internal/config"
)

func teardownFixture(t *testing.T) (*SiteLinkHandlers, siteTeardownParams) {
	t.Helper()
	cfg, p := siteFixture("hub")
	p.Links = nil
	p.DesiredHash = siteSnapshotHash(p)
	p.OwnerAgentID = cfg.AgentID
	cfg.SiteLinkDesired = p
	cfg.SiteLinkApplied = p
	cfg.SiteLinkGuardPeers = p.TransitPeers
	h := NewSiteLinks(cfg, filepath.Join(t.TempDir(), "agent.yaml"))
	h.persistFirewall = func(context.Context) error { return nil }
	return h, siteTeardownParams{SchemaVersion: 1, AgentID: cfg.AgentID, Revision: p.Revision, DesiredHash: p.DesiredHash}
}

func TestSiteTeardownReceiptRestartAndNewGeneration(t *testing.T) {
	h, p := teardownFixture(t)
	calls := 0
	persists := 0
	h.persistFirewall = func(context.Context) error { persists++; return nil }
	h.cleanup = func(context.Context, *config.Config) error { calls++; return nil }
	raw, _ := json.Marshal(p)
	result, err := h.handleTeardown(raw)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if json.Unmarshal([]byte(result), &output) != nil || output["released"] != true || output["desired_hash"] != p.DesiredHash {
		t.Fatal(result)
	}
	loaded, err := config.Load(h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SiteLinkDesired != nil || loaded.SiteLinkApplied != nil || len(loaded.SiteLinkGuardPeers) != 0 || loaded.SiteLinkTeardown.AgentID != p.AgentID {
		t.Fatal("release was not fully persisted")
	}
	restarted := NewSiteLinks(loaded, h.cfgPath)
	restarted.persistFirewall = func(context.Context) error { t.Fatal("receipt retry persisted firewall"); return nil }
	restarted.cleanup = func(context.Context, *config.Config) error { t.Fatal("receipt retry repeated cleanup"); return nil }
	if _, err := restarted.handleTeardown(raw); err != nil {
		t.Fatal("restart retry:", err)
	}
	_, next := siteFixture("hub")
	next.Revision = p.Revision
	if err := validateSiteSnapshot(loaded, next); err == nil {
		t.Fatal("released generation restored ownership")
	}
	next.Revision++
	next.DesiredHash = siteSnapshotHash(next)
	restarted.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	restarted.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
		return nil
	}
	restarted.ownership = func(context.Context, *config.Config, *config.SiteLinkSnapshot) error { return errSitePeerPending }
	rawNext, _ := json.Marshal(next)
	_, _ = restarted.handleDesired(rawNext)
	if loaded.Snapshot().SiteLinkTeardown != nil || loaded.Snapshot().SiteLinkDesired.Revision != next.Revision {
		t.Fatal("new accepted generation did not clear receipt")
	}
	if _, err := restarted.handleTeardown(raw); err == nil {
		t.Fatal("stale receipt released new desired state")
	}
	if calls != 1 || persists != 1 {
		t.Fatal(calls)
	}
}

func TestSiteTeardownPersistenceFailureRestoresAndPersistsGuard(t *testing.T) {
	for _, failAgain := range []bool{false, true} {
		t.Run(fmt.Sprint(failAgain), func(t *testing.T) {
			h, p := teardownFixture(t)
			h.cleanup = func(context.Context, *config.Config) error { return nil }
			calls, restored := 0, false
			h.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
				restored = true
				return nil
			}
			h.persistFirewall = func(ctx context.Context) error {
				calls++
				if ctx.Err() != nil {
					t.Fatal("cancelled persistence context")
				}
				if calls == 1 {
					return errors.New("initial persistence failed")
				}
				if !restored {
					t.Fatal("persisted before guard restore")
				}
				if failAgain {
					return errors.New("rollback persistence failed")
				}
				return nil
			}
			raw, _ := json.Marshal(p)
			_, err := h.handleTeardown(raw)
			if err == nil || calls != 2 || !strings.Contains(err.Error(), "initial persistence failed") {
				t.Fatalf("failure masked: %v calls=%d", err, calls)
			}
			if failAgain && !strings.Contains(err.Error(), "rollback persistence failed") {
				t.Fatal("rollback persistence failure hidden")
			}
			if h.cfg.Snapshot().SiteLinkDesired == nil || h.cfg.Snapshot().SiteLinkTeardown != nil {
				t.Fatal("persistence failure released ownership")
			}
		})
	}
}

func TestSiteTeardownPersistenceInvokesExistingSaveMechanism(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "arguments")
	program := []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$SITE_PERSIST_LOG\"\nexit 1\n")
	if err := os.WriteFile(filepath.Join(dir, "netfilter-persistent"), program, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SITE_PERSIST_LOG", logPath)
	if err := persistSiteFirewall(context.Background()); err == nil {
		t.Fatal("save failure hidden")
	}
	args, err := os.ReadFile(logPath)
	if err != nil || strings.TrimSpace(string(args)) != "save" {
		t.Fatalf("unexpected persistence invocation: %v %s", err, args)
	}
}

func TestSiteTeardownPersistenceCancellationStopsPluginChild(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "child.pid")
	program := []byte("#!/bin/sh\n/bin/sleep 30 &\necho \"$!\" > \"$SITE_CHILD_PID\"\nwait\n")
	if err := os.WriteFile(filepath.Join(dir, "netfilter-persistent"), program, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SITE_CHILD_PID", pidPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- persistSiteFirewall(ctx) }()
	var pid int
	for attempt := 0; attempt < 100; attempt++ {
		if data, err := os.ReadFile(pidPath); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("plugin child did not start")
	}
	t.Cleanup(func() {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err == nil && !strings.Contains(string(data), ") Z ") {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled save returned success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled save did not exit")
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil && !strings.Contains(string(data), ") Z ") {
		t.Fatalf("cancelled plugin child still runs: PID %d", pid)
	}
}

func TestSiteTeardownRejectsUnappliedLinkedStaleAndWrongOwner(t *testing.T) {
	for _, name := range []string{"owner", "stale", "hash", "unapplied", "linked", "routes", "applied-owner", "applied-hash"} {
		t.Run(name, func(t *testing.T) {
			h, p := teardownFixture(t)
			switch name {
			case "owner":
				p.AgentID = siteAID
			case "stale":
				p.Revision++
			case "hash":
				p.DesiredHash = strings.Repeat("a", 64)
			case "unapplied":
				h.cfg.SiteLinkApplied = nil
			case "linked":
				h.cfg.SiteLinkDesired.Links = []config.SiteLink{{}}
			case "routes":
				h.cfg.SiteLinkRoutes = []config.SiteLinkRoute{{Table: 60000}}
			case "applied-owner":
				copy := *h.cfg.SiteLinkApplied
				copy.OwnerAgentID = siteAID
				h.cfg.SiteLinkApplied = &copy
			case "applied-hash":
				copy := *h.cfg.SiteLinkApplied
				copy.DesiredHash = strings.Repeat("b", 64)
				h.cfg.SiteLinkApplied = &copy
			}
			h.cleanup = func(context.Context, *config.Config) error { t.Fatal("rejected request touched firewall"); return nil }
			raw, _ := json.Marshal(p)
			if _, err := h.handleTeardown(raw); err == nil {
				t.Fatal("unsafe teardown accepted")
			}
		})
	}
}

func TestSiteTeardownRejectsMalformedPayloadBeforeEffects(t *testing.T) {
	h, p := teardownFixture(t)
	h.cleanup = func(context.Context, *config.Config) error { t.Fatal("malformed input changed firewall"); return nil }
	raw, _ := json.Marshal(p)
	for _, input := range []string{string(raw) + " {}", strings.Replace(string(raw), `"schema_version":1`, `"schema_version":2`, 1), strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`, strings.Repeat("x", 4097)} {
		if _, err := h.handleTeardown(json.RawMessage(input)); err == nil {
			t.Fatal("malformed teardown accepted")
		}
	}
}

func TestSiteTeardownPartialCleanupAndSaveFailureRestoreGuard(t *testing.T) {
	for _, name := range []string{"partial", "save", "rollback"} {
		t.Run(name, func(t *testing.T) {
			h, p := teardownFixture(t)
			h.cleanup = func(context.Context, *config.Config) error {
				if name == "partial" || name == "rollback" {
					return errors.New("nat removed then filter failed")
				}
				return nil
			}
			if name == "save" {
				h.cfgPath = t.TempDir()
			}
			restored := 0
			h.firewall = func(ctx context.Context, _ *config.Config, _ *config.SiteLinkSnapshot, peers []config.SiteLinkTransitPeer, allow bool) error {
				restored++
				if ctx.Err() != nil || allow || len(peers) == 0 {
					t.Fatal("guard rollback invalid")
				}
				if name == "rollback" {
					return errors.New("restore failed")
				}
				return nil
			}
			raw, _ := json.Marshal(p)
			_, err := h.handleTeardown(raw)
			if err == nil || restored != 1 {
				t.Fatalf("failure hidden or guard forgotten: %v", err)
			}
			if name == "rollback" && !strings.Contains(err.Error(), "restore failed") {
				t.Fatal("degraded rollback hidden")
			}
			if h.cfg.Snapshot().SiteLinkDesired == nil || h.cfg.Snapshot().SiteLinkTeardown != nil {
				t.Fatal("failed teardown cleared persisted protection")
			}
			if name != "save" {
				if err := h.cfg.Save(h.cfgPath); err != nil {
					t.Fatal(err)
				}
				loaded, err := config.Load(h.cfgPath)
				if err != nil || loaded.SiteLinkDesired == nil || len(loaded.SiteLinkGuardPeers) == 0 {
					t.Fatal("crash lost guard")
				}
			}
		})
	}
}

func TestSiteTeardownFirewallOwnedOnlyAndCollisions(t *testing.T) {
	h, _ := teardownFixture(t)
	saved := h.cfg.Snapshot()
	oldIPT, oldRestore := edgeIPTables, edgeIPTablesRestore
	t.Cleanup(func() { edgeIPTables, edgeIPTablesRestore = oldIPT, oldRestore })
	rules := siteFirewallRules(saved, saved.SiteLinkDesired, saved.SiteLinkGuardPeers, false)
	var filter strings.Builder
	filter.WriteString("-P FORWARD ACCEPT\n-N UNRELATED\n-A FORWARD -j UNRELATED\n")
	for _, chain := range []string{"WW-SITE-FWD", "WW-SITE-IN", "WW-SITE-OUT", "WW-SITE-DST"} {
		filter.WriteString("-N " + chain + "\n")
		for _, rule := range rules[chain] {
			filter.WriteString(rule + "\n")
		}
	}
	for _, parent := range []string{"FORWARD", "INPUT", "OUTPUT"} {
		filter.WriteString("-A " + parent + " -m comment --comment " + siteComment + " -j " + siteChains[parent] + "\n")
	}
	body := filter.String()
	nat := "-N WW-SITE-NAT\n-A POSTROUTING -m comment --comment " + siteComment + " -j WW-SITE-NAT\n-A POSTROUTING -o eth0 -j MASQUERADE\n"
	edgeIPTables = func(_ context.Context, args ...string) ([]byte, error) {
		if args[1] == "filter" {
			return []byte(body), nil
		}
		return []byte(nat), nil
	}
	commits := []string{}
	edgeIPTablesRestore = func(_ context.Context, input string) error { commits = append(commits, input); return nil }
	if err := cleanupSiteFirewall(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	if len(commits) != 2 || !strings.HasPrefix(commits[0], "*nat") || strings.Contains(strings.Join(commits, ""), "UNRELATED") || strings.Contains(strings.Join(commits, ""), "MASQUERADE") {
		t.Fatal("cleanup touched unrelated rules")
	}
	for _, collision := range []string{"-A UNRELATED -j WW-SITE-DST\n", "-A WW-SITE-FWD -j ACCEPT\n"} {
		body = filter.String() + collision
		commits = nil
		if err := cleanupSiteFirewall(context.Background(), saved); !errors.Is(err, errSiteTeardownPreflight) {
			t.Fatalf("collision not rejected: %v", err)
		}
		if len(commits) != 0 {
			t.Fatal("collision detected after mutation")
		}
	}
	// A collision must not trigger a rollback that flushes the foreign rule.
	h.firewall = func(context.Context, *config.Config, *config.SiteLinkSnapshot, []config.SiteLinkTransitPeer, bool) error {
		t.Fatal("preflight collision mutated guard")
		return nil
	}
	p := siteTeardownParams{SchemaVersion: 1, AgentID: saved.AgentID, Revision: saved.SiteLinkDesired.Revision, DesiredHash: saved.SiteLinkDesired.DesiredHash}
	raw, _ := json.Marshal(p)
	if _, err := h.handleTeardown(raw); err == nil {
		t.Fatal("collision teardown succeeded")
	}
	if _, err := os.Stat(h.cfgPath); !os.IsNotExist(err) {
		t.Fatal("collision persisted release")
	}
}
