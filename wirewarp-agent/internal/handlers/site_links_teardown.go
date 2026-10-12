package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/wirewarp/agent/internal/config"
)

type siteTeardownParams struct {
	SchemaVersion int    `json:"schema_version"`
	AgentID       string `json:"agent_id"`
	Revision      int64  `json:"revision"`
	DesiredHash   string `json:"desired_hash"`
}

var errSiteTeardownPreflight = errors.New("site-link teardown preflight failed")

func (h *SiteLinkHandlers) handleTeardown(raw json.RawMessage) (string, error) {
	var p siteTeardownParams
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 4096 || decoder.Decode(&p) != nil || decoder.Decode(new(any)) != io.EOF || p.SchemaVersion != 1 || p.Revision <= 0 || !siteUUID.MatchString(p.AgentID) || len(p.DesiredHash) != 64 {
		return "", fmt.Errorf("invalid site-link teardown parameters")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	saved := h.cfg.Snapshot()
	if p.AgentID != saved.AgentID {
		return "", fmt.Errorf("site-link teardown owner does not match this agent")
	}
	response, _ := json.Marshal(map[string]any{"released": true, "revision": p.Revision, "desired_hash": p.DesiredHash})
	if saved.SiteLinkDesired == nil && saved.SiteLinkApplied == nil && len(saved.SiteLinkRoutes) == 0 && len(saved.SiteLinkGuardPeers) == 0 {
		if r := saved.SiteLinkTeardown; r != nil && r.AgentID == p.AgentID && r.Revision == p.Revision && r.DesiredHash == p.DesiredHash {
			return string(response), nil
		}
	}
	desired, applied := saved.SiteLinkDesired, saved.SiteLinkApplied
	if desired == nil || applied == nil || desired.OwnerAgentID != p.AgentID || applied.OwnerAgentID != p.AgentID || desired.Revision != p.Revision || applied.Revision != p.Revision || desired.DesiredHash != p.DesiredHash || applied.DesiredHash != p.DesiredHash || len(desired.Links) != 0 || len(applied.Links) != 0 || len(saved.SiteLinkRoutes) != 0 {
		return "", fmt.Errorf("site-link teardown requires the exact applied empty topology")
	}
	if err := validateSiteSnapshot(saved, desired); err != nil {
		return "", err
	}
	if err := validateSiteSnapshot(saved, applied); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rollback := func(cause error) error {
		retry, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := h.firewall(retry, saved, desired, siteUnionPeers(saved.SiteLinkGuardPeers, desired.TransitPeers), false); err != nil {
			return fmt.Errorf("site-link teardown failed; deny guard restore failed: %v; %w", err, cause)
		}
		if err := h.persistFirewall(retry); err != nil {
			return fmt.Errorf("site-link teardown failed; deny guard restored but firewall persistence failed: %v; %w", err, cause)
		}
		return fmt.Errorf("site-link teardown failed; deny guard restored: %w", cause)
	}
	if err := h.cleanup(ctx, saved); err != nil {
		if errors.Is(err, errSiteTeardownPreflight) {
			return "", err
		}
		return "", rollback(err)
	}
	if err := h.persistFirewall(ctx); err != nil {
		return "", rollback(err)
	}
	if err := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
		next.SiteLinkDesired = nil
		next.SiteLinkApplied = nil
		next.SiteLinkGuardPeers = nil
		next.SiteLinkRoutes = nil
		next.SiteLinkTeardown = &config.SiteLinkTeardownReceipt{AgentID: p.AgentID, Revision: p.Revision, DesiredHash: p.DesiredHash}
		return nil
	}); err != nil {
		return "", rollback(fmt.Errorf("persist released site-link state: %w", err))
	}
	return string(response), nil
}

func persistSiteFirewall(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	bin := resolveBin("netfilter-persistent", "/usr/sbin/netfilter-persistent", "/sbin/netfilter-persistent")
	cmd := exec.CommandContext(ctx, bin, "save")
	// Save plugins are child processes. Cancel the exact command group so a
	// timed-out plugin cannot save old rules after guard rollback.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("persist site-link firewall: %w: %s", err, tail(out, 6))
	}
	return nil
}

// Inspect both tables before committing either. Unknown references and foreign
// rules in reserved chains block teardown instead of being flushed.
func cleanupSiteFirewall(ctx context.Context, saved *config.Config) error {
	transactions, err := siteTeardownTransactions(ctx, saved)
	if err != nil {
		return fmt.Errorf("%w: %v", errSiteTeardownPreflight, err)
	}
	for _, table := range []string{"nat", "filter"} {
		if transaction := transactions[table]; transaction != "" {
			if err := edgeIPTablesRestore(ctx, transaction); err != nil {
				return fmt.Errorf("remove owned site-link %s rules: %w", table, err)
			}
		}
	}
	return nil
}

func siteTeardownRuleKey(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return line
	}
	options := []string{}
	for i := 2; i < len(fields); i += 2 {
		if i+1 >= len(fields) {
			return line
		}
		options = append(options, fields[i]+"="+fields[i+1])
	}
	sort.Strings(options)
	return fields[0] + " " + fields[1] + " " + strings.Join(options, " ")
}

func siteTeardownTransactions(ctx context.Context, saved *config.Config) (map[string]string, error) {
	expected := siteFirewallRules(saved, saved.SiteLinkDesired, siteUnionPeers(saved.SiteLinkGuardPeers, saved.SiteLinkDesired.TransitPeers), false)
	transactions := map[string]string{}
	for _, table := range []string{"nat", "filter"} {
		chains := []string{"WW-SITE-NAT"}
		parents := []string{"POSTROUTING"}
		if table == "filter" {
			chains = []string{"WW-SITE-FWD", "WW-SITE-IN", "WW-SITE-OUT", "WW-SITE-DST"}
			parents = []string{"FORWARD", "INPUT", "OUTPUT"}
		}
		owned := map[string]bool{}
		for _, chain := range chains {
			owned[chain] = true
		}
		allowed := map[string]bool{}
		for _, chain := range chains {
			for _, rule := range expected[chain] {
				allowed[siteTeardownRuleKey(rule)] = true
			}
		}
		jumps := map[string]bool{}
		for _, parent := range parents {
			jumps["-A "+parent+" -m comment --comment "+siteComment+" -j "+siteChains[parent]] = true
		}
		out, err := edgeIPTables(ctx, "-t", table, "-S")
		if err != nil {
			return nil, fmt.Errorf("inspect site-link teardown table: %w", err)
		}
		existing := map[string]bool{}
		remove := []string{}
		for _, raw := range strings.Split(string(out), "\n") {
			line := strings.ReplaceAll(strings.TrimSpace(raw), `"`, "")
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "-N" && owned[fields[1]] {
				existing[fields[1]] = true
				continue
			}
			if len(fields) < 2 || fields[0] != "-A" {
				continue
			}
			if owned[fields[1]] {
				if !allowed[siteTeardownRuleKey(line)] {
					return nil, fmt.Errorf("reserved site-link chain contains an unexpected rule")
				}
				continue
			}
			references := false
			for i := 2; i+1 < len(fields); i++ {
				if (fields[i] == "-j" || fields[i] == "-g") && owned[fields[i+1]] {
					references = true
				}
			}
			if references {
				if !jumps[line] {
					return nil, fmt.Errorf("reserved site-link chain has an unexpected reference")
				}
				remove = append(remove, strings.Replace(line, "-A", "-D", 1))
			}
		}
		if len(existing) == 0 && len(remove) == 0 {
			continue
		}
		var transaction strings.Builder
		transaction.WriteString("*" + table + "\n")
		for _, chain := range chains {
			if existing[chain] {
				transaction.WriteString("-F " + chain + "\n")
			}
		}
		for _, rule := range remove {
			transaction.WriteString(rule + "\n")
		}
		for _, chain := range chains {
			if existing[chain] {
				transaction.WriteString("-X " + chain + "\n")
			}
		}
		transaction.WriteString("COMMIT\n")
		transactions[table] = transaction.String()
	}
	return transactions, nil
}
