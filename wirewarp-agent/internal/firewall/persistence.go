// Package firewall persists only WireWarp-owned rules when UFW owns the host.
package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Table struct {
	Chains  []string        `json:"chains"`
	Rules   []string        `json:"rules"`
	Parents map[string]bool `json:"-"`
}
type Journal struct {
	Schema     int              `json:"schema"`
	AgentID    string           `json:"agent_id"`
	ConfigPath string           `json:"config_path"`
	Tables     map[string]Table `json:"tables"`
}
type Store struct {
	Path          string
	UFWConfig     string
	UFWDefaults   string
	Owner         func() (string, string)
	UnitReady     func(context.Context) error
	DockerAllowed func(string, string) bool
	Run           func(context.Context, string, string, ...string) ([]byte, error)
	mu            sync.Mutex
}

var defaultMu sync.RWMutex
var defaultStore = &Store{Path: "/var/lib/wirewarp/firewall.json", UFWConfig: "/etc/ufw/ufw.conf", UFWDefaults: "/etc/default/ufw", Run: Run}

func Configure(owner func() (string, string), unit func(context.Context) error, docker ...func(string, string) bool) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultStore = &Store{Path: "/var/lib/wirewarp/firewall.json", UFWConfig: "/etc/ufw/ufw.conf", UFWDefaults: "/etc/default/ufw", Owner: owner, UnitReady: unit, Run: Run}
	if len(docker) > 0 {
		defaultStore.DockerAllowed = docker[0]
	}
}
func Save(ctx context.Context) error {
	defaultMu.RLock()
	s := defaultStore
	defaultMu.RUnlock()
	return s.Save(ctx)
}
func Restore(ctx context.Context) error {
	defaultMu.RLock()
	s := defaultStore
	defaultMu.RUnlock()
	return s.Restore(ctx)
}
func Check(ctx context.Context) error {
	defaultMu.RLock()
	s := defaultStore
	defaultMu.RUnlock()
	_, err := s.ufw(ctx)
	return err
}

// ValidateIdentity checks an existing journal without adopting or restoring it.
func ValidateIdentity(agentID, configPath string) error {
	defaultMu.RLock()
	s := defaultStore
	defaultMu.RUnlock()
	return s.ValidateIdentity(agentID, configPath)
}

func (s *Store) ValidateIdentity(agentID, configPath string) error {
	if agentID == "" {
		return fmt.Errorf("owned firewall identity is missing")
	}
	path, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("owned firewall config path is invalid")
	}
	_, err = s.load(agentID, path)
	return err
}

// Preflight checks every reserved chain before a runtime can replace it.
// Legacy rules must come from the caller's saved desired state.
func Preflight(ctx context.Context, legacy map[string][]string) error {
	defaultMu.RLock()
	s := defaultStore
	defaultMu.RUnlock()
	return s.Preflight(ctx, legacy)
}
func (s *Store) Preflight(ctx context.Context, legacy map[string][]string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := s.ufw(ctx); err != nil {
		return err
	}
	var previous *Journal
	if _, err := os.Lstat(s.Path); err == nil {
		id, path, err := s.identity()
		if err != nil {
			return err
		}
		previous, err = s.load(id, path)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	_, err := s.capture(ctx, previous, false, legacy)
	return err
}

// Run cancels the exact process group, including persistence plugin children.
func Run(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return cmd.CombinedOutput()
}
func (s *Store) runner(ctx context.Context, input, binary string, args ...string) ([]byte, error) {
	if s.Run != nil {
		return s.Run(ctx, input, binary, args...)
	}
	return Run(ctx, input, binary, args...)
}
func settings(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		key, value, ok := strings.Cut(line, "=")
		if ok {
			out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return out, nil
}
func (s *Store) ufw(ctx context.Context) (bool, error) {
	conf, err := settings(s.UFWConfig)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read UFW enablement: %w", err)
	}
	if strings.ToLower(conf["ENABLED"]) != "yes" {
		return false, nil
	}
	defaults, err := settings(s.UFWDefaults)
	if err != nil {
		return false, fmt.Errorf("read UFW persistence compatibility: %w", err)
	}
	if strings.ToLower(defaults["MANAGE_BUILTINS"]) != "no" {
		return false, fmt.Errorf("active UFW requires MANAGE_BUILTINS=no for WireWarp persistence")
	}
	return true, nil
}
func (s *Store) identity() (string, string, error) {
	if s.Owner == nil {
		return "", "", fmt.Errorf("owned firewall persistence has no installation owner")
	}
	id, path := s.Owner()
	if id == "" || !filepath.IsAbs(path) {
		return "", "", fmt.Errorf("owned firewall persistence requires a registered installation owner")
	}
	return id, path, nil
}
func (s *Store) locked(ctx context.Context, fn func() error) error {
	for !s.mu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer s.mu.Unlock()
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("owned firewall directory is unsafe")
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("owned firewall directory owner is unsafe")
	}
	fd, err := unix.Open(s.Path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("open owned firewall lock: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("owned firewall lock is unsafe")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}
func (s *Store) Save(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ufw, err := s.ufw(ctx)
	if err != nil {
		return err
	}
	if !ufw {
		out, err := s.runner(ctx, "", "netfilter-persistent", "save")
		if err != nil {
			return fmt.Errorf("netfilter-persistent save: %w: %s", err, strings.TrimSpace(string(out)))
		}
		// A successful traditional save replaces the authoritative inventory.
		// Retire an owned journal so a later UFW enable cannot replay stale rules.
		if _, err := os.Lstat(s.Path); os.IsNotExist(err) {
			return nil
		}
		id, path, err := s.identity()
		if err != nil {
			return err
		}
		return s.locked(ctx, func() error {
			if _, err := s.load(id, path); err != nil {
				return err
			}
			if err := os.Remove(s.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
			dir, err := os.Open(filepath.Dir(s.Path))
			if err != nil {
				return err
			}
			defer dir.Close()
			return dir.Sync()
		})
	}
	if s.UnitReady == nil {
		return fmt.Errorf("owned firewall restore unit is not configured")
	}
	id, path, err := s.identity()
	if err != nil {
		return err
	}
	return s.locked(ctx, func() error {
		previous, err := s.load(id, path)
		if err != nil {
			return err
		}
		tables, err := s.capture(ctx, previous, true)
		if err != nil {
			return err
		}
		if err := s.UnitReady(ctx); err != nil {
			return fmt.Errorf("owned firewall restore unit is not ready: %w", err)
		}
		return s.write(&Journal{Schema: 1, AgentID: id, ConfigPath: path, Tables: tables})
	})
}
func (s *Store) load(id, path string) (*Journal, error) {
	fi, err := os.Lstat(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || fi.Size() > 2<<20 {
		return nil, fmt.Errorf("owned firewall journal file is unsafe")
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var j Journal
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&j) != nil || decoder.Decode(new(any)) != io.EOF || j.Schema != 1 || j.AgentID != id || j.ConfigPath != path {
		return nil, fmt.Errorf("owned firewall journal owner or schema mismatch")
	}
	if err := validateTables(j.Tables); err != nil {
		return nil, err
	}
	return &j, nil
}
func (s *Store) write(j *Journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.Path), ".firewall-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.Path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.Path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

var chainOwner = map[string]string{"WW-EDGE-INGRESS": "wirewarp-edge-ingress", "WW-SITE-FWD": "wirewarp-site-links", "WW-SITE-IN": "wirewarp-site-links", "WW-SITE-OUT": "wirewarp-site-links", "WW-SITE-DST": "wirewarp-site-links", "WW-SITE-NAT": "wirewarp-site-links"}
var comments = map[string]bool{"wirewarp-edge-ingress": true, "wirewarp-site-links": true, "wirewarp-server-masquerade": true, "wirewarp-lan-snat": true, "wirewarp-raw-forward": true, "wirewarp-server-mss": true, "wirewarp-vpn-peer": true, "wirewarp-vpn-drop": true, "wirewarp-vpn-mss": true, "wirewarp-gateway-mangle": true, "wirewarp-gateway-mss": true, "wirewarp-gateway-forward": true, "wirewarp-gateway-nat": true, "wirewarp-gateway-docker-user": true}
var tableChains = map[string]map[string]bool{"filter": {"INPUT": true, "OUTPUT": true, "FORWARD": true, "DOCKER-USER": true}, "nat": {"PREROUTING": true, "POSTROUTING": true, "OUTPUT": true}, "mangle": {"PREROUTING": true, "POSTROUTING": true, "OUTPUT": true, "FORWARD": true}}

func flag(fields []string, name string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == name {
			return strings.Trim(fields[i+1], `"`)
		}
	}
	return ""
}
func ownedRule(table, line string) (bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 || fields[0] != "-A" {
		return false, fmt.Errorf("invalid owned firewall rule")
	}
	source := fields[1]
	comment := flag(fields, "--comment")
	target := flag(fields, "-j")
	if target == "" {
		target = flag(fields, "-g")
	}
	if owner := chainOwner[source]; owner != "" {
		if comment != owner || (source == "WW-SITE-NAT") != (table == "nat") || table != "nat" && table != "filter" {
			return false, fmt.Errorf("reserved firewall chain contains an unowned rule")
		}
		if chainOwner[target] != "" {
			if chainOwner[target] != owner {
				return false, fmt.Errorf("owned firewall chain references another owner")
			}
			return true, nil
		}
		if target != "ACCEPT" && target != "DROP" && target != "RETURN" && !(table == "nat" && target == "SNAT") {
			return false, fmt.Errorf("owned firewall chain has an unsafe target")
		}
		return true, nil
	}
	if owner := chainOwner[target]; owner != "" {
		if comment != owner || !tableChains[table][source] || source == "DOCKER-USER" || (target == "WW-SITE-NAT") != (table == "nat") {
			return false, fmt.Errorf("reserved firewall chain has an unowned reference")
		}
		return true, nil
	}
	if !comments[comment] {
		return false, nil
	}
	if source == "DOCKER-USER" && (table != "filter" || comment != "wirewarp-gateway-docker-user" || target != "ACCEPT" || flag(fields, "-i") == "" || flag(fields, "-o") == "") {
		return false, fmt.Errorf("owned Docker inventory is not a scoped ACCEPT")
	}
	if !map[string]bool{"ACCEPT": true, "DROP": true, "RETURN": true, "SNAT": true, "DNAT": true, "MASQUERADE": true, "TCPMSS": true, "CONNMARK": true, "MARK": true}[target] {
		return false, fmt.Errorf("owned firewall rule has an unknown target")
	}
	if !tableChains[table][source] || strings.HasPrefix(target, "ufw-") || target == "" {
		return false, fmt.Errorf("owned firewall rule has an unsafe chain")
	}
	return true, nil
}
func validateTables(tables map[string]Table) error {
	if len(tables) != 3 {
		return fmt.Errorf("owned firewall journal has unknown tables")
	}
	for table, data := range tables {
		if tableChains[table] == nil || len(data.Rules) > 10000 {
			return fmt.Errorf("owned firewall journal table is invalid")
		}
		known := map[string]bool{}
		for _, chain := range data.Chains {
			if chainOwner[chain] == "" || known[chain] || chain == "WW-SITE-NAT" && table != "nat" || chain != "WW-SITE-NAT" && table != "filter" {
				return fmt.Errorf("owned firewall journal chain is invalid")
			}
			known[chain] = true
		}
		for _, line := range data.Rules {
			if strings.ContainsAny(line, "\r\n\x00") {
				return fmt.Errorf("owned firewall journal rule is invalid")
			}
			owned, err := ownedRule(table, line)
			if err != nil || !owned {
				return fmt.Errorf("owned firewall journal contains a foreign rule")
			}
			fields := strings.Fields(line)
			if chainOwner[fields[1]] != "" && !known[fields[1]] || chainOwner[flag(fields, "-j")] != "" && !known[flag(fields, "-j")] {
				return fmt.Errorf("owned firewall journal references an undeclared chain")
			}
		}
	}
	return nil
}
func (s *Store) capture(ctx context.Context, previous *Journal, preserveDeferred bool, legacy ...map[string][]string) (map[string]Table, error) {
	tables := map[string]Table{}
	for _, table := range []string{"filter", "mangle", "nat"} {
		out, err := s.runner(ctx, "", "iptables", "-w", "5", "-t", table, "-S")
		if err != nil {
			return nil, fmt.Errorf("inspect owned firewall %s: %w", table, err)
		}
		data := Table{Parents: map[string]bool{}}
		evidence := map[string]bool{}
		if previous != nil {
			for _, chain := range previous.Tables[table].Chains {
				evidence[chain] = true
			}
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if fields[0] == "-N" || fields[0] == "-P" {
				data.Parents[fields[1]] = true
			}
			if fields[0] == "-N" && chainOwner[fields[1]] != "" {
				data.Chains = append(data.Chains, fields[1])
				continue
			}
			if fields[0] != "-A" {
				continue
			}
			owned, err := ownedRule(table, line)
			if err != nil {
				accepted := false
				if len(legacy) > 0 && chainOwner[fields[1]] != "" && flag(fields, "--comment") == "" {
					for _, allowed := range legacy[0][table] {
						if strings.Join(strings.Fields(line), " ") == strings.Join(strings.Fields(allowed), " ") {
							accepted = true
							break
						}
					}
				}
				if accepted {
					evidence[fields[1]] = true
					continue
				}
				return nil, err
			}
			if owned {
				data.Rules = append(data.Rules, line)
				if chainOwner[fields[1]] != "" {
					evidence[fields[1]] = true
				}
				if target := flag(fields, "-j"); chainOwner[target] != "" {
					evidence[target] = true
				}
			}
		}
		for _, chain := range data.Chains {
			if !evidence[chain] {
				return nil, fmt.Errorf("reserved firewall chain has no ownership marker")
			}
		}
		if preserveDeferred && table == "filter" && !data.Parents["DOCKER-USER"] && previous != nil {
			for _, line := range previous.Tables[table].Rules {
				fields := strings.Fields(line)
				if fields[1] == "DOCKER-USER" && s.DockerAllowed != nil && s.DockerAllowed(flag(fields, "-i"), flag(fields, "-o")) {
					data.Rules = append(data.Rules, line)
				}
			}
		}
		tables[table] = data
	}
	return tables, validateTables(tables)
}
func (s *Store) Restore(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ufw, err := s.ufw(ctx)
	if err != nil {
		return err
	}
	if !ufw {
		return nil
	}
	if _, err := os.Lstat(s.Path); os.IsNotExist(err) {
		return nil
	}
	id, path, err := s.identity()
	if err != nil {
		return err
	}
	return s.locked(ctx, func() error {
		desired, err := s.load(id, path)
		if err != nil {
			return err
		}
		if desired == nil {
			return nil
		}
		current, err := s.capture(ctx, desired, false)
		if err != nil {
			return err
		}
		transactions := map[string]string{}
		deferred := 0
		applied := 0
		for _, table := range []string{"filter", "mangle", "nat"} {
			data := desired.Tables[table]
			rules := []string{}
			for _, line := range data.Rules {
				fields := strings.Fields(line)
				if fields[1] == "DOCKER-USER" && !current[table].Parents["DOCKER-USER"] {
					deferred++
					continue
				}
				if chainOwner[fields[1]] != "" && flag(fields, "--comment") == "wirewarp-site-links" && flag(fields, "-j") == "ACCEPT" {
					continue
				}
				rules = append(rules, line)
				applied++
			}
			data.Rules = rules
			transactions[table] = restoreTransaction(table, current[table], data)
		}
		for _, table := range []string{"filter", "mangle", "nat"} {
			if transactions[table] != "" {
				if _, err := s.runner(ctx, transactions[table], "iptables-restore", "--test", "--wait", "5", "--noflush"); err != nil {
					return fmt.Errorf("preflight owned firewall %s: %w", table, err)
				}
			}
		}
		for _, table := range []string{"filter", "mangle", "nat"} {
			if transactions[table] == "" {
				continue
			}
			if _, err := s.runner(ctx, transactions[table], "iptables-restore", "--wait", "5", "--noflush"); err != nil {
				return fmt.Errorf("restore owned firewall %s: %w", table, err)
			}
		}
		log.Printf("[firewall-restore] restored %d owned rules; deferred %d scoped Docker ACCEPT rules", applied, deferred)
		return nil
	})
}
func restoreTransaction(table string, current, desired Table) string {
	if len(current.Rules)+len(current.Chains)+len(desired.Rules)+len(desired.Chains) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("*" + table + "\n")
	want := map[string]bool{}
	for _, chain := range desired.Chains {
		want[chain] = true
		b.WriteString(":" + chain + " - [0:0]\n")
	}
	all := map[string]bool{}
	for _, chain := range current.Chains {
		all[chain] = true
	}
	for _, chain := range desired.Chains {
		all[chain] = true
	}
	names := []string{}
	for chain := range all {
		names = append(names, chain)
	}
	sort.Strings(names)
	for _, line := range current.Rules {
		fields := strings.Fields(line)
		if chainOwner[fields[1]] == "" {
			b.WriteString(strings.Replace(line, "-A", "-D", 1) + "\n")
		}
	}
	for _, chain := range names {
		b.WriteString("-F " + chain + "\n")
	}
	for _, chain := range names {
		if !want[chain] {
			b.WriteString("-X " + chain + "\n")
		}
	}
	for _, line := range desired.Rules {
		fields := strings.Fields(line)
		if chainOwner[fields[1]] != "" {
			b.WriteString(line + "\n")
		}
	}
	// Reverse insertion preserves owned rule order and keeps guards first.
	builtins := []string{}
	for _, line := range desired.Rules {
		fields := strings.Fields(line)
		if chainOwner[fields[1]] == "" {
			builtins = append(builtins, line)
		}
	}
	sort.SliceStable(builtins, func(i, j int) bool { return rulePriority(builtins[i]) < rulePriority(builtins[j]) })
	for i := len(builtins) - 1; i >= 0; i-- {
		b.WriteString(strings.Replace(builtins[i], "-A", "-I", 1) + "\n")
	}
	b.WriteString("COMMIT\n")
	return b.String()
}
func rulePriority(line string) int {
	fields := strings.Fields(line)
	switch flag(fields, "--comment") {
	case "wirewarp-edge-ingress":
		return 0
	case "wirewarp-site-links":
		return 1
	}
	return 2
}
