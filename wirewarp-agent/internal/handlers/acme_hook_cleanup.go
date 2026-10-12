package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const acmeCleanupDir = "/var/lib/wirewarp/acme-dns"
const acmeAbandonedGrace = 15 * time.Minute

var errACMEIssuerStopped = errors.New("ACME issuer has stopped")

// CA Retry-After can extend Lego validation. Never expire a live issuer by age.
// The grace starts only after its boot ID and process start time no longer match.
type acmeIssuer struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
	Boot  string `json:"boot"`
}

type acmeCredentialReference struct {
	Nameserver string `json:"nameserver"`
	Key        string `json:"key"`
	Algorithm  string `json:"algorithm"`
	SecretFile string `json:"secret_file"`
}

type acmeChallengeLease struct {
	Issuer      acmeIssuer              `json:"issuer"`
	Credentials acmeCredentialReference `json:"credentials"`
	Count       int                     `json:"count"`
	AbandonedAt int64                   `json:"abandoned_at,omitempty"`
}

type acmeChallengeJournal struct {
	Version     int                      `json:"version"`
	FQDN        string                   `json:"fqdn"`
	Value       string                   `json:"value"`
	Zone        string                   `json:"zone"`
	Leases      []acmeChallengeLease     `json:"leases"`
	Pending     *acmeCredentialReference `json:"pending,omitempty"`
	LastAttempt int64                    `json:"last_attempt,omitempty"`
}

func (s acmeCleanupStore) inventory() ([]os.DirEntry, error) {
	directory, err := os.Open(s.dir)
	if err != nil {
		return nil, errors.New("ACME cleanup inventory unavailable")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(4097)
	if (err != nil && err != io.EOF) || len(entries) > 4096 {
		return nil, errors.New("ACME cleanup inventory limit reached")
	}
	return entries, nil
}

type acmeCleanupStore struct {
	dir   string
	owner uint32
}

func currentACMEIssuer(pid int) (acmeIssuer, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return acmeIssuer{}, errors.New("ACME issuer identity unavailable")
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return acmeIssuer{}, errors.New("ACME issuer identity unavailable")
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return acmeIssuer{}, errors.New("ACME issuer identity unavailable")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return acmeIssuer{}, errors.New("ACME issuer identity unavailable")
	}
	if fields[0] == "Z" {
		return acmeIssuer{}, errACMEIssuerStopped
	}
	return acmeIssuer{PID: pid, Start: fields[19], Boot: strings.TrimSpace(string(boot))}, nil
}

func acmeIssuerAlive(issuer acmeIssuer) bool {
	// An unreadable process inventory cannot prove that an issuer has stopped.
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", issuer.PID)); err != nil {
		return !os.IsNotExist(err)
	}
	current, err := currentACMEIssuer(issuer.PID)
	return (err != nil && !errors.Is(err, errACMEIssuerStopped)) || (err == nil && current == issuer)
}

func (s acmeCleanupStore) lock(ctx context.Context) (*os.File, error) {
	if !filepath.IsAbs(s.dir) {
		return nil, errors.New("ACME cleanup directory is invalid")
	}
	// Reject redirected or writable ancestors before creating any owned files.
	for path := s.dir; path != "/"; path = filepath.Dir(path) {
		var ancestor unix.Stat_t
		err := unix.Lstat(path, &ancestor)
		if err == unix.ENOENT {
			continue
		}
		if err != nil || ancestor.Mode&unix.S_IFMT != unix.S_IFDIR || (ancestor.Uid != 0 && ancestor.Uid != s.owner) || (ancestor.Mode&0022 != 0 && ancestor.Mode&unix.S_ISVTX == 0) {
			return nil, errors.New("ACME cleanup directory ancestry is invalid")
		}
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return nil, errors.New("ACME cleanup directory unavailable")
	}
	var stat unix.Stat_t
	if unix.Lstat(s.dir, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0777 != 0700 || stat.Uid != s.owner {
		return nil, errors.New("ACME cleanup directory requires root ownership and mode 0700")
	}
	fd, err := unix.Open(filepath.Join(s.dir, "lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("ACME cleanup lock unavailable")
	}
	file := os.NewFile(uintptr(fd), "ACME cleanup lock")
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != s.owner {
		file.Close()
		return nil, errors.New("ACME cleanup lock permissions are invalid")
	}
	for {
		if ctx.Err() != nil {
			file.Close()
			return nil, errors.New("ACME cleanup lock deadline exceeded")
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			file.Close()
			return nil, errors.New("ACME cleanup lock failed")
		}
		if !waitACMEDNS(ctx, 10*time.Millisecond) {
			file.Close()
			return nil, errors.New("ACME cleanup lock deadline exceeded")
		}
	}
}

func acmeJournalID(primary, fqdn, value string) string {
	sum := sha256.Sum256([]byte(primary + "\x00" + fqdn + "\x00" + value))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (s acmeCleanupStore) read(name string) (*acmeChallengeJournal, error) {
	if len(name) != 69 || !strings.HasSuffix(name, ".json") {
		return nil, errors.New("ACME cleanup record name is invalid")
	}
	if _, err := hex.DecodeString(name[:64]); err != nil {
		return nil, errors.New("ACME cleanup record name is invalid")
	}
	fd, err := unix.Open(filepath.Join(s.dir, name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("ACME cleanup record unavailable")
	}
	file := os.NewFile(uintptr(fd), "ACME cleanup record")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != s.owner || stat.Size > 65536 {
		return nil, errors.New("ACME cleanup record permissions are invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return nil, errors.New("ACME cleanup record unreadable")
	}
	var record acmeChallengeJournal
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || !validACMEHookName(record.FQDN) || !validACMEHookName(record.Zone) || !dns.IsSubDomain(record.Zone, record.FQDN) || !acmeHookValue.MatchString(record.Value) || len(record.Leases) > 128 {
		return nil, errors.New("ACME cleanup record is invalid")
	}
	primary := ""
	check := func(c acmeCredentialReference) bool {
		if !filepath.IsAbs(c.SecretFile) || c.Nameserver == "" || c.Key == "" || c.Algorithm == "" {
			return false
		}
		if primary != "" && primary != c.Nameserver {
			return false
		}
		primary = c.Nameserver
		return true
	}
	for _, lease := range record.Leases {
		_, startErr := strconv.ParseUint(lease.Issuer.Start, 10, 64)
		if lease.Count < 1 || lease.Count > 1024 || lease.Issuer.PID < 1 || startErr != nil || lease.Issuer.Boot == "" || !check(lease.Credentials) {
			return nil, errors.New("ACME cleanup lease is invalid")
		}
	}
	if record.Pending != nil && !check(*record.Pending) {
		return nil, errors.New("ACME cleanup credential reference is invalid")
	}
	if primary == "" || name != acmeJournalID(primary, record.FQDN, record.Value) {
		return nil, errors.New("ACME cleanup record identity is invalid")
	}
	return &record, nil
}

func (s acmeCleanupStore) write(name string, record *acmeChallengeJournal) error {
	data, err := json.Marshal(record)
	if err != nil || len(data) > 65536 {
		return errors.New("ACME cleanup record too large")
	}
	temp, err := os.CreateTemp(s.dir, ".pending-")
	if err != nil {
		return errors.New("ACME cleanup record could not be created")
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tempName, filepath.Join(s.dir, name))
	}
	if err == nil {
		err = s.sync()
	}
	if err != nil {
		return errors.New("ACME cleanup record could not be persisted")
	}
	return nil
}

func (s acmeCleanupStore) sync() error {
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s acmeCleanupStore) remove(name string) error {
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !os.IsNotExist(err) {
		return errors.New("ACME cleanup record could not be removed")
	}
	if s.sync() != nil {
		return errors.New("ACME cleanup removal could not be persisted")
	}
	return nil
}

func (c acmeCredentialReference) load(owner uint32) (TraefikACMEParams, error) {
	return loadACMEHookCredentials(func(key string) string {
		switch key {
		case "RFC2136_NAMESERVER":
			return c.Nameserver
		case "RFC2136_TSIG_KEY":
			return c.Key
		case "RFC2136_TSIG_ALGORITHM":
			return c.Algorithm
		case "RFC2136_TSIG_SECRET_FILE":
			return c.SecretFile
		}
		return ""
	}, owner)
}

func (s acmeCleanupStore) finish(ctx context.Context, name string, record *acmeChallengeJournal) error {
	if len(record.Leases) > 0 || record.Pending == nil {
		return nil
	}
	// A nameserver rotation or alias must not let one generation delete a
	// challenge value that another generation still uses on the same node.
	entries, err := s.inventory()
	if err != nil {
		return errors.New("ACME cleanup inventory unavailable")
	}
	for _, entry := range entries {
		if entry.Name() == name || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		other, err := s.read(entry.Name())
		if err != nil {
			return err
		}
		if other != nil && other.FQDN == record.FQDN && other.Value == record.Value && len(other.Leases) > 0 {
			return nil
		}
	}
	credentials, err := record.Pending.load(s.owner)
	if err != nil {
		return err
	}
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: record.FQDN, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{record.Value}}
	if acmeHookUpdate(ctx, record.Zone, txt, credentials, true) != nil {
		return errors.New("ACME owned TXT cleanup remains pending")
	}
	return s.remove(name)
}

func runJournaledACMEDNSHook(ctx context.Context, args []string, credentials TraefikACMEParams, reference acmeCredentialReference, issuer acmeIssuer, store acmeCleanupStore) error {
	if len(args) != 3 || (args[0] != "present" && args[0] != "cleanup") || !validACMEHookName(args[1]) || !acmeHookValue.MatchString(args[2]) {
		return errors.New("ACME hook arguments are invalid")
	}
	if validateRFC2136ACME(credentials) != nil {
		return errors.New("ACME hook credentials are invalid")
	}
	lock, err := store.lock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	fqdn := dns.CanonicalName(args[1])
	name := acmeJournalID(reference.Nameserver, fqdn, args[2])
	record, err := store.read(name)
	if err != nil {
		return err
	}
	if args[0] == "cleanup" && record == nil {
		return nil
	} // No ownership record means no permission to delete.
	if record == nil {
		entries, err := store.inventory()
		if err != nil {
			return err
		}
		if len(entries) >= 4095 {
			return errors.New("ACME cleanup inventory limit reached")
		}
		zone, err := acmeHookZone(ctx, fqdn, credentials.RFC2136Nameserver)
		if err != nil {
			return errors.New("ACME hook authoritative zone discovery failed")
		}
		record = &acmeChallengeJournal{Version: 1, FQDN: fqdn, Value: args[2], Zone: zone}
	}
	index := -1
	for i, lease := range record.Leases {
		if lease.Issuer == issuer && lease.Credentials == reference {
			index = i
			break
		}
	}
	// A cleanup callback can arrive after the original issuer has restarted.
	if args[0] == "cleanup" && index < 0 {
		for i, lease := range record.Leases {
			if lease.Credentials == reference && !acmeIssuerAlive(lease.Issuer) {
				index = i
				break
			}
		}
	}
	if args[0] == "present" {
		if index < 0 {
			if len(record.Leases) >= 128 {
				return errors.New("ACME owned challenge lease limit reached")
			}
			record.Leases = append(record.Leases, acmeChallengeLease{Issuer: issuer, Credentials: reference, Count: 1})
		} else {
			if record.Leases[index].Count >= 1024 {
				return errors.New("ACME owned challenge reference limit reached")
			}
			record.Leases[index].Count++
			record.Leases[index].AbandonedAt = 0
		}
		record.Pending = nil
		if err := store.write(name, record); err != nil {
			return err
		}
		txt := &dns.TXT{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{args[2]}}
		if acmeHookUpdate(ctx, record.Zone, txt, credentials, false) == nil {
			return nil
		}
		// The insertion may have committed. Release only this invocation's lease.
		for i, lease := range record.Leases {
			if lease.Issuer == issuer && lease.Credentials == reference {
				index = i
				break
			}
		}
	} else if index < 0 {
		return store.finish(ctx, name, record)
	}
	if index >= 0 {
		record.Leases[index].Count--
		if record.Leases[index].Count == 0 {
			record.Leases = append(record.Leases[:index], record.Leases[index+1:]...)
		}
	}
	if len(record.Leases) == 0 {
		record.Pending = &reference
	}
	if err := store.write(name, record); err != nil {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), acmeHookCleanupTimeout)
	defer cancel()
	cleanupErr := store.finish(cleanupCtx, name, record)
	if args[0] == "present" {
		if cleanupErr != nil {
			return errors.New("ACME hook insertion failed; owned cleanup remains pending")
		}
		return errors.New("ACME hook insertion failed; owned challenge released")
	}
	return cleanupErr
}

// RetryACMEDNSCleanup retries bounded exact-value cleanup from immutable credentials.
// An active issuer always retains its TXT value, regardless of record age.
func RetryACMEDNSCleanup(ctx context.Context) error {
	return retryACMEDNSCleanup(ctx, acmeCleanupStore{acmeCleanupDir, 0}, time.Now(), acmeIssuerAlive)
}

func retryACMEDNSCleanup(ctx context.Context, store acmeCleanupStore, now time.Time, alive func(acmeIssuer) bool) error {
	ctx, cancel := context.WithTimeout(ctx, acmeHookTimeout)
	defer cancel()
	lock, err := store.lock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	entries, err := store.inventory()
	if err != nil {
		return errors.New("ACME cleanup inventory unavailable")
	}
	var failure error
	type candidate struct {
		name   string
		record *acmeChallengeJournal
	}
	var candidates []candidate
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := store.read(entry.Name())
		if err != nil {
			return err
		}
		if record == nil {
			continue
		}
		changed := false
		leases := record.Leases[:0]
		for _, lease := range record.Leases {
			if alive(lease.Issuer) {
				if lease.AbandonedAt != 0 {
					lease.AbandonedAt = 0
					changed = true
				}
				leases = append(leases, lease)
				continue
			}
			if lease.AbandonedAt == 0 || now.Unix() < lease.AbandonedAt {
				lease.AbandonedAt = now.Unix()
				changed = true
			}
			if now.Unix()-lease.AbandonedAt < int64(acmeAbandonedGrace/time.Second) {
				leases = append(leases, lease)
			} else {
				copy := lease.Credentials
				record.Pending = &copy
				changed = true
			}
		}
		record.Leases = leases
		if changed {
			if err = store.write(entry.Name(), record); err != nil {
				return err
			}
		}
		if len(record.Leases) == 0 && record.Pending != nil {
			candidates = append(candidates, candidate{entry.Name(), record})
		}
		if ctx.Err() != nil {
			return errors.New("ACME owned TXT cleanup deadline exceeded")
		}
	}
	// Persistent denied records must not starve later records across daemon restarts.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].record.LastAttempt == candidates[j].record.LastAttempt {
			return candidates[i].name < candidates[j].name
		}
		return candidates[i].record.LastAttempt < candidates[j].record.LastAttempt
	})
	for i, candidate := range candidates {
		if i >= 8 {
			break
		}
		if ctx.Err() != nil {
			return errors.New("ACME owned TXT cleanup deadline exceeded")
		}
		candidate.record.LastAttempt = now.UnixNano()
		if err := store.write(candidate.name, candidate.record); err != nil {
			return err
		}
		if err := store.finish(ctx, candidate.name, candidate.record); err != nil {
			failure = errors.New("ACME owned TXT cleanup remains pending")
		}
	}
	return failure
}

// ACMEDNSCleanupCredentialsInUse reports current references. Retain generations:
// this read alone cannot coordinate removal against a later hook invocation.
func ACMEDNSCleanupCredentialsInUse(path string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	store := acmeCleanupStore{acmeCleanupDir, 0}
	lock, err := store.lock(ctx)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	entries, err := store.inventory()
	if err != nil {
		return false, errors.New("ACME cleanup inventory unavailable")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := store.read(entry.Name())
		if err != nil {
			return false, err
		}
		if record == nil {
			continue
		}
		for _, lease := range record.Leases {
			if lease.Credentials.SecretFile == path {
				return true, nil
			}
		}
		if record.Pending != nil && record.Pending.SecretFile == path {
			return true, nil
		}
	}
	return false, nil
}
