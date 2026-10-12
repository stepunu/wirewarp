package handlers

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func init() {
	if payload := os.Getenv("WIREWARP_TEST_ACME_CHILD"); payload != "" {
		var input struct {
			Dir, Action, Value string
			Reference          acmeCredentialReference
		}
		if json.Unmarshal([]byte(payload), &input) != nil {
			os.Exit(2)
		}
		credentials, err := input.Reference.load(uint32(os.Getuid()))
		if err != nil {
			os.Exit(3)
		}
		issuer, err := currentACMEIssuer(os.Getppid())
		if err != nil {
			os.Exit(4)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if runJournaledACMEDNSHook(ctx, []string{input.Action, acmeHookTestName, input.Value}, credentials, input.Reference, issuer, acmeCleanupStore{input.Dir, uint32(os.Getuid())}) != nil {
			os.Exit(5)
		}
		os.Exit(0)
	}
}

func acmeChildCommand(t *testing.T, store acmeCleanupStore, reference acmeCredentialReference, action, value string) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(struct {
		Dir, Action, Value string
		Reference          acmeCredentialReference
	}{store.dir, action, value, reference})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "WIREWARP_TEST_ACME_CHILD="+string(payload))
	return cmd
}

func TestACMECleanupJournalSIGKILLAfterCommitRetainsOwnership(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}}
	committed := make(chan struct{})
	release := make(chan struct{})
	address := startACMETestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		if request.Opcode == dns.OpcodeUpdate && len(request.Ns) > 0 && request.Ns[0].Header().Class == dns.ClassINET {
			state.mu.Lock()
			state.values[strings.Repeat("A", 43)] = true
			state.mu.Unlock()
			close(committed)
			<-release
			return
		}
		state.handler(false)(w, request)
	})
	store, reference, _ := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	cmd := acmeChildCommand(t, store, reference, "present", value)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	select {
	case <-committed:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("child did not reach committed DNS insertion")
	}
	if err := cmd.Process.Kill(); err != nil {
		close(release)
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		close(release)
		t.Fatal("child survived SIGKILL")
	}
	close(release)
	name := acmeJournalID(address, acmeHookTestName, value)
	record, err := store.read(name)
	if err != nil || record == nil || len(record.Leases) != 1 {
		t.Fatal("SIGKILL lost the durable challenge owner")
	}
	now := time.Now()
	if err := retryACMEDNSCleanup(context.Background(), store, now, func(acmeIssuer) bool { return true }); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	if !state.values[value] {
		t.Error("still-active parent challenge was removed")
	}
	state.mu.Unlock()
	dead := func(acmeIssuer) bool { return false }
	if err := retryACMEDNSCleanup(context.Background(), store, now, dead); err != nil {
		t.Fatal(err)
	}
	if err := retryACMEDNSCleanup(context.Background(), store, now.Add(acmeAbandonedGrace+time.Second), dead); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.values[value] || !state.values["external"] {
		t.Fatal("killed helper ownership did not recover exactly")
	}
}

func TestACMECleanupJournalCrossProcessIdenticalValueReferences(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, _ := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	commands := []*exec.Cmd{acmeChildCommand(t, store, reference, "present", value), acmeChildCommand(t, store, reference, "present", value)}
	for _, cmd := range commands {
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatal("cross-process insertion failed")
		}
	}
	if err := acmeChildCommand(t, store, reference, "cleanup", value).Run(); err != nil {
		t.Fatal("first process cleanup failed")
	}
	state.mu.Lock()
	if !state.values[value] || state.removes != 0 {
		t.Error("first cleanup deleted another process reference")
	}
	state.mu.Unlock()
	if err := acmeChildCommand(t, store, reference, "cleanup", value).Run(); err != nil {
		t.Fatal("last process cleanup failed")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.values[value] || !state.values["external"] {
		t.Fatal("last cross-process cleanup failed")
	}
}

func cleanupFixture(t *testing.T, address string) (acmeCleanupStore, acmeCredentialReference, acmeIssuer) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "generation.secret")
	if err := os.WriteFile(secret, []byte(acmeTestSecret), 0600); err != nil {
		t.Fatal(err)
	}
	issuer, err := currentACMEIssuer(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return acmeCleanupStore{dir, uint32(os.Getuid())}, acmeCredentialReference{address, acmeTestKey, "hmac-sha256", secret}, issuer
}

func journalCall(ctx context.Context, action, value string, store acmeCleanupStore, reference acmeCredentialReference, issuer acmeIssuer) error {
	return runJournaledACMEDNSHook(ctx, []string{action, acmeHookTestName, value}, hookCredentials(reference.Nameserver), reference, issuer, store)
}

func TestACMECleanupJournalPersistsBeforeInsertionAndRecoversInterruptedOwner(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, issuer := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	// The durable intent is sufficient even if the helper dies before an acknowledgement.
	record := &acmeChallengeJournal{Version: 1, FQDN: acmeHookTestName, Value: value, Zone: acmeTestZone, Leases: []acmeChallengeLease{{Issuer: issuer, Credentials: reference, Count: 1}}}
	name := acmeJournalID(address, acmeHookTestName, value)
	if err := store.write(name, record); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.values[value] = true
	state.mu.Unlock()
	now := time.Now()
	dead := func(acmeIssuer) bool { return false }
	if err := retryACMEDNSCleanup(context.Background(), store, now, dead); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	if !state.values[value] {
		t.Error("dead issuer TXT was removed before the grace")
	}
	state.mu.Unlock()
	if err := retryACMEDNSCleanup(context.Background(), store, now.Add(acmeAbandonedGrace+time.Second), dead); err != nil {
		t.Fatal(err)
	}
	if record, err := store.read(name); err != nil || record != nil {
		t.Fatal("recovered cleanup did not remove journal")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.values[value] || !state.values["external"] {
		t.Fatal("recovery removed another TXT or missed its owned value")
	}
}

func TestACMECleanupJournalRetainsLiveIssuerAtAnyAge(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{}}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, issuer := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	if err := journalCall(context.Background(), "present", value, store, reference, issuer); err != nil {
		t.Fatal(err)
	}
	if err := retryACMEDNSCleanup(context.Background(), store, time.Now().Add(365*24*time.Hour), func(acmeIssuer) bool { return true }); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.values[value] || state.removes != 0 {
		t.Fatal("active challenge expired")
	}
}

func TestACMECleanupJournalPermanentDenialAndImmutableRotationRecovery(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, issuer := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	if err := journalCall(context.Background(), "present", value, store, reference, issuer); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.denyRemove = true
	state.mu.Unlock()
	if err := journalCall(context.Background(), "cleanup", value, store, reference, issuer); err == nil {
		t.Fatal("denied cleanup was hidden")
	}
	name := acmeJournalID(address, acmeHookTestName, value)
	record, err := store.read(name)
	if err != nil || record.Pending == nil || len(record.Leases) != 0 {
		t.Fatal("denied cleanup lost durable ownership")
	}
	// A later configuration uses another generation. Recovery must load the saved one.
	t.Setenv("RFC2136_TSIG_SECRET_FILE", filepath.Join(t.TempDir(), "missing-new-generation"))
	if err := retryACMEDNSCleanup(context.Background(), store, time.Now(), func(acmeIssuer) bool { return true }); err == nil {
		t.Fatal("permanent denial was hidden on retry")
	}
	state.mu.Lock()
	state.denyRemove = false
	state.mu.Unlock()
	if err := retryACMEDNSCleanup(context.Background(), store, time.Now(), func(acmeIssuer) bool { return true }); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.values[value] || !state.values["external"] {
		t.Fatal("rotation recovery did not perform exact cleanup")
	}
}

func TestACMECleanupJournalConcurrentIdenticalValuesUseRefcounts(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, issuer := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := journalCall(context.Background(), "present", value, store, reference, issuer); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 7; i++ {
		if err := journalCall(context.Background(), "cleanup", value, store, reference, issuer); err != nil {
			t.Fatal(err)
		}
	}
	state.mu.Lock()
	if !state.values[value] || state.removes != 0 {
		t.Error("cleanup deleted another active local reference")
	}
	state.mu.Unlock()
	if err := journalCall(context.Background(), "cleanup", value, store, reference, issuer); err != nil {
		t.Fatal(err)
	}
	if err := journalCall(context.Background(), "cleanup", value, store, reference, issuer); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.values[value] || !state.values["external"] || state.removes != 1 {
		t.Fatal("last reference or idempotent cleanup failed")
	}
}

func TestACMECleanupJournalUncertainInsertionKeepsFailedCleanupForRetry(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}, dropInsert: true, denyRemove: true}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, issuer := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := journalCall(ctx, "present", value, store, reference, issuer); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatal("uncertain insert lost failure state")
	}
	state.mu.Lock()
	state.denyRemove = false
	state.mu.Unlock()
	if err := retryACMEDNSCleanup(context.Background(), store, time.Now(), func(acmeIssuer) bool { return true }); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.values[value] || !state.values["external"] {
		t.Fatal("uncertain insertion was not recovered")
	}
}

func TestACMECleanupJournalRejectsUnsafePathsBeforeDNSEffects(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{}}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, issuer := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	if err := os.Chmod(store.dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := journalCall(context.Background(), "present", value, store, reference, issuer); err == nil {
		t.Fatal("readable journal directory accepted")
	}
	if err := os.Chmod(store.dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(reference.SecretFile, filepath.Join(store.dir, "lock")); err != nil {
		t.Fatal(err)
	}
	if err := journalCall(context.Background(), "present", value, store, reference, issuer); err == nil {
		t.Fatal("symlink lock accepted")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.values) != 0 {
		t.Fatal("unsafe journal paths allowed a DNS update")
	}
}

func TestACMECleanupJournalPendingDeletionIsIdempotentAfterLostAcknowledgement(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}}
	address := startACMETestDNS(t, state.handler(false))
	store, reference, _ := cleanupFixture(t, address)
	value := strings.Repeat("A", 43)
	record := &acmeChallengeJournal{Version: 1, FQDN: acmeHookTestName, Value: value, Zone: acmeTestZone, Pending: &reference}
	if err := store.write(acmeJournalID(address, acmeHookTestName, value), record); err != nil {
		t.Fatal(err)
	}
	// DNS deletion committed before a killed helper could unlink the durable intent.
	if err := retryACMEDNSCleanup(context.Background(), store, time.Now(), func(acmeIssuer) bool { return false }); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.values["external"] || state.removes != 1 {
		t.Fatal("replayed deletion was not exact and idempotent")
	}
}

func TestACMECleanupJournalNameserverAliasCannotDeleteActiveGeneration(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"external": true}}
	address := startACMETestDNS(t, state.handler(false))
	store, oldReference, issuer := cleanupFixture(t, address)
	newReference := oldReference
	newReference.Nameserver = strings.Replace(address, "127.0.0.1", "localhost", 1)
	value := strings.Repeat("A", 43)
	for _, reference := range []acmeCredentialReference{oldReference, newReference} {
		if err := journalCall(context.Background(), "present", value, store, reference, issuer); err != nil {
			t.Fatal(err)
		}
	}
	if err := journalCall(context.Background(), "cleanup", value, store, oldReference, issuer); err != nil {
		t.Fatal(err)
	}
	if err := retryACMEDNSCleanup(context.Background(), store, time.Now(), func(acmeIssuer) bool { return true }); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	if !state.values[value] || state.removes != 0 {
		t.Error("old nameserver generation removed an active identical value")
	}
	state.mu.Unlock()
	if err := journalCall(context.Background(), "cleanup", value, store, newReference, issuer); err != nil {
		t.Fatal(err)
	}
	if err := retryACMEDNSCleanup(context.Background(), store, time.Now(), func(acmeIssuer) bool { return true }); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.values[value] || !state.values["external"] {
		t.Fatal("final alias generation did not clean exactly")
	}
}

func TestACMECleanupJournalBoundedRetriesDoNotStarveLaterRecords(t *testing.T) {
	store, reference, _ := cleanupFixture(t, "127.0.0.1:15353")
	reference.SecretFile = filepath.Join(t.TempDir(), "unavailable-generation")
	for i := 0; i < 9; i++ {
		value := strings.Repeat(string(rune('A'+i)), 43)
		record := &acmeChallengeJournal{Version: 1, FQDN: acmeHookTestName, Value: value, Zone: acmeTestZone, Pending: &reference}
		if err := store.write(acmeJournalID(reference.Nameserver, acmeHookTestName, value), record); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := retryACMEDNSCleanup(context.Background(), store, now, func(acmeIssuer) bool { return false }); err == nil {
		t.Fatal("missing generation errors were hidden")
	}
	entries, err := store.inventory()
	if err != nil {
		t.Fatal(err)
	}
	untouched := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := store.read(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if record.LastAttempt == 0 {
			untouched++
		}
	}
	if untouched != 1 {
		t.Fatal("cleanup exceeded the eight-attempt bound")
	}
	if err := retryACMEDNSCleanup(context.Background(), store, now.Add(time.Second), func(acmeIssuer) bool { return false }); err == nil {
		t.Fatal("missing generation errors were hidden")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := store.read(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if record.LastAttempt == 0 {
			t.Fatal("permanent denial starved a later owned record")
		}
	}
}
