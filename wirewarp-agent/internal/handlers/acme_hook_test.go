package handlers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const acmeHookTestName = "_acme-challenge.app.example.test."

func hookCredentials(address string) TraefikACMEParams {
	return TraefikACMEParams{RFC2136Nameserver: address, RFC2136TSIGKey: acmeTestKey, RFC2136TSIGAlgorithm: "hmac-sha256", RFC2136TSIGSecret: acmeTestSecret}
}

func TestACMEHookConcurrentIssuersPreserveTXTAndExactIdempotentCleanup(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"existing-challenge": true}}
	address := startACMETestDNS(t, state.handler(false))
	a, b := strings.Repeat("A", 43), strings.Repeat("B", 43)
	var wg sync.WaitGroup
	for _, value := range []string{a, b} {
		wg.Add(1)
		go func(value string) {
			defer wg.Done()
			if err := runACMEDNSHook(context.Background(), []string{"present", acmeHookTestName, value}, hookCredentials(address)); err != nil {
				t.Error(err)
			}
		}(value)
	}
	wg.Wait()
	state.mu.Lock()
	if len(state.values) != 3 || !state.values[a] || !state.values[b] || state.badSignature {
		t.Error("concurrent signed insertion lost a TXT value")
	}
	state.mu.Unlock()
	for i := 0; i < 2; i++ {
		if err := runACMEDNSHook(context.Background(), []string{"cleanup", acmeHookTestName, a}, hookCredentials(address)); err != nil {
			t.Fatal(err)
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.values) != 2 || !state.values[b] || !state.values["existing-challenge"] {
		t.Fatal("exact cleanup removed another issuer's TXT")
	}
}

func TestACMEHookUncertainAndCanceledInsertionCleansWithIndependentContext(t *testing.T) {
	for _, cancelAfterWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost-response", true: "canceled-after-write"}[cancelAfterWrite], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			state := &acmeTestDNS{values: map[string]bool{"existing-challenge": true}, dropInsert: true}
			if cancelAfterWrite {
				state.cancel = cancel
			}
			address := startACMETestDNS(t, state.handler(false))
			value := strings.Repeat("A", 43)
			err := runACMEDNSHook(ctx, []string{"present", acmeHookTestName, value}, hookCredentials(address))
			if err == nil || !strings.Contains(err.Error(), "exact cleanup confirmed") {
				t.Fatalf("uncertain insertion result was hidden: %v", err)
			}
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.values[value] || !state.values["existing-challenge"] || state.removes == 0 {
				t.Fatal("uncertain insertion did not clean only its own value")
			}
		})
	}
}

func TestACMEHookDeniedCleanupAndBadSignatureFailWithoutSecretOutput(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"existing-challenge": true}, denyRemove: true}
	address := startACMETestDNS(t, state.handler(false))
	value := strings.Repeat("A", 43)
	err := runACMEDNSHook(context.Background(), []string{"cleanup", acmeHookTestName, value}, hookCredentials(address))
	if err == nil || strings.Contains(err.Error(), value) || strings.Contains(err.Error(), acmeTestSecret) {
		t.Fatal("denied cleanup was accepted or leaked sensitive output")
	}
	credentials := hookCredentials(address)
	credentials.RFC2136TSIGSecret = "aW52YWxpZC1rZXk="
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := runACMEDNSHook(ctx, []string{"cleanup", acmeHookTestName, value}, credentials); err == nil {
		t.Fatal("an invalid TSIG response was accepted")
	}
}

func TestACMEHookUncertainWriteWithDeniedCleanupReportsDegradedState(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"existing-challenge": true}, dropInsert: true, denyRemove: true}
	address := startACMETestDNS(t, state.handler(false))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	value := strings.Repeat("A", 43)
	err := runACMEDNSHook(ctx, []string{"present", acmeHookTestName, value}, hookCredentials(address))
	if err == nil || !strings.Contains(err.Error(), "cleanup could not be confirmed") || strings.Contains(err.Error(), value) {
		t.Fatal("failed cleanup was hidden or exposed challenge data")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.values["existing-challenge"] || !state.values[value] {
		t.Fatal("denied cleanup changed the primary TXT contents")
	}
}

func TestACMEHookUnsignedSuccessResponseIsNotAccepted(t *testing.T) {
	address := startACMETestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg).SetReply(request)
		response.Authoritative = true
		if request.Opcode != dns.OpcodeUpdate {
			response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: acmeTestZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.test.", Mbox: "hostmaster.example.test."}}
		}
		_ = w.WriteMsg(response)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := runACMEDNSHook(ctx, []string{"cleanup", acmeHookTestName, strings.Repeat("A", 43)}, hookCredentials(address)); err == nil {
		t.Fatal("unsigned success was accepted")
	}
}

func TestACMEHookSignedWrongOpcodeIsNotAccepted(t *testing.T) {
	address := startACMETestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg).SetReply(request)
		response.Authoritative = true
		if request.Opcode != dns.OpcodeUpdate {
			response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: acmeTestZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.test.", Mbox: "hostmaster.example.test."}}
		} else {
			response.Opcode = dns.OpcodeQuery
			tsig := request.IsTsig()
			response.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(response)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := runACMEDNSHook(ctx, []string{"cleanup", acmeHookTestName, strings.Repeat("A", 43)}, hookCredentials(address)); err == nil {
		t.Fatal("a signed response with the wrong opcode was accepted")
	}
}

func TestACMEHookEffectiveNameSupportsDelegationAndRejectsMalformedRequests(t *testing.T) {
	// A CNAME target does not need an _acme-challenge prefix.
	if !validACMEHookName("validation.delegated.example.test.") {
		t.Fatal("a valid effective CNAME target was rejected")
	}
	for _, args := range [][]string{{}, {"delete", acmeHookTestName, strings.Repeat("A", 43)}, {"present", "bad;name.example.test.", strings.Repeat("A", 43)}, {"present", acmeHookTestName, "bad\nvalue"}, {"present", ".", strings.Repeat("A", 43)}, {"present", acmeHookTestName, strings.Repeat("A", 43), "extra"}} {
		if err := runACMEDNSHook(context.Background(), args, hookCredentials("127.0.0.1:1")); err == nil || !strings.Contains(err.Error(), "requires present or cleanup") {
			t.Fatal("malformed request reached the network")
		}
	}
	address := startACMETestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg).SetReply(request)
		response.Authoritative = true
		response.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "validation.delegated.example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.test.", Mbox: "hostmaster.example.test."}}
		_ = w.WriteMsg(response)
	})
	zone, err := acmeHookZone(context.Background(), "validation.delegated.example.test.", address)
	if err != nil || zone != "validation.delegated.example.test." {
		t.Fatal("the delegated effective name zone was not used")
	}
}

func TestACMEHookSecretFilePermissionsOwnershipAndSymlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(acmeTestSecret), 0600); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Geteuid())
	if secret, err := readACMEHookSecret(path, owner); err != nil || secret != acmeTestSecret {
		t.Fatal("valid protected secret file was rejected")
	}
	if _, err := readACMEHookSecret(path, owner+1); err == nil {
		t.Fatal("incorrect secret file ownership was accepted")
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := readACMEHookSecret(path, owner); err == nil {
		t.Fatal("group-readable secret was accepted")
	}
	_ = os.Chmod(path, 0600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readACMEHookSecret(link, owner); err == nil {
		t.Fatal("secret symlink was accepted")
	}
	if _, err := readACMEHookSecret("relative", owner); err == nil {
		t.Fatal("relative secret path was accepted")
	}
}

func TestACMEHookLoadsInheritedFileCredentialsAndSanitizesErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(path, []byte(acmeTestSecret), 0600)
	environment := map[string]string{"RFC2136_NAMESERVER": "127.0.0.1:5353", "RFC2136_TSIG_KEY": "ACME.EXAMPLE.TEST", "RFC2136_TSIG_ALGORITHM": "HMAC-SHA256", "RFC2136_TSIG_SECRET_FILE": path}
	credentials, err := loadACMEHookCredentials(func(key string) string { return environment[key] }, uint32(os.Geteuid()))
	if err != nil || credentials.RFC2136TSIGKey != acmeTestKey || credentials.RFC2136TSIGSecret != acmeTestSecret {
		t.Fatal("inherited credential fields were not loaded consistently")
	}
	environment["RFC2136_NAMESERVER"] = "bad-host\n" + acmeTestSecret
	_, err = loadACMEHookCredentials(func(key string) string { return environment[key] }, uint32(os.Geteuid()))
	if err == nil || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), acmeTestSecret) {
		t.Fatal("credential validation leaked environment or secret contents")
	}
}

func TestACMEHookInstallerFixedArgumentsAndUnmanagedFilePreservation(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "agent")
	_ = os.WriteFile(binary, []byte("binary-fixture"), 0755)
	hook := filepath.Join(dir, "libexec", "hook")
	owner := uint32(os.Geteuid())
	if err := ensureACMEDNSHookAt(hook, binary, owner); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(hook)
	info, statErr := os.Stat(hook)
	if err != nil || statErr != nil || info.Mode().Perm() != 0755 || !strings.Contains(string(data), "acme-dns \"$@\"") {
		t.Fatal("fixed hook arguments or executable mode are incorrect")
	}
	if err := ensureACMEDNSHookAt(hook, binary, owner); err != nil {
		t.Fatal("idempotent managed installation failed")
	}
	_ = os.WriteFile(hook, []byte("unmanaged contents"), 0755)
	if err := ensureACMEDNSHookAt(hook, binary, owner); err == nil {
		t.Fatal("an unmanaged hook was overwritten")
	}
	data, _ = os.ReadFile(hook)
	if string(data) != "unmanaged contents" {
		t.Fatal("unmanaged hook changed")
	}
	if err := ensureACMEDNSHookAt(hook, filepath.Join(dir, "missing"), owner); err == nil {
		t.Fatal("missing installed agent was accepted")
	}
}

func TestACMEHookCancellationBeforeDiscoveryIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err := runACMEDNSHook(ctx, []string{"present", acmeHookTestName, strings.Repeat("A", 43)}, hookCredentials("127.0.0.1:1"))
	if err == nil || time.Since(started) > time.Second || errors.Is(err, context.Canceled) {
		t.Fatal("cancellation did not produce a prompt safe stage error")
	}
}
