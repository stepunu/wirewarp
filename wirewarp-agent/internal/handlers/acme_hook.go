package handlers

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const ACMEHookPath = "/usr/local/libexec/wirewarp-acme-dns"
const acmeHookAgentPath = "/usr/local/bin/wirewarp-agent"
const acmeHookTimeout = 15 * time.Second
const acmeHookCleanupTimeout = 6 * time.Second

var acmeHookValue = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var acmeHookLabel = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// EnsureACMEDNSHook installs a fixed executable, without credential contents.
func EnsureACMEDNSHook() error {
	return ensureACMEDNSHookAt(ACMEHookPath, acmeHookAgentPath, 0)
}

func ensureACMEDNSHookAt(path, binary string, owner uint32) error {
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("ACME hook requires an installed executable WireWarp agent")
	}
	var stat unix.Stat_t
	if unix.Lstat(binary, &stat) != nil || stat.Uid != owner {
		return errors.New("ACME hook agent ownership is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return errors.New("ACME hook directory could not be created")
	}
	if info, err := os.Lstat(filepath.Dir(path)); err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("ACME hook directory permissions are invalid")
	}
	if unix.Lstat(filepath.Dir(path), &stat) != nil || stat.Uid != owner {
		return errors.New("ACME hook directory ownership is invalid")
	}
	// The binary path is an internal installation constant, never user input.
	if strings.ContainsAny(binary, "\r\n\"$`\\") || !filepath.IsAbs(binary) {
		return errors.New("ACME hook agent path is invalid")
	}
	script := []byte("#!/bin/bash\n# WireWarp-managed ACME DNS hook\nexec \"" + binary + "\" acme-dns \"$@\"\n")
	hookInfo, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("ACME hook could not be inspected")
	}
	if err == nil {
		if !hookInfo.Mode().IsRegular() || unix.Lstat(path, &stat) != nil || stat.Uid != owner || hookInfo.Mode().Perm()&0022 != 0 {
			return errors.New("ACME hook path is occupied by an unmanaged file")
		}
		current, readErr := os.ReadFile(path)
		if readErr != nil || !strings.Contains(string(current), "# WireWarp-managed ACME DNS hook\n") {
			return errors.New("ACME hook path is occupied by an unmanaged file")
		}
	}
	if err := writeFileAtomic(path, script, 0755); err != nil {
		return errors.New("ACME hook could not be installed")
	}
	return nil
}

// RunACMEDNSHook is the early CLI entry point. It does not load agent config.
func RunACMEDNSHook(args []string) error {
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, acmeHookTimeout)
	defer cancel()
	credentials, err := loadACMEHookCredentials(os.Getenv, 0)
	if err != nil {
		return err
	}
	issuer, err := currentACMEIssuer(os.Getppid())
	if err != nil {
		return errors.New("ACME issuer identity unavailable")
	}
	reference := acmeCredentialReference{Nameserver: credentials.RFC2136Nameserver, Key: credentials.RFC2136TSIGKey, Algorithm: credentials.RFC2136TSIGAlgorithm, SecretFile: os.Getenv("RFC2136_TSIG_SECRET_FILE")}
	return runJournaledACMEDNSHook(ctx, args, credentials, reference, issuer, acmeCleanupStore{acmeCleanupDir, 0})
}

func loadACMEHookCredentials(getenv func(string) string, owner uint32) (TraefikACMEParams, error) {
	var credentials TraefikACMEParams
	secret, err := readACMEHookSecret(getenv("RFC2136_TSIG_SECRET_FILE"), owner)
	if err != nil {
		return credentials, err
	}
	credentials = TraefikACMEParams{
		RFC2136Nameserver:    getenv("RFC2136_NAMESERVER"),
		RFC2136TSIGKey:       dns.CanonicalName(getenv("RFC2136_TSIG_KEY")),
		RFC2136TSIGAlgorithm: strings.ToLower(getenv("RFC2136_TSIG_ALGORITHM")),
		RFC2136TSIGSecret:    secret,
	}
	if getenv("RFC2136_TSIG_KEY") == "" || validateRFC2136ACME(credentials) != nil {
		return TraefikACMEParams{}, errors.New("ACME hook credentials are invalid")
	}
	return credentials, nil
}

func readACMEHookSecret(path string, owner uint32) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("ACME hook requires a managed secret file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", errors.New("ACME hook secret file could not be opened")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != owner || stat.Size < 1 || stat.Size > 4096 {
		return "", errors.New("ACME hook secret file requires root ownership and mode 0600")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("ACME hook secret file could not be read")
	}
	return string(data), nil
}

func runACMEDNSHook(ctx context.Context, args []string, credentials TraefikACMEParams) error {
	if len(args) != 3 || (args[0] != "present" && args[0] != "cleanup") || !validACMEHookName(args[1]) || !acmeHookValue.MatchString(args[2]) {
		return errors.New("ACME hook requires present or cleanup, an effective DNS name, and a challenge value")
	}
	if validateRFC2136ACME(credentials) != nil {
		return errors.New("ACME hook credentials are invalid")
	}
	fqdn := dns.CanonicalName(args[1])
	zone, err := acmeHookZone(ctx, fqdn, credentials.RFC2136Nameserver)
	if err != nil {
		return errors.New("ACME hook authoritative zone discovery failed")
	}
	record := &dns.TXT{Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{args[2]}}
	if args[0] == "cleanup" {
		if err := acmeHookUpdate(ctx, zone, record, credentials, true); err != nil {
			return errors.New("ACME hook exact TXT cleanup failed")
		}
		return nil
	}
	if err := acmeHookUpdate(ctx, zone, record, credentials, false); err != nil {
		// The primary may have committed a write whose response was lost.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), acmeHookCleanupTimeout)
		defer cancel()
		if acmeHookUpdate(cleanupCtx, zone, record, credentials, true) != nil {
			return errors.New("ACME hook TXT insertion failed; exact cleanup could not be confirmed")
		}
		return errors.New("ACME hook TXT insertion failed; exact cleanup confirmed")
	}
	return nil
}

func validACMEHookName(value string) bool {
	if len(value) == 0 || len(value) > 254 {
		return false
	}
	name := dns.Fqdn(value)
	if _, ok := dns.IsDomainName(name); !ok || name == "." {
		return false
	}
	for _, label := range dns.SplitDomainName(name) {
		if !acmeHookLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func acmeHookZone(ctx context.Context, fqdn, primary string) (string, error) {
	for name, depth := fqdn, 0; name != "." && depth < 32; depth++ {
		request := new(dns.Msg).SetQuestion(name, dns.TypeSOA)
		client := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
		response, _, err := client.ExchangeContext(ctx, request, primary)
		if err != nil || response == nil || !response.Authoritative || response.Truncated || (response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError) {
			return "", errors.New("authoritative SOA unavailable")
		}
		for _, rr := range append(response.Answer, response.Ns...) {
			if soa, ok := rr.(*dns.SOA); ok && dns.IsSubDomain(soa.Hdr.Name, fqdn) {
				return dns.CanonicalName(soa.Hdr.Name), nil
			}
		}
		index := strings.IndexByte(name, '.')
		if index <= 0 || index == len(name)-1 {
			break
		}
		name = name[index+1:]
	}
	return "", errors.New("authoritative SOA unavailable")
}

func acmeHookUpdate(ctx context.Context, zone string, record *dns.TXT, credentials TraefikACMEParams, remove bool) error {
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			break
		}
		if acmeHookSignedUpdate(ctx, zone, record, credentials, remove) == nil {
			return nil
		}
		if !waitACMEDNS(ctx, time.Duration(attempt+1)*100*time.Millisecond) {
			break
		}
	}
	return errors.New("signed TXT update failed")
}

func acmeHookSignedUpdate(ctx context.Context, zone string, record *dns.TXT, credentials TraefikACMEParams, remove bool) error {
	message := new(dns.Msg).SetUpdate(zone)
	if remove {
		message.Remove([]dns.RR{record})
	} else {
		message.Insert([]dns.RR{record})
	}
	key := dns.CanonicalName(credentials.RFC2136TSIGKey)
	algorithm := dns.CanonicalName(credentials.RFC2136TSIGAlgorithm)
	message.SetTsig(key, algorithm, 300, time.Now().Unix())
	client := &dns.Client{Net: "tcp", Timeout: 3 * time.Second, TsigSecret: map[string]string{key: credentials.RFC2136TSIGSecret}}
	response, _, err := client.ExchangeContext(ctx, message, credentials.RFC2136Nameserver)
	if err != nil || response == nil || response.Rcode != dns.RcodeSuccess || response.Opcode != dns.OpcodeUpdate || !response.Response || response.Truncated {
		return errors.New("signed TXT update failed")
	}
	tsig := response.IsTsig()
	if tsig == nil || !strings.EqualFold(tsig.Hdr.Name, key) || !strings.EqualFold(tsig.Algorithm, algorithm) || tsig.Error != 0 {
		return errors.New("signed TXT update failed")
	}
	return nil
}
