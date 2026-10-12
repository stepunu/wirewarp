package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type ACMEDNSTestParams struct {
	Domain          string            `json:"domain"`
	DNSDelaySeconds int               `json:"dns_delay_seconds"`
	Credentials     TraefikACMEParams `json:"credentials"`
}

type ACMEAuthoritativeResult struct {
	Server string `json:"server"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type ACMEDNSTestResult struct {
	OK                   bool                      `json:"ok"`
	Stage                string                    `json:"stage"`
	Detail               string                    `json:"detail"`
	RecordName           string                    `json:"record_name"`
	CleanupOK            bool                      `json:"cleanup_ok"`
	AuthoritativeResults []ACMEAuthoritativeResult `json:"authoritative_results"`
}

var acmeDNSTestLock = make(chan struct{}, 1)

type acmeDNSTester struct {
	resolve        func(context.Context, string) ([]string, error)
	pollInterval   time.Duration
	cleanupTimeout time.Duration
}

// HandleACMEDNSTest runs a bounded temporary DNS update in either agent mode.
func HandleACMEDNSTest(raw json.RawMessage) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	var p ACMEDNSTestParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return acmeDNSTestOutput(ACMEDNSTestResult{Stage: "validation", Detail: "Invalid DNS test request."})
	}
	select {
	case acmeDNSTestLock <- struct{}{}:
		defer func() { <-acmeDNSTestLock }()
	case <-ctx.Done():
		return acmeDNSTestOutput(ACMEDNSTestResult{Stage: "busy", Detail: "Another DNS test did not finish within the time limit."})
	}
	tester := acmeDNSTester{
		resolve: func(ctx context.Context, host string) ([]string, error) {
			addresses, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(addresses))
			for _, address := range addresses {
				out = append(out, net.JoinHostPort(address, "53"))
			}
			return out, nil
		},
		pollInterval:   2 * time.Second,
		cleanupTimeout: 15 * time.Second,
	}
	return acmeDNSTestOutput(tester.run(ctx, p))
}

func acmeDNSTestOutput(result ACMEDNSTestResult) (string, error) {
	if result.AuthoritativeResults == nil {
		result.AuthoritativeResults = []ACMEAuthoritativeResult{}
	}
	data, _ := json.Marshal(result)
	if !result.OK {
		return string(data), errors.New(string(data))
	}
	return string(data), nil
}

func (t acmeDNSTester) run(ctx context.Context, p ACMEDNSTestParams) (result ACMEDNSTestResult) {
	result.Stage = "validation"
	result.Detail = "Invalid DNS test configuration."
	domain := strings.ToLower(strings.TrimSuffix(p.Domain, "."))
	if strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
	}
	if p.DNSDelaySeconds < 0 || p.DNSDelaySeconds > 90 {
		result.Detail = "DNS test delay must be between 0 and 90 seconds."
		return result
	}
	if _, ok := dns.IsDomainName(domain + "."); !ok || !validACMEDomain(domain) {
		return result
	}
	if err := validateRFC2136ACME(p.Credentials); err != nil {
		return result
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(p.Credentials.RFC2136TSIGKey)); !ok {
		return result
	}
	result.RecordName = "_acme-challenge." + domain + "."
	result.Stage = "discovery"
	result.Detail = "Could not discover the authoritative zone and servers."
	zone, servers, err := t.discover(ctx, domain+".", p.Credentials.RFC2136Nameserver)
	if err != nil || len(servers) == 0 {
		return result
	}
	valueBytes := make([]byte, 24)
	if _, err := rand.Read(valueBytes); err != nil {
		result.Detail = "Could not create a temporary challenge."
		return result
	}
	value := hex.EncodeToString(valueBytes)
	record := &dns.TXT{Hdr: dns.RR_Header{Name: result.RecordName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{value}}
	// Even an uncertain update response can mean the primary accepted the write.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), t.cleanupTimeout)
		defer cancel()
		result.CleanupOK = t.cleanup(cleanupCtx, zone, record, p.Credentials)
		if !result.CleanupOK {
			result.OK = false
			result.Stage = "cleanup"
			result.Detail = "Temporary TXT removal could not be verified on the primary."
		} else if result.OK {
			result.Detail = "TXT propagated to every authoritative server. Removal verified on the primary; secondary removal was not checked."
		}
	}()
	result.Stage = "update"
	result.Detail = "The signed DNS update failed or was denied."
	if err := signedACMEUpdate(ctx, zone, record, p.Credentials, false); err != nil {
		return result
	}
	result.Stage = "propagation"
	result.Detail = "TXT did not reach every authoritative server within the time limit."
	if !waitACMEDNS(ctx, time.Duration(p.DNSDelaySeconds)*time.Second) {
		return result
	}
	for {
		allOK := true
		result.AuthoritativeResults = make([]ACMEAuthoritativeResult, 0, len(servers))
		for _, server := range servers {
			ok := false
			for _, address := range server.addresses {
				present, authoritative, err := queryACMETXT(ctx, address, record.Hdr.Name, value)
				if err == nil && present && authoritative {
					ok = true
					break
				}
			}
			detail := "Temporary TXT is visible."
			if !ok {
				detail = "Temporary TXT is missing or the authoritative query failed."
			}
			result.AuthoritativeResults = append(result.AuthoritativeResults, ACMEAuthoritativeResult{Server: server.name, OK: ok, Detail: detail})
			allOK = allOK && ok
		}
		if allOK {
			result.OK = true
			result.Stage = "complete"
			return result
		}
		if !waitACMEDNS(ctx, t.pollInterval) {
			return result
		}
	}
}

func validACMEDomain(domain string) bool {
	if len(domain) > 230 || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return net.ParseIP(domain) == nil
}

type acmeNameServer struct {
	name      string
	addresses []string
}

func (t acmeDNSTester) discover(ctx context.Context, domain, primary string) (string, []acmeNameServer, error) {
	zone := ""
	for name := domain; name != "." && name != ""; {
		response, err := queryACMEDNS(ctx, primary, name, dns.TypeSOA)
		if err != nil || !response.Authoritative {
			return "", nil, errors.New("SOA query failed")
		}
		for _, record := range append(response.Answer, response.Ns...) {
			if soa, ok := record.(*dns.SOA); ok && dns.IsSubDomain(soa.Hdr.Name, domain) {
				zone = soa.Hdr.Name
				break
			}
		}
		if zone != "" {
			break
		}
		index := strings.IndexByte(name, '.')
		if index < 0 || index == len(name)-1 {
			break
		}
		name = name[index+1:]
	}
	if zone == "" {
		return "", nil, errors.New("zone unavailable")
	}
	response, err := queryACMEDNS(ctx, primary, zone, dns.TypeNS)
	if err != nil || !response.Authoritative || response.Rcode != dns.RcodeSuccess {
		return "", nil, errors.New("NS query failed")
	}
	names := map[string]bool{}
	for _, record := range response.Answer {
		if ns, ok := record.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, zone) {
			names[strings.ToLower(ns.Ns)] = true
		}
	}
	if len(names) == 0 || len(names) > 32 {
		return "", nil, errors.New("invalid NS set")
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	servers := make([]acmeNameServer, 0, len(ordered))
	for _, name := range ordered {
		addresses, err := t.resolve(ctx, strings.TrimSuffix(name, "."))
		if err != nil || len(addresses) == 0 {
			return "", nil, errors.New("NS address lookup failed")
		}
		servers = append(servers, acmeNameServer{name: name, addresses: addresses})
	}
	return zone, servers, nil
}

func queryACMEDNS(ctx context.Context, server, name string, kind uint16) (*dns.Msg, error) {
	message := new(dns.Msg)
	message.SetQuestion(name, kind)
	message.RecursionDesired = false
	client := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	response, _, err := client.ExchangeContext(ctx, message, server)
	return response, err
}

func queryACMETXT(ctx context.Context, server, name, value string) (bool, bool, error) {
	response, err := queryACMEDNS(ctx, server, name, dns.TypeTXT)
	if err != nil {
		return false, false, err
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return false, response.Authoritative, errors.New("TXT query failed")
	}
	for _, record := range response.Answer {
		if txt, ok := record.(*dns.TXT); ok && strings.EqualFold(txt.Hdr.Name, name) && strings.Join(txt.Txt, "") == value {
			return true, response.Authoritative, nil
		}
	}
	return false, response.Authoritative, nil
}

func signedACMEUpdate(ctx context.Context, zone string, record *dns.TXT, credentials TraefikACMEParams, remove bool) error {
	message := new(dns.Msg)
	message.SetUpdate(zone)
	if remove {
		message.Remove([]dns.RR{record})
	} else {
		message.Insert([]dns.RR{record})
	}
	key := dns.Fqdn(credentials.RFC2136TSIGKey)
	message.SetTsig(key, dns.Fqdn(credentials.RFC2136TSIGAlgorithm), 300, time.Now().Unix())
	client := &dns.Client{Net: "tcp", Timeout: 3 * time.Second, TsigSecret: map[string]string{key: credentials.RFC2136TSIGSecret}}
	response, _, err := client.ExchangeContext(ctx, message, credentials.RFC2136Nameserver)
	if err != nil || response == nil || response.Rcode != dns.RcodeSuccess || response.IsTsig() == nil {
		return errors.New("signed update failed")
	}
	return nil
}

func (t acmeDNSTester) cleanup(ctx context.Context, zone string, record *dns.TXT, credentials TraefikACMEParams) bool {
	_ = signedACMEUpdate(ctx, zone, record, credentials, true)
	present, authoritative, err := queryACMETXT(ctx, credentials.RFC2136Nameserver, record.Hdr.Name, record.Txt[0])
	return err == nil && authoritative && !present
}

func waitACMEDNS(ctx context.Context, delay time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
