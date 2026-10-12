package handlers

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const acmeTestZone = "example.test."
const acmeTestKey = "acme.example.test."
const acmeTestSecret = "dGVzdC1hY21lLXNlY3JldA=="

type acmeTestDNS struct {
	mu           sync.Mutex
	values       map[string]bool
	propagate    bool
	denyInsert   bool
	denyRemove   bool
	dropInsert   bool
	cancel       context.CancelFunc
	inserts      int
	removes      int
	badSignature bool
}

func (state *acmeTestDNS) handler(secondary bool) dns.HandlerFunc {
	return func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		state.mu.Lock()
		defer state.mu.Unlock()
		if request.Opcode == dns.OpcodeUpdate {
			if request.IsTsig() == nil || w.TsigStatus() != nil {
				state.badSignature = true
				response.Rcode = dns.RcodeNotAuth
			} else {
				for _, record := range request.Ns {
					txt, ok := record.(*dns.TXT)
					if !ok || txt.Hdr.Name != "_acme-challenge.app.example.test." || len(txt.Txt) != 1 {
						response.Rcode = dns.RcodeRefused
						continue
					}
					switch txt.Hdr.Class {
					case dns.ClassINET:
						state.inserts++
						if state.denyInsert {
							response.Rcode = dns.RcodeRefused
						} else {
							state.values[txt.Txt[0]] = true
							if state.cancel != nil {
								state.cancel()
							}
							if state.dropInsert {
								_ = w.Close()
								return
							}
						}
					case dns.ClassNONE:
						state.removes++
						if state.denyRemove {
							response.Rcode = dns.RcodeRefused
						} else {
							delete(state.values, txt.Txt[0])
						}
					default:
						// A whole-RRset removal would destroy a concurrent challenge.
						response.Rcode = dns.RcodeRefused
					}
				}
			}
			if tsig := request.IsTsig(); tsig != nil {
				response.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
			}
		} else {
			question := request.Question[0]
			switch question.Qtype {
			case dns.TypeSOA:
				soa := &dns.SOA{Hdr: dns.RR_Header{Name: acmeTestZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.example.test.", Mbox: "hostmaster.example.test.", Serial: 1}
				if question.Name == acmeTestZone {
					response.Answer = []dns.RR{soa}
				} else {
					response.Ns = []dns.RR{soa}
				}
			case dns.TypeNS:
				response.Answer = []dns.RR{
					&dns.NS{Hdr: dns.RR_Header{Name: acmeTestZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.example.test."},
					&dns.NS{Hdr: dns.RR_Header{Name: acmeTestZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns2.example.test."},
				}
			case dns.TypeTXT:
				for value := range state.values {
					if secondary && !state.propagate && value != "existing-challenge" {
						continue
					}
					response.Answer = append(response.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{value}})
				}
			}
		}
		_ = w.WriteMsg(response)
	}
}

func startACMETestDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &dns.Server{Listener: listener, Net: "tcp", Handler: handler, TsigSecret: map[string]string{acmeTestKey: acmeTestSecret}, NotifyStartedFunc: func() { close(ready) }, MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }}
	finished := make(chan error, 1)
	go func() { finished <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.ShutdownContext(ctx); err != nil {
			t.Errorf("DNS server shutdown: %v", err)
		}
		if err := <-finished; err != nil {
			t.Errorf("DNS server exited: %v", err)
		}
	})
	return listener.Addr().String()
}

func acmeDNSFixture(t *testing.T, state *acmeTestDNS) (acmeDNSTester, ACMEDNSTestParams) {
	t.Helper()
	primary := startACMETestDNS(t, state.handler(false))
	secondary := startACMETestDNS(t, state.handler(true))
	tester := acmeDNSTester{
		resolve: func(_ context.Context, name string) ([]string, error) {
			if name == "ns1.example.test" {
				return []string{primary}, nil
			}
			return []string{secondary}, nil
		},
		pollInterval:   5 * time.Millisecond,
		cleanupTimeout: 500 * time.Millisecond,
	}
	params := ACMEDNSTestParams{Domain: "app.example.test", Credentials: TraefikACMEParams{
		RFC2136Nameserver: primary, RFC2136TSIGKey: acmeTestKey,
		RFC2136TSIGAlgorithm: "hmac-sha256", RFC2136TSIGSecret: acmeTestSecret,
	}}
	return tester, params
}

func assertACMESafeOutput(t *testing.T, result ACMEDNSTestResult) {
	t.Helper()
	output, err := acmeDNSTestOutput(result)
	if (err == nil) != result.OK {
		t.Fatal("failure must be returned as an executor error")
	}
	if err != nil && err.Error() != output {
		t.Fatal("executor error must contain the same safe structured result")
	}
	if strings.Contains(output, acmeTestSecret) || strings.Contains(output, "existing-challenge") {
		t.Fatal("DNS result exposed sensitive data")
	}
	var decoded ACMEDNSTestResult
	if json.Unmarshal([]byte(output), &decoded) != nil || decoded.Stage != result.Stage {
		t.Fatal("DNS result is not valid JSON")
	}
}

func TestACMEDNSPrimarySecondarySuccessPreservesExistingTXT(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"existing-challenge": true}, propagate: true}
	tester, params := acmeDNSFixture(t, state)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := tester.run(ctx, params)
	if !result.OK || !result.CleanupOK || result.Stage != "complete" || len(result.AuthoritativeResults) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, authority := range result.AuthoritativeResults {
		if !authority.OK {
			t.Fatal("authoritative TXT was not verified")
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.badSignature || state.inserts != 1 || state.removes != 1 || len(state.values) != 1 || !state.values["existing-challenge"] {
		t.Fatal("test must use verified TSIG and preserve every pre-existing TXT")
	}
	assertACMESafeOutput(t, result)
}

func TestACMEDNSDeniedUpdate(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{}, propagate: true, denyInsert: true}
	tester, params := acmeDNSFixture(t, state)
	result := tester.run(context.Background(), params)
	if result.OK || result.Stage != "update" || !result.CleanupOK {
		t.Fatalf("unexpected denied update result: %+v", result)
	}
	assertACMESafeOutput(t, result)
}

func TestACMEDNSPropagationTimeoutCleansPrimary(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{"existing-challenge": true}}
	tester, params := acmeDNSFixture(t, state)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := tester.run(ctx, params)
	if result.OK || result.Stage != "propagation" || !result.CleanupOK || len(result.AuthoritativeResults) != 2 || result.AuthoritativeResults[1].OK {
		t.Fatalf("unexpected propagation result: %+v", result)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.values) != 1 || !state.values["existing-challenge"] {
		t.Fatal("timeout did not preserve and clean primary TXT state")
	}
	assertACMESafeOutput(t, result)
}

func TestACMEDNSCleanupFailureIsCommandFailure(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{}, propagate: true, denyRemove: true}
	tester, params := acmeDNSFixture(t, state)
	result := tester.run(context.Background(), params)
	if result.OK || result.CleanupOK || result.Stage != "cleanup" {
		t.Fatalf("cleanup failure was hidden: %+v", result)
	}
	assertACMESafeOutput(t, result)
}

func TestACMEDNSCanceledAfterWriteStillCleans(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &acmeTestDNS{values: map[string]bool{}, propagate: true, cancel: cancel}
	tester, params := acmeDNSFixture(t, state)
	result := tester.run(ctx, params)
	if result.OK || !result.CleanupOK {
		t.Fatalf("canceled write did not clean up: %+v", result)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.values) != 0 || state.removes != 1 {
		t.Fatal("cleanup reused the canceled context")
	}
	assertACMESafeOutput(t, result)
}

func TestACMEDNSUncertainUpdateStillCleans(t *testing.T) {
	state := &acmeTestDNS{values: map[string]bool{}, propagate: true, dropInsert: true}
	tester, params := acmeDNSFixture(t, state)
	result := tester.run(context.Background(), params)
	if result.OK || !result.CleanupOK || result.Stage != "update" {
		t.Fatalf("uncertain update did not clean up: %+v", result)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.values) != 0 || state.removes != 1 {
		t.Fatal("accepted update was left behind after a lost response")
	}
	assertACMESafeOutput(t, result)
}

func TestACMEDNSMalformedInputsDoNotWrite(t *testing.T) {
	for _, change := range []func(*ACMEDNSTestParams){
		func(p *ACMEDNSTestParams) { p.Domain = "not a domain" },
		func(p *ACMEDNSTestParams) { p.Domain = "*.app.*.example.test" },
		func(p *ACMEDNSTestParams) { p.Domain = "192.168.20.1" },
		func(p *ACMEDNSTestParams) { p.DNSDelaySeconds = -1 },
		func(p *ACMEDNSTestParams) { p.DNSDelaySeconds = 601 },
		func(p *ACMEDNSTestParams) { p.DNSDelaySeconds = 91 },
		func(p *ACMEDNSTestParams) { p.Credentials.RFC2136TSIGSecret = "invalid secret" },
		func(p *ACMEDNSTestParams) { p.Credentials.RFC2136TSIGAlgorithm = "hmac-md5" },
	} {
		state := &acmeTestDNS{values: map[string]bool{}, propagate: true}
		tester, params := acmeDNSFixture(t, state)
		change(&params)
		result := tester.run(context.Background(), params)
		if result.OK || result.Stage != "validation" {
			t.Fatalf("malformed input was accepted: %+v", result)
		}
		state.mu.Lock()
		if state.inserts != 0 || state.removes != 0 {
			t.Error("malformed input caused a write")
		}
		state.mu.Unlock()
		assertACMESafeOutput(t, result)
	}
}

func TestACMEDNSMalformedJSONSafeError(t *testing.T) {
	output, err := HandleACMEDNSTest(json.RawMessage(`{"credentials":{"rfc2136_tsig_secret":"sensitive"},`))
	if err == nil || strings.Contains(output, "sensitive") || err.Error() != output {
		t.Fatal("malformed JSON did not return a safe failure")
	}
}
