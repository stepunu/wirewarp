package handlers

import (
	"strings"
	"testing"
)

func TestSiteLocalListenerExceptionCannotOpenTransit(t *testing.T) {
	for _, test := range []struct {
		name, address string
		local         bool
	}{
		{"gateway", "192.168.20.110", true},
		{"other-subnet", "192.168.0.110", false},
		{"ipv6", "::1", false},
		{"rule-injection", "192.168.20.110 -j ACCEPT", false},
		{"missing", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, snapshot := siteFixture("gateway")
			cfg.Attachments[0].LANIP = test.address
			rules := siteFirewallRules(cfg, snapshot, snapshot.TransitPeers, false)
			count := 0
			for chain, lines := range rules {
				for _, line := range lines {
					if !strings.Contains(line, "-i lo ") && !strings.Contains(line, "-o lo ") {
						continue
					}
					count++
					if chain != "WW-SITE-IN" && chain != "WW-SITE-OUT" {
						t.Fatal("loopback exception reached a transit chain", line)
					}
					if !test.local || !strings.Contains(line, "-s "+test.address+"/32 -d "+test.address+"/32 ") || !strings.HasSuffix(line, "-j RETURN") {
						t.Fatal("loopback exception exceeds the gateway's own address", line)
					}
				}
			}
			if test.local && count != 2 || !test.local && count != 0 {
				t.Fatalf("unexpected loopback exceptions: %d", count)
			}
			forward := strings.Join(rules["WW-SITE-FWD"], "\n")
			if !strings.Contains(forward, "-j WW-SITE-DST") {
				t.Fatal("local listener exception removed the transit deny guard")
			}
		})
	}
}
