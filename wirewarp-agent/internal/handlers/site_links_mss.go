package handlers

import "github.com/wirewarp/agent/internal/config"

const siteMSSChain = "WW-SITE-MSS"

// The encrypted underlay can have a lower MTU than the WireGuard interface.
// Use the existing VPN baseline for selected site TCP flows when PMTUD fails.
const siteTCPMSS = "1240"

func siteMSSRules(saved *config.Config, p *config.SiteLinkSnapshot) []string {
	var rules []string
	for _, flow := range compileSiteFlows(p) {
		if flow.protocol != "any" && flow.protocol != "tcp" {
			continue
		}
		add := func(iface, direction string) {
			if iface != "" {
				rules = append(rules, "-A "+siteMSSChain+" -p tcp --tcp-flags SYN,RST SYN -o "+iface+" "+siteOriginalMatch(flow)+" --ctdir "+direction+" -j TCPMSS --set-mss "+siteTCPMSS)
			}
		}
		if p.NodeRole == "hub" {
			iface, _ := siteHubIngressInterface(saved, p)
			add(iface, "ORIGINAL")
			add(iface, "REPLY")
		} else if flow.sourceSite.GatewayAgentID == saved.AgentID {
			if att, ok := siteAttachment(saved, flow.sourceSite.AttachmentID); ok {
				add(att.WGInterface, "ORIGINAL")
			}
		} else if flow.destinationSite.GatewayAgentID == saved.AgentID {
			if att, ok := siteAttachment(saved, flow.destinationSite.AttachmentID); ok {
				add(att.WGInterface, "REPLY")
			}
		}
	}
	return rules
}

func siteFirewallTable(table string) (parents, chains []string) {
	switch table {
	case "filter":
		return []string{"FORWARD", "INPUT", "OUTPUT"}, []string{"WW-SITE-FWD", "WW-SITE-IN", "WW-SITE-OUT", "WW-SITE-DST"}
	case "nat":
		return []string{"POSTROUTING"}, []string{"WW-SITE-NAT"}
	case "mangle":
		return []string{"POSTROUTING"}, []string{siteMSSChain}
	}
	return nil, nil
}

func siteParentChain(table, parent string) string {
	if table == "mangle" {
		return siteMSSChain
	}
	return siteChains[parent]
}
