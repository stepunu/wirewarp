package handlers

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/wirewarp/agent/internal/config"
)

const siteComment = "wirewarp-site-links"

var siteChains = map[string]string{"FORWARD": "WW-SITE-FWD", "INPUT": "WW-SITE-IN", "OUTPUT": "WW-SITE-OUT", "POSTROUTING": "WW-SITE-NAT"}

func siteSubnets(peers []config.SiteLinkTransitPeer) []string {
	seen := map[string]bool{}
	for _, peer := range peers {
		for _, subnet := range peer.AdvertisedSubnets {
			seen[subnet] = true
		}
	}
	var out []string
	for subnet := range seen {
		out = append(out, subnet)
	}
	sort.Strings(out)
	return out
}

func siteFlowInterfaces(saved *config.Config, flow siteFlow) (incoming, outgoing string, local bool) {
	if saved.Mode == "server" && saved.Server != nil {
		return saved.Server.WGInterface, saved.Server.WGInterface, false
	}
	if flow.sourceSite.GatewayAgentID == saved.AgentID {
		att, ok := siteAttachment(saved, flow.sourceSite.AttachmentID)
		if ok {
			return att.LANIface, att.WGInterface, true
		}
	}
	if flow.destinationSite.GatewayAgentID == saved.AgentID {
		att, ok := siteAttachment(saved, flow.destinationSite.AttachmentID)
		if ok {
			return att.WGInterface, att.LANIface, true
		}
	}
	return "", "", false
}

func siteFirewallRules(saved *config.Config, p *config.SiteLinkSnapshot, peers []config.SiteLinkTransitPeer, allow bool) map[string][]string {
	rules := map[string][]string{}
	hubInterface := ""
	if p.NodeRole == "hub" {
		hubInterface, _ = siteHubIngressInterface(saved, p)
	}
	if allow {
		rules[siteMSSChain] = siteMSSRules(saved, p)
		for _, flow := range compileSiteFlows(p) {
			in, out, _ := siteFlowInterfaces(saved, flow)
			if hubInterface != "" {
				in, out = hubInterface, hubInterface
			}
			if in == "" {
				continue
			}
			match := siteOriginalMatch(flow)
			original := " -m conntrack --ctdir ORIGINAL --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT"
			reply := " -m conntrack --ctdir REPLY --ctstate ESTABLISHED,RELATED -j ACCEPT"
			rules["WW-SITE-FWD"] = append(rules["WW-SITE-FWD"], "-A WW-SITE-FWD -i "+in+" -o "+out+" "+match+original, "-A WW-SITE-FWD -i "+out+" -o "+in+" "+match+reply)
			if saved.Mode == "client" {
				if flow.sourceSite.GatewayAgentID == saved.AgentID {
					rules["WW-SITE-OUT"] = append(rules["WW-SITE-OUT"], "-A WW-SITE-OUT -o "+out+" "+match+original)
					rules["WW-SITE-IN"] = append(rules["WW-SITE-IN"], "-A WW-SITE-IN -i "+out+" "+match+reply)
				} else {
					rules["WW-SITE-IN"] = append(rules["WW-SITE-IN"], "-A WW-SITE-IN -i "+in+" "+match+original)
					rules["WW-SITE-OUT"] = append(rules["WW-SITE-OUT"], "-A WW-SITE-OUT -o "+in+" "+match+reply)
					att, _ := siteAttachment(saved, flow.destinationSite.AttachmentID)
					nat := "-A WW-SITE-NAT -o " + att.LANIface + " " + match + " -m connmark --mark " + att.Fwmark
					if flow.snat == "gateway_lan_ip" {
						nat += " -j SNAT --to-source " + att.LANIP
					} else {
						nat += " -j ACCEPT"
					}
					rules["WW-SITE-NAT"] = append(rules["WW-SITE-NAT"], nat)
				}
			}
		}
	}
	// Local LAN traffic does not cross the site boundary. This exception must
	// include the real LAN interface so a tunnel peer cannot use it.
	if saved.Mode == "client" {
		seen := map[string]bool{}
		for _, att := range saved.Attachments {
			if !att.IsGateway || seen[att.LANIface+att.LANNetwork] {
				continue
			}
			prefix, err := netip.ParsePrefix(att.LANNetwork)
			if err != nil {
				continue
			}
			seen[att.LANIface+att.LANNetwork] = true
			cidr := prefix.Masked().String()
			rules["WW-SITE-FWD"] = append(rules["WW-SITE-FWD"], "-A WW-SITE-FWD -i "+att.LANIface+" -o "+att.LANIface+" -s "+cidr+" -d "+cidr+" -j RETURN")
			rules["WW-SITE-IN"] = append(rules["WW-SITE-IN"], "-A WW-SITE-IN -i "+att.LANIface+" -s "+cidr+" -d "+cidr+" -j RETURN")
			rules["WW-SITE-OUT"] = append(rules["WW-SITE-OUT"], "-A WW-SITE-OUT -o "+att.LANIface+" -s "+cidr+" -d "+cidr+" -j RETURN")
			// Requests to this gateway's LAN listener use loopback locally.
			address, err := netip.ParseAddr(att.LANIP)
			if err == nil && address.Is4() && prefix.Contains(address) && !address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback() {
				local := address.String() + "/32"
				rules["WW-SITE-IN"] = append(rules["WW-SITE-IN"], "-A WW-SITE-IN -i lo -s "+local+" -d "+local+" -j RETURN")
				rules["WW-SITE-OUT"] = append(rules["WW-SITE-OUT"], "-A WW-SITE-OUT -o lo -s "+local+" -d "+local+" -j RETURN")
			}
		}
	}
	for _, subnet := range siteSubnets(peers) {
		// Every authenticated peer can use its own tunnel address. LAN-only
		// source classification cannot distinguish that traffic from management.
		if hubInterface != "" {
			rules["WW-SITE-FWD"] = append(rules["WW-SITE-FWD"], "-A WW-SITE-FWD -i "+hubInterface+" -d "+subnet+" -j DROP")
		}
		rules["WW-SITE-DST"] = append(rules["WW-SITE-DST"], "-A WW-SITE-DST -d "+subnet+" -j DROP")
		for _, chain := range []string{"WW-SITE-FWD", "WW-SITE-IN", "WW-SITE-OUT"} {
			rules[chain] = append(rules[chain], "-A "+chain+" -s "+subnet+" -j WW-SITE-DST")
		}
	}
	for chain, list := range rules {
		for i, line := range list {
			rules[chain][i] = strings.Replace(line, " -j ", " -m comment --comment "+siteComment+" -j ", 1)
		}
	}
	return rules
}

func reconcileSiteFirewall(ctx context.Context, saved *config.Config, p *config.SiteLinkSnapshot, peers []config.SiteLinkTransitPeer, allow bool) error {
	if p.NodeRole == "hub" {
		if _, err := siteHubIngressInterface(saved, p); err != nil {
			return err
		}
	}
	rules := siteFirewallRules(saved, p, peers, allow)
	for _, table := range []string{"filter", "nat", "mangle"} {
		parents, chains := siteFirewallTable(table)
		var transaction strings.Builder
		transaction.WriteString("*" + table + "\n")
		exists := map[string]bool{}
		for _, chain := range chains {
			out, err := edgeIPTables(ctx, "-t", table, "-S", chain)
			if err != nil && !missingOwnedChain(ctx, table, chain, string(out)) {
				return fmt.Errorf("inspect owned site-link chain: %w: %s", err, strings.TrimSpace(string(out)))
			}
			exists[chain] = err == nil
			if len(peers) > 0 {
				transaction.WriteString(":" + chain + " - [0:0]\n")
			}
		}
		for _, chain := range chains {
			if exists[chain] || len(peers) > 0 {
				transaction.WriteString("-F " + chain + "\n")
			}
		}
		for _, parent := range parents {
			out, err := edgeIPTables(ctx, "-t", table, "-S", parent)
			if err != nil {
				return fmt.Errorf("inspect site-link parent rules: %w", err)
			}
			jump := "-A " + parent + " -m comment --comment " + siteComment + " -j " + siteParentChain(table, parent)
			for _, line := range strings.Split(string(out), "\n") {
				if strings.ReplaceAll(strings.TrimSpace(line), `"`, "") == jump {
					transaction.WriteString(strings.Replace(jump, "-A", "-D", 1) + "\n")
				}
			}
			if len(peers) > 0 {
				transaction.WriteString("-I " + parent + " 1 -m comment --comment " + siteComment + " -j " + siteParentChain(table, parent) + "\n")
			}
		}
		if len(peers) > 0 {
			for _, chain := range chains {
				for _, rule := range rules[chain] {
					transaction.WriteString(rule + "\n")
				}
			}
		} else {
			for _, chain := range chains {
				if exists[chain] {
					transaction.WriteString("-X " + chain + "\n")
				}
			}
		}
		transaction.WriteString("COMMIT\n")
		if err := edgeIPTablesRestore(ctx, transaction.String()); err != nil {
			return fmt.Errorf("apply owned site-link %s rules: %w", table, err)
		}
	}
	return nil
}
