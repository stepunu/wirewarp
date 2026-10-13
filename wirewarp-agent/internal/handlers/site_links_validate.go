package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/wirewarp/agent/internal/config"
)

var siteUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var siteInterface = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

type siteFlow struct {
	linkID, source, destination, protocol string
	port                                  int
	sourceSite, destinationSite           config.SiteLinkSite
	hub, snat                             string
}

func siteSnapshotHash(p *config.SiteLinkSnapshot) string {
	data, _ := json.Marshal(p)
	var payload map[string]any
	_ = json.Unmarshal(data, &payload)
	delete(payload, "revision")
	delete(payload, "desired_hash")
	var normalize func(any)
	normalize = func(v any) {
		switch value := v.(type) {
		case map[string]any:
			for key, child := range value {
				if child == nil && (key == "links" || key == "transit_peers" || key == "subnets" || key == "advertised_subnets" || key == "access_rules" || key == "destination_cidrs" || key == "destination_ports") {
					value[key] = []any{}
				} else {
					normalize(child)
				}
			}
		case []any:
			for _, child := range value {
				normalize(child)
			}
		}
	}
	normalize(payload)
	data, _ = json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func decodeSiteSnapshot(raw json.RawMessage) (*config.SiteLinkSnapshot, error) {
	if len(raw) > 1024*1024 {
		return nil, fmt.Errorf("site-link snapshot exceeds size limit")
	}
	var p config.SiteLinkSnapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid site-link snapshot")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid site-link snapshot")
	}
	return &p, nil
}

func sitePrefixes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 || len(values) > 32 {
		return nil, fmt.Errorf("site-link subnets must contain 1 to 32 IPv4 prefixes")
	}
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() {
			return nil, fmt.Errorf("site-link subnets require canonical unicast IPv4 prefixes")
		}
		for _, old := range out {
			if old.Overlaps(prefix) {
				return nil, fmt.Errorf("site-link subnets overlap")
			}
		}
		out = append(out, prefix)
	}
	return out, nil
}

func validateSiteSnapshot(saved *config.Config, p *config.SiteLinkSnapshot) error {
	if p.OwnerAgentID != "" && p.OwnerAgentID != saved.AgentID {
		return fmt.Errorf("saved site-link state belongs to another node identity")
	}
	if p.SchemaVersion != 1 || p.Revision <= 0 || len(p.Links) > 128 || len(p.TransitPeers) > 256 {
		return fmt.Errorf("unsupported site-link snapshot or limits")
	}
	if p.DesiredHash != siteSnapshotHash(p) {
		return fmt.Errorf("site-link snapshot hash does not match")
	}
	if p.NodeRole == "hub" {
		if saved.Mode != "server" {
			return fmt.Errorf("site-link hub requires a server node")
		}
		if _, err := siteHubIngressInterface(saved, p); err != nil {
			return err
		}
	} else if p.NodeRole == "gateway" {
		if p.HubWGInterface != "" {
			return fmt.Errorf("gateway site-link snapshot cannot name a hub interface")
		}
		if saved.Mode != "client" || !saved.Gateway() {
			return fmt.Errorf("site-link gateway requires a gateway node")
		}
	} else {
		return fmt.Errorf("invalid site-link node role")
	}
	if old := saved.SiteLinkDesired; old != nil && (p.Revision < old.Revision || p.Revision == old.Revision && p.DesiredHash != old.DesiredHash) {
		return fmt.Errorf("stale or conflicting site-link revision")
	}
	if released := saved.SiteLinkTeardown; released != nil && (released.AgentID != saved.AgentID || p.Revision <= released.Revision) {
		return fmt.Errorf("site-link desired revision must follow its released receipt")
	}
	peers := map[string]config.SiteLinkTransitPeer{}
	var allPrefixes []netip.Prefix
	var prefixOwners []string
	for _, peer := range p.TransitPeers {
		if !siteUUID.MatchString(peer.GatewayAgentID) || !siteUUID.MatchString(peer.AttachmentID) {
			return fmt.Errorf("invalid site-link peer identity")
		}
		key, err := base64.StdEncoding.DecodeString(peer.WireGuardPublicKey)
		if peer.WireGuardPublicKey != "" && (err != nil || len(key) != 32) {
			return fmt.Errorf("invalid site-link WireGuard public key")
		}
		if _, exists := peers[peer.AttachmentID]; exists {
			return fmt.Errorf("duplicate site-link attachment")
		}
		prefixes, err := sitePrefixes(peer.AdvertisedSubnets)
		if err != nil {
			return err
		}
		for _, prefix := range prefixes {
			for i, old := range allPrefixes {
				if old.Overlaps(prefix) && (prefixOwners[i] != peer.GatewayAgentID || old != prefix) {
					return fmt.Errorf("site-link peer subnets overlap")
				}
			}
			allPrefixes = append(allPrefixes, prefix)
			prefixOwners = append(prefixOwners, peer.GatewayAgentID)
		}
		peers[peer.AttachmentID] = peer
	}
	seen := map[string]bool{}
	for _, link := range p.Links {
		if !siteUUID.MatchString(link.ID) || seen[link.ID] || !siteUUID.MatchString(link.HubAgentID) {
			return fmt.Errorf("invalid or duplicate site-link identity")
		}
		seen[link.ID] = true
		if link.SiteA.GatewayAgentID == link.SiteB.GatewayAgentID || link.SiteA.AttachmentID == link.SiteB.AttachmentID {
			return fmt.Errorf("site-link endpoints must differ")
		}
		if p.NodeRole == "hub" && link.HubAgentID != saved.AgentID || p.NodeRole == "gateway" && link.SiteA.GatewayAgentID != saved.AgentID && link.SiteB.GatewayAgentID != saved.AgentID {
			return fmt.Errorf("site-link snapshot belongs to another node")
		}
		for _, site := range []config.SiteLinkSite{link.SiteA, link.SiteB} {
			peer, exists := peers[site.AttachmentID]
			if !exists || peer.GatewayAgentID != site.GatewayAgentID {
				return fmt.Errorf("site-link endpoint does not match peer inventory")
			}
			selected, err := sitePrefixes(site.Subnets)
			if err != nil {
				return err
			}
			advertised, _ := sitePrefixes(peer.AdvertisedSubnets)
			for _, prefix := range selected {
				contained := false
				for _, parent := range advertised {
					if parent.Contains(prefix.Addr()) && parent.Bits() <= prefix.Bits() {
						contained = true
					}
				}
				if !contained {
					return fmt.Errorf("site-link subnet is outside advertised inventory")
				}
			}
			if p.NodeRole == "gateway" && site.GatewayAgentID == saved.AgentID {
				att, ok := siteAttachment(saved, site.AttachmentID)
				if !ok || !att.IsGateway {
					return fmt.Errorf("site-link attachment is not a saved gateway attachment")
				}
				if _, err := edgeIPv4(att.LANIP); err != nil || !siteInterface.MatchString(att.LANIface) || !siteInterface.MatchString(att.WGInterface) {
					return fmt.Errorf("site-link gateway LAN metadata is invalid")
				}
				if att.ServerPublicKey == "" || att.VPSTunnelIP == "" || att.Fwmark == "" {
					return fmt.Errorf("site-link attachment authentication is incomplete")
				}
				lan, err := netip.ParsePrefix(att.LANNetwork)
				if err != nil || !lan.Addr().Is4() {
					return fmt.Errorf("site-link attachment LAN network is invalid")
				}
				for _, prefix := range selected {
					if !lan.Contains(prefix.Addr()) || prefix.Bits() < lan.Bits() {
						return fmt.Errorf("site-link selected subnet is outside saved gateway LAN")
					}
				}
			}
		}
		if link.SNATAtA != "preserve" && link.SNATAtA != "gateway_lan_ip" || link.SNATAtB != "preserve" && link.SNATAtB != "gateway_lan_ip" {
			return fmt.Errorf("invalid site-link destination NAT mode")
		}
		if len(link.AccessRules) > 64 {
			return fmt.Errorf("too many site-link access rules")
		}
		for _, rule := range link.AccessRules {
			site := link.SiteB
			if rule.Direction == "b_to_a" {
				site = link.SiteA
			} else if rule.Direction != "a_to_b" {
				return fmt.Errorf("invalid site-link rule direction")
			}
			if rule.Protocol != "any" && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
				return fmt.Errorf("invalid site-link rule protocol")
			}
			if len(rule.DestinationPorts) > 64 || len(rule.DestinationPorts) > 0 && rule.Protocol != "tcp" && rule.Protocol != "udp" {
				return fmt.Errorf("invalid site-link destination ports")
			}
			for _, port := range rule.DestinationPorts {
				if port < 1 || port > 65535 {
					return fmt.Errorf("invalid site-link destination port")
				}
			}
			prefixes, err := sitePrefixes(rule.DestinationCIDRs)
			if err != nil {
				return err
			}
			selected, _ := sitePrefixes(site.Subnets)
			for _, prefix := range prefixes {
				contained := false
				for _, parent := range selected {
					if parent.Contains(prefix.Addr()) && parent.Bits() <= prefix.Bits() {
						contained = true
					}
				}
				if !contained {
					return fmt.Errorf("site-link rule destination is outside selected subnets")
				}
			}
		}
	}
	if siteFlowCount(p) > 4096 {
		return fmt.Errorf("site-link compiled permission limit exceeded")
	}
	return nil
}

func siteFlowCount(p *config.SiteLinkSnapshot) int {
	count := 0
	for _, link := range p.Links {
		if !link.Enabled {
			continue
		}
		for _, direction := range []string{"a_to_b", "b_to_a"} {
			source, destination, enabled := link.SiteA, link.SiteB, link.AllowNewAToB
			if direction == "b_to_a" {
				source, destination, enabled = link.SiteB, link.SiteA, link.AllowNewBToA
			}
			if !enabled {
				continue
			}
			if len(link.AccessRules) == 0 {
				count += len(source.Subnets) * len(destination.Subnets)
			} else {
				for _, rule := range link.AccessRules {
					if rule.Direction != direction {
						continue
					}
					ports := len(rule.DestinationPorts)
					if ports == 0 {
						ports = 1
					}
					count += len(source.Subnets) * len(rule.DestinationCIDRs) * ports
				}
			}
			if count > 4096 {
				return count
			}
		}
	}
	return count
}

func siteAttachment(saved *config.Config, id string) (config.AttachmentState, bool) {
	for _, att := range saved.Attachments {
		if att.AttachmentID == id {
			return att, true
		}
	}
	return config.AttachmentState{}, false
}

func compileSiteFlows(p *config.SiteLinkSnapshot) []siteFlow {
	var flows []siteFlow
	for _, link := range p.Links {
		if !link.Enabled {
			continue
		}
		for _, direction := range []string{"a_to_b", "b_to_a"} {
			source, destination, enabled, snat := link.SiteA, link.SiteB, link.AllowNewAToB, link.SNATAtB
			if direction == "b_to_a" {
				source, destination, enabled, snat = link.SiteB, link.SiteA, link.AllowNewBToA, link.SNATAtA
			}
			if !enabled {
				continue
			}
			rules := link.AccessRules
			if len(rules) == 0 {
				rules = []config.SiteLinkAccessRule{{Direction: direction, DestinationCIDRs: destination.Subnets, Protocol: "any"}}
			}
			for _, rule := range rules {
				if rule.Direction != direction {
					continue
				}
				ports := rule.DestinationPorts
				if len(ports) == 0 {
					ports = []int{0}
				}
				for _, src := range source.Subnets {
					for _, dst := range rule.DestinationCIDRs {
						for _, port := range ports {
							flows = append(flows, siteFlow{link.ID, src, dst, rule.Protocol, port, source, destination, link.HubAgentID, snat})
						}
					}
				}
			}
		}
	}
	return flows
}

func siteUnionPeers(old, next []config.SiteLinkTransitPeer) []config.SiteLinkTransitPeer {
	var result []config.SiteLinkTransitPeer
	seen := map[string]bool{}
	for _, peer := range append(append([]config.SiteLinkTransitPeer{}, old...), next...) {
		for _, subnet := range peer.AdvertisedSubnets {
			key := peer.AttachmentID + "|" + subnet
			if !seen[key] {
				seen[key] = true
				copy := peer
				copy.AdvertisedSubnets = []string{subnet}
				result = append(result, copy)
			}
		}
	}
	return result
}

func siteOriginalMatch(flow siteFlow) string {
	match := " -m conntrack --ctorigsrc " + flow.source + " --ctorigdst " + flow.destination
	if flow.protocol != "any" {
		match += " --ctproto " + flow.protocol
	}
	if flow.port != 0 {
		match += fmt.Sprintf(" --ctorigdstport %d", flow.port)
	}
	return strings.TrimSpace(match)
}
