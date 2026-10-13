package config

type SiteLinkTeardownReceipt struct {
	AgentID     string `yaml:"agent_id"`
	Revision    int64  `yaml:"revision"`
	DesiredHash string `yaml:"desired_hash"`
}

type SiteLinkSnapshot struct {
	OwnerAgentID   string                `json:"-" yaml:"owner_agent_id"`
	SchemaVersion  int                   `json:"schema_version" yaml:"schema_version"`
	Revision       int64                 `json:"revision" yaml:"revision"`
	DesiredHash    string                `json:"desired_hash" yaml:"desired_hash"`
	NodeRole       string                `json:"node_role" yaml:"node_role"`
	HubWGInterface string                `json:"hub_wireguard_interface,omitempty" yaml:"hub_wireguard_interface,omitempty"`
	Links          []SiteLink            `json:"links" yaml:"links"`
	TransitPeers   []SiteLinkTransitPeer `json:"transit_peers" yaml:"transit_peers"`
}

type SiteLink struct {
	ID           string               `json:"id" yaml:"id"`
	Enabled      bool                 `json:"enabled" yaml:"enabled"`
	HubAgentID   string               `json:"hub_agent_id" yaml:"hub_agent_id"`
	SiteA        SiteLinkSite         `json:"site_a" yaml:"site_a"`
	SiteB        SiteLinkSite         `json:"site_b" yaml:"site_b"`
	AllowNewAToB bool                 `json:"allow_new_a_to_b" yaml:"allow_new_a_to_b"`
	AllowNewBToA bool                 `json:"allow_new_b_to_a" yaml:"allow_new_b_to_a"`
	SNATAtA      string               `json:"snat_at_a" yaml:"snat_at_a"`
	SNATAtB      string               `json:"snat_at_b" yaml:"snat_at_b"`
	AccessRules  []SiteLinkAccessRule `json:"access_rules" yaml:"access_rules"`
}

type SiteLinkSite struct {
	GatewayAgentID string   `json:"gateway_agent_id" yaml:"gateway_agent_id"`
	AttachmentID   string   `json:"attachment_id" yaml:"attachment_id"`
	Subnets        []string `json:"subnets" yaml:"subnets"`
}

type SiteLinkAccessRule struct {
	Direction        string   `json:"direction" yaml:"direction"`
	DestinationCIDRs []string `json:"destination_cidrs" yaml:"destination_cidrs"`
	Protocol         string   `json:"protocol" yaml:"protocol"`
	DestinationPorts []int    `json:"destination_ports" yaml:"destination_ports"`
}

type SiteLinkTransitPeer struct {
	GatewayAgentID     string   `json:"gateway_agent_id" yaml:"gateway_agent_id"`
	AttachmentID       string   `json:"attachment_id" yaml:"attachment_id"`
	AdvertisedSubnets  []string `json:"advertised_subnets" yaml:"advertised_subnets"`
	WireGuardPublicKey string   `json:"wireguard_public_key" yaml:"wireguard_public_key"`
}

// Each route uses a dedicated table and an exact, tagged source/destination
// rule. Attachment healers cannot flush these tables.
type SiteLinkRoute struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	Interface   string `yaml:"interface"`
	NextHop     string `yaml:"next_hop"`
	Table       int    `yaml:"table"`
	Priority    int    `yaml:"priority"`
}

func cloneSiteLinks(input *SiteLinkSnapshot) *SiteLinkSnapshot {
	if input == nil {
		return nil
	}
	out := *input
	out.Links = append([]SiteLink(nil), input.Links...)
	for i := range out.Links {
		out.Links[i].SiteA.Subnets = append([]string(nil), input.Links[i].SiteA.Subnets...)
		out.Links[i].SiteB.Subnets = append([]string(nil), input.Links[i].SiteB.Subnets...)
		out.Links[i].AccessRules = append([]SiteLinkAccessRule(nil), input.Links[i].AccessRules...)
		for j := range out.Links[i].AccessRules {
			out.Links[i].AccessRules[j].DestinationCIDRs = append([]string(nil), input.Links[i].AccessRules[j].DestinationCIDRs...)
			out.Links[i].AccessRules[j].DestinationPorts = append([]int(nil), input.Links[i].AccessRules[j].DestinationPorts...)
		}
	}
	out.TransitPeers = cloneSiteLinkPeers(input.TransitPeers)
	return &out
}

func cloneSiteLinkPeers(input []SiteLinkTransitPeer) []SiteLinkTransitPeer {
	out := append([]SiteLinkTransitPeer(nil), input...)
	for i := range out {
		out[i].AdvertisedSubnets = append([]string(nil), input[i].AdvertisedSubnets...)
	}
	return out
}
