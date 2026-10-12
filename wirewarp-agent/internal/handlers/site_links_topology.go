package handlers

import (
	"context"
	"fmt"
	"github.com/wirewarp/agent/internal/config"
	"net/netip"
	"time"
)

func ensureSitePeerGuard(cfg *config.Config, key string, allowed []string) error {
	saved := cfg.Snapshot()
	p := saved.SiteLinkDesired
	if p == nil || p.NodeRole != "hub" {
		return fmt.Errorf("gateway peer requires a saved site-link guard inventory")
	}
	if err := validateSiteSnapshot(saved, p); err != nil {
		return err
	}
	wanted := map[netip.Prefix]bool{}
	for _, value := range allowed {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			ip, ipErr := netip.ParseAddr(value)
			if ipErr != nil {
				return fmt.Errorf("invalid gateway peer AllowedIPs")
			}
			prefix = netip.PrefixFrom(ip, 32)
		}
		wanted[prefix.Masked()] = true
	}
	matched := false
	for _, peer := range p.TransitPeers {
		for _, value := range peer.AdvertisedSubnets {
			prefix, _ := netip.ParsePrefix(value)
			if peer.WireGuardPublicKey == key {
				if !wanted[prefix] {
					return fmt.Errorf("gateway peer AllowedIPs do not include advertised LAN")
				}
				matched = true
			}
			for candidate := range wanted {
				if candidate.Overlaps(prefix) && (peer.WireGuardPublicKey != key || candidate != prefix) {
					return fmt.Errorf("gateway peer AllowedIPs conflict with LAN guard inventory")
				}
			}
		}
	}
	if !matched {
		return fmt.Errorf("gateway peer is absent from saved site-link guard inventory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := RestoreSiteLinkGuard(ctx, cfg); err != nil {
		return fmt.Errorf("gateway peer refused because site-link guard failed: %w", err)
	}
	return nil
}

func (h *ServerHandlers) SetTopologyChanged(fn func()) { h.topologyChanged.Store(&fn) }
func (h *ClientHandlers) SetTopologyChanged(fn func()) { h.topologyChanged.Store(&fn) }
func (h *ServerHandlers) notifyTopologyChanged() {
	if fn := h.topologyChanged.Load(); fn != nil {
		(*fn)()
	}
}
func (h *ClientHandlers) notifyTopologyChanged() {
	if fn := h.topologyChanged.Load(); fn != nil {
		(*fn)()
	}
}
