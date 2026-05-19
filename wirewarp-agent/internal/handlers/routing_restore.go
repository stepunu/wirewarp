package handlers

import (
	"fmt"
	"log"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/iptables"
	"github.com/wirewarp/agent/internal/wireguard"
)

// RestoreRouting is the entry point for `wirewarp-agent --restore-routing`.
// It reads the saved config and re-applies the host-wide routing state
// the agent normally only installs at run-time: iptables rules on a
// server, ip rule + custom routing tables on a gateway client.
//
// The function is idempotent — running it on an already-healthy host is
// a no-op (everything underneath uses check-then-add semantics) — so the
// systemd unit can fire it as a oneshot at every boot without coordination.
func RestoreRouting(cfg *config.Config) error {
	switch cfg.Mode {
	case "server":
		return restoreRoutingServer(cfg)
	case "client":
		return restoreRoutingClient(cfg)
	case "":
		return fmt.Errorf("restore-routing: agent mode is unset; nothing to do")
	default:
		return fmt.Errorf("restore-routing: unknown agent mode %q", cfg.Mode)
	}
}

func restoreRoutingServer(cfg *config.Config) error {
	if cfg.Server == nil || !cfg.Server.Initialized {
		log.Println("[restore-routing] server agent has no saved wg state — nothing to restore")
		return nil
	}
	healed, err := iptables.HealServerNetwork(cfg.Server.PublicIface, cfg.Server.WGInterface)
	if err != nil {
		return fmt.Errorf("server network restore: %w", err)
	}
	if len(healed) > 0 {
		log.Printf("[restore-routing] server re-installed: %v", healed)
		if persistErr := iptables.SaveRules(); persistErr != nil {
			log.Printf("[restore-routing] WARN: persist iptables failed: %v", persistErr)
		}
	}
	return nil
}

func restoreRoutingClient(cfg *config.Config) error {
	if len(cfg.Attachments) == 0 {
		log.Println("[restore-routing] client agent has no saved attachments — nothing to restore")
		return nil
	}
	var firstErr error
	healedAny := false
	for i := range cfg.Attachments {
		att := &cfg.Attachments[i]
		gwCfg := wireguard.GatewayConfig{
			TunnelIface:     att.WGInterface,
			LANIface:        att.LANIface,
			VPSTunnelIP:     att.VPSTunnelIP,
			GatewayTunnelIP: att.TunnelIP,
			GatewayLANIP:    att.LANIP,
			LANNetwork:      att.LANNetwork,
			WGSubnet:        tunnelSubnet(att.TunnelIP),
			IsGateway:       att.IsGateway,
			Fwmark:          att.Fwmark,
			RouteTableID:    att.RouteTableID,
			ReplyPriority:   replyPriorityForIface(att.WGInterface),
		}
		healed, err := wireguard.HealAttachment(gwCfg)
		if err != nil {
			log.Printf("[restore-routing] %s: %v", att.WGInterface, err)
			if firstErr == nil {
				firstErr = err
			}
		}
		if len(healed) > 0 {
			log.Printf("[restore-routing] %s re-installed: %v", att.WGInterface, healed)
			healedAny = true
		}
	}
	if healedAny {
		if persistErr := iptables.SaveRules(); persistErr != nil {
			log.Printf("[restore-routing] WARN: persist iptables failed: %v", persistErr)
		}
	}
	return firstErr
}
