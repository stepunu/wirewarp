package handlers

import (
	"fmt"

	"github.com/wirewarp/agent/internal/config"
)

// The controller can name the hub interface before WireGuard exists locally.
func siteHubIngressInterface(saved *config.Config, p *config.SiteLinkSnapshot) (string, error) {
	interfaceName := p.HubWGInterface
	existing := ""
	if saved.Server != nil {
		existing = saved.Server.WGInterface
	}
	if interfaceName == "" {
		interfaceName = existing
	}
	if !siteInterface.MatchString(interfaceName) {
		return "", fmt.Errorf("site-link hub requires an authenticated WireGuard interface")
	}
	if existing != "" && existing != interfaceName {
		return "", fmt.Errorf("site-link hub WireGuard interface conflicts with saved networking")
	}
	return interfaceName, nil
}
