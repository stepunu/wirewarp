package websocket

import (
	"fmt"
	"regexp"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/firewall"
)

var canonicalAgentID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func ownedIdentityMatches(saved *config.Config, id string) error {
	if (len(saved.SiteLinkGuardPeers) != 0 || len(saved.SiteLinkRoutes) != 0) && saved.SiteLinkDesired == nil && saved.SiteLinkApplied == nil {
		return fmt.Errorf("authenticated identity cannot claim site-link state without saved ownership")
	}
	if saved.UpdateReceipt != nil && saved.UpdateReceipt.OwnerAgentID != id {
		return fmt.Errorf("authenticated identity conflicts with saved update receipt")
	}
	for _, snapshot := range []*config.SiteLinkSnapshot{saved.SiteLinkDesired, saved.SiteLinkApplied} {
		if snapshot != nil && snapshot.OwnerAgentID != id {
			return fmt.Errorf("authenticated identity conflicts with saved site-link ownership")
		}
	}
	if saved.SiteLinkTeardown != nil && saved.SiteLinkTeardown.AgentID != id {
		return fmt.Errorf("authenticated identity conflicts with saved site-link teardown receipt")
	}
	return nil
}

// Accept only the server's authenticated identity. Existing owners never change.
func (c *Client) acceptAuthenticatedIdentity(id string) error {
	saved := c.cfg.Snapshot()
	if id == "" {
		if saved.AgentID == "" {
			return fmt.Errorf("authenticated response has no agent identity; upgrade the control server")
		}
		id = saved.AgentID // Older servers cannot fill an empty installation identity.
	} else if !canonicalAgentID.MatchString(id) {
		return fmt.Errorf("authenticated response has an invalid agent identity")
	}
	if saved.AgentID != "" && saved.AgentID != id {
		return fmt.Errorf("authenticated identity does not match this installation; saved ownership was not changed")
	}
	if err := ownedIdentityMatches(saved, id); err != nil {
		return err
	}
	if err := firewall.ValidateIdentity(id, c.cfgPath); err != nil {
		return fmt.Errorf("authenticated identity conflicts with owned firewall journal: %w", err)
	}
	if saved.AgentID != "" {
		return nil
	}
	if err := c.cfg.UpdateAndSave(c.cfgPath, func(next *config.Config) error {
		if next.AgentID != "" && next.AgentID != id {
			return fmt.Errorf("agent identity changed during authentication")
		}
		if err := ownedIdentityMatches(next, id); err != nil {
			return err
		}
		if err := firewall.ValidateIdentity(id, c.cfgPath); err != nil {
			return fmt.Errorf("authenticated identity conflicts with owned firewall journal: %w", err)
		}
		next.AgentID = id
		return nil
	}); err != nil {
		return fmt.Errorf("persist authenticated identity: %w", err)
	}
	return nil
}
