package handlers

import (
	"context"
	"log"
	"time"

	"github.com/wirewarp/agent/internal/iptables"
)

// StartHealer launches the background goroutine that verifies host-wide
// network state on the tunnel-server (VPS) agent and re-installs any
// pieces that drifted. Per-forward DNAT/FORWARD rules are reconciled by
// the control-server replay loop on reconnect and are intentionally out
// of scope here.
//
// Runs every healInterval (defined in client_heal.go). Exits when ctx is
// done.
func (h *ServerHandlers) StartHealer(ctx context.Context) {
	go h.healLoop(ctx)
}

func (h *ServerHandlers) healLoop(ctx context.Context) {
	t := time.NewTicker(healInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.healOnce()
		}
	}
}

func (h *ServerHandlers) healOnce() {
	if h.cfg.Server == nil || !h.cfg.Server.Initialized {
		return
	}
	healed, err := iptables.HealServerNetwork(h.cfg.Server.PublicIface, h.cfg.Server.WGInterface)
	if err != nil {
		log.Printf("[heal] server network: %v", err)
	}
	if len(healed) > 0 {
		log.Printf("[heal] server network re-installed: %v", healed)
		h.emitHealEvent("server", h.cfg.Server.WGInterface, healed)
		if err := iptables.SaveRules(); err != nil {
			log.Printf("[heal] WARN: persist iptables failed: %v", err)
		}
	}
}

// SetEmit installs the upstream telemetry channel. See ClientHandlers.SetEmit.
func (h *ServerHandlers) SetEmit(fn EmitFn) {
	h.emit.Store(&fn)
}

func (h *ServerHandlers) emitHealEvent(mode, iface string, healed []string) {
	p := h.emit.Load()
	if p == nil {
		return
	}
	fn := *p
	if fn == nil {
		return
	}
	_ = fn("heal_event", map[string]any{
		"mode":      mode,
		"interface": iface,
		"healed":    healed,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
