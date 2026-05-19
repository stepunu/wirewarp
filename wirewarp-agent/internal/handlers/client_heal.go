package handlers

import (
	"context"
	"log"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/iptables"
	"github.com/wirewarp/agent/internal/wireguard"
)

// healInterval is how often the heal loop wakes up. 60s is a compromise:
// fast enough to recover from drift within one client retry-budget on
// most protocols, slow enough that the iptables / `ip rule` lookups don't
// cost anything noticeable on the host.
const healInterval = 60 * time.Second

// EmitFn is the signature of the agent's upstream telemetry channel.
// Healers and pollers call it to push a structured event to the control
// server. Returning nil silently when there is no live connection is the
// expected behaviour — see `*websocket.Client.Emit`.
type EmitFn func(eventType string, payload map[string]any) error

// StartHealer launches the background goroutine that verifies per-
// attachment routing state on a cadence and re-installs anything that
// drifted. Returns immediately. The goroutine exits when ctx is done.
//
// The healer is independent of the WebSocket loop: even if the control
// server is unreachable, drift on locally-installed rules is still
// detected and repaired. This is the path that catches the real
// incident this loop is here for — an `ip rule fwmark` that vanishes
// after the initial wg_attach without the agent noticing.
func (h *ClientHandlers) StartHealer(ctx context.Context) {
	go h.healLoop(ctx)
}

func (h *ClientHandlers) healLoop(ctx context.Context) {
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

func (h *ClientHandlers) healOnce() {
	snapshot := h.snapshotAttachments()
	if len(snapshot) == 0 {
		return
	}
	var anyHealed bool
	for i := range snapshot {
		att := &snapshot[i]
		gwCfg := h.buildGatewayConfig(att)
		healed, err := wireguard.HealAttachment(gwCfg)
		if err != nil {
			log.Printf("[heal] attachment %s: %v", att.WGInterface, err)
		}
		if len(healed) > 0 {
			anyHealed = true
			log.Printf("[heal] attachment %s re-installed: %v", att.WGInterface, healed)
			h.emitHealEvent("client", att.WGInterface, healed)
		}
	}
	if anyHealed {
		if err := iptables.SaveRules(); err != nil {
			log.Printf("[heal] WARN: persist iptables failed: %v", err)
		}
	}
}

// SetEmit installs the upstream telemetry channel. Safe to call once at
// agent startup; the healer's goroutine reads the pointer atomically.
func (h *ClientHandlers) SetEmit(fn EmitFn) {
	h.emit.Store(&fn)
}

// emitHealEvent pushes a `heal_event` frame to the control server. Safe
// to call when no emit fn has been installed (no-op).
func (h *ClientHandlers) emitHealEvent(mode, iface string, healed []string) {
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


// snapshotAttachments returns a shallow copy of the attachment slice for
// the healer to iterate over safely while wg_attach / wg_detach handlers
// continue to mutate the underlying config slice on the dispatch goroutine.
func (h *ClientHandlers) snapshotAttachments() []config.AttachmentState {
	src := h.cfg.Attachments
	out := make([]config.AttachmentState, len(src))
	copy(out, src)
	return out
}
