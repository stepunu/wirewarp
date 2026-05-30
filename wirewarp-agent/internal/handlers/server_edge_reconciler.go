package handlers

import (
	"context"
	"log"
	"time"
)

// StartEdgeReconciler is the unified server-mode reconcile loop. It folds
// the older network healer, CrowdSec status poller, and Traefik status poller
// into one cadence so degraded edge components back off together instead of
// thrashing independent loops.
func (h *ServerHandlers) StartEdgeReconciler(ctx context.Context) {
	go h.edgeReconcileLoop(ctx)
}

func (h *ServerHandlers) edgeReconcileLoop(ctx context.Context) {
	failures := 0
	for {
		runCtx, cancel := context.WithTimeout(ctx, 12*time.Minute)
		err := h.edgeReconcileOnce(runCtx)
		cancel()
		if err != nil {
			failures++
			log.Printf("[edge-reconcile] degraded: %v", err)
		} else {
			failures = 0
		}

		delayAttempt := failures
		if delayAttempt > 0 {
			delayAttempt--
		}
		delay := edgeBackoffDuration(delayAttempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (h *ServerHandlers) edgeReconcileOnce(ctx context.Context) error {
	h.healOnce()
	if h.cfg.EdgeDesired != nil {
		return h.reconcileDesiredEdge(ctx)
	}
	h.pollAndEmitCrowdSec(ctx, true)
	h.pollAndEmitTraefik(ctx, true)
	return nil
}
