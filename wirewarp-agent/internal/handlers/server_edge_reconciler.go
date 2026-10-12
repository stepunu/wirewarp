package handlers

import (
	"context"
	"log"
	"time"
)

// StartEdgeReconciler converges HTTP edge services on eligible nodes.
func (h *EdgeHandlers) StartEdgeReconciler(ctx context.Context) {
	go h.edgeReconcileLoop(ctx)
}

func (h *EdgeHandlers) edgeReconcileLoop(ctx context.Context) {
	failures := 0
	for {
		if err := RetryACMEDNSCleanup(ctx); err != nil {
			log.Printf("[acme-cleanup] degraded: %v", err)
		}
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

func (h *EdgeHandlers) edgeReconcileOnce(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	saved := h.cfg.Snapshot()
	if !h.eligible() || saved.EdgeDisabled {
		if saved.EdgeDesired != nil || saved.Mode == "server" && saved.EdgeDisabled || saved.EdgeRuntimePending || len(saved.EdgeIngressGuard) != 0 {
			_, err := h.stopDisabledEdge(nil)
			return err
		}
		return nil
	}
	if saved.EdgeDesired != nil {
		if err := validateEdgeRuntime(saved, saved.EdgeDesired); err != nil {
			return err
		}
		return h.convergeEdgeRuntime(ctx)
	}
	if saved.Mode != "server" {
		return nil
	}
	h.pollAndEmitCrowdSec(ctx, true)
	h.pollAndEmitTraefik(ctx, true)
	h.pollAndEmitNginxCache(ctx, true)
	return nil
}
