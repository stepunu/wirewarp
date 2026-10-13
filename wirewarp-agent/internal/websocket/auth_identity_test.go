package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const authOwner = "00000000-0000-4000-8000-000000000001"
const authOther = "00000000-0000-4000-8000-000000000002"

func TestJWTIdentityFailureStopsCommandsAndPreservesCredentials(t *testing.T) {
	for _, kind := range []string{"invalid-id", "missing-id", "existing-mismatch", "update-owner", "site-desired-owner", "site-applied-owner", "teardown-owner", "orphan-guard", "save-failure"} {
		t.Run(kind, func(t *testing.T) {
			cfg := &config.Config{AgentJWT: "synthetic-auth-token", Insecure: true}
			canonical := authOwner
			path := filepath.Join(t.TempDir(), "agent.yaml")
			switch kind {
			case "invalid-id":
				canonical = "not-a-uuid"
			case "missing-id":
				canonical = ""
			case "existing-mismatch":
				cfg.AgentID = authOther
			case "update-owner":
				cfg.UpdateReceipt = &config.AgentUpdateReceipt{OwnerAgentID: authOther}
			case "site-desired-owner":
				cfg.SiteLinkDesired = &config.SiteLinkSnapshot{OwnerAgentID: authOther}
			case "site-applied-owner":
				cfg.SiteLinkApplied = &config.SiteLinkSnapshot{OwnerAgentID: authOther}
			case "teardown-owner":
				cfg.SiteLinkTeardown = &config.SiteLinkTeardownReceipt{AgentID: authOther}
			case "orphan-guard":
				cfg.SiteLinkGuardPeers = []config.SiteLinkTransitPeer{{GatewayAgentID: authOther}}
			case "save-failure":
				block := filepath.Join(t.TempDir(), "block")
				if err := os.WriteFile(block, []byte("block"), 0600); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(block, "agent.yaml")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var frames atomic.Int32
			serverDone := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(serverDone)
				conn, err := websocket.Accept(w, r, nil)
				if err != nil {
					return
				}
				defer conn.CloseNow()
				var auth map[string]string
				if wsjson.Read(ctx, conn, &auth) != nil {
					return
				}
				wsjson.Write(ctx, conn, map[string]string{"type": "authenticated", "agent_id": canonical})
				wsjson.Write(ctx, conn, map[string]any{"type": "must-not-run", "id": "blocked-command", "params": map[string]any{}})
				for {
					var frame map[string]any
					if wsjson.Read(ctx, conn, &frame) != nil {
						return
					}
					frames.Add(1)
				}
			}))
			defer server.Close()
			cfg.ControlServerURL = server.URL
			c := New(cfg, path, "abcdef1")
			var effects atomic.Int32
			c.Exec().Register("must-not-run", func(_ json.RawMessage) (string, error) { effects.Add(1); return "", nil })
			if err := c.connect(ctx); err == nil {
				t.Fatal("invalid authentication identity accepted")
			}
			select {
			case <-serverDone:
			case <-ctx.Done():
				t.Fatal("connection did not close on identity error")
			}
			if effects.Load() != 0 || frames.Load() != 0 {
				t.Fatal("commands or heartbeat ran after identity failure")
			}
			saved := cfg.Snapshot()
			expectedID := ""
			if kind == "existing-mismatch" {
				expectedID = authOther
			}
			if saved.AgentID != expectedID || saved.AgentJWT != "synthetic-auth-token" || saved.AgentToken != "" {
				t.Fatal("identity rejection changed ownership or credentials")
			}
		})
	}
}

func TestAuthenticationOldServerCompatibilityAndMatchingOwner(t *testing.T) {
	for _, kind := range []string{"legacy-with-id", "canonical-matching"} {
		t.Run(kind, func(t *testing.T) {
			cfg := &config.Config{AgentID: authOwner, AgentJWT: "synthetic", UpdateReceipt: &config.AgentUpdateReceipt{OwnerAgentID: authOwner}, SiteLinkDesired: &config.SiteLinkSnapshot{OwnerAgentID: authOwner}, SiteLinkApplied: &config.SiteLinkSnapshot{OwnerAgentID: authOwner}, SiteLinkTeardown: &config.SiteLinkTeardownReceipt{AgentID: authOwner}}
			path := filepath.Join(t.TempDir(), "agent.yaml")
			c := New(cfg, path, "abcdef1")
			id := authOwner
			if strings.HasPrefix(kind, "legacy") {
				id = ""
			}
			if err := c.acceptAuthenticatedIdentity(id); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("matching existing identity was needlessly rewritten")
			}
			if cfg.Snapshot().AgentID != authOwner || cfg.Snapshot().UpdateReceipt.OwnerAgentID != authOwner {
				t.Fatal("existing ownership changed")
			}
		})
	}
}
