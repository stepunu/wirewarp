package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	wsclient "github.com/wirewarp/agent/internal/websocket"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

type identityHTTPTransport struct{ base http.RoundTripper }

func (transport identityHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host == "ipv4.icanhazip.com" {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	}
	return transport.base.RoundTrip(request)
}

func TestJWTEmptyIdentityPersistsBeforeActualSiteLinkCommand(t *testing.T) {
	old := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: identityHTTPTransport{base: http.DefaultTransport}}
	defer func() { http.DefaultClient = old }()
	cfg, p := siteFixture("gateway")
	cfg.AgentID = ""
	cfg.AgentJWT = "synthetic-test-token"
	cfg.Insecure = true
	path := filepath.Join(t.TempDir(), "agent.yaml")
	h := NewSiteLinks(cfg, path)
	h.firewall = func(_ context.Context, saved *config.Config, _ *config.SiteLinkSnapshot, _ []config.SiteLinkTransitPeer, _ bool) error {
		if saved.AgentID != siteAID {
			return errors.New("firewall ran before canonical identity")
		}
		return nil
	}
	h.ownership = func(context.Context, *config.Config, *config.SiteLinkSnapshot) error { return nil }
	h.routesPreflight = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	h.routesApply = func(context.Context, []config.SiteLinkRoute, []config.SiteLinkRoute) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	outcome := make(chan executor.Result, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.CloseNow()
		var auth map[string]string
		if err := wsjson.Read(ctx, conn, &auth); err != nil {
			t.Error(err)
			return
		}
		if err := wsjson.Write(ctx, conn, map[string]string{"type": "authenticated", "agent_id": siteAID}); err != nil {
			t.Error(err)
			return
		}
		if err := wsjson.Write(ctx, conn, map[string]any{"type": "site_link_desired_state", "id": "identity-site-command", "params": p}); err != nil {
			t.Error(err)
			return
		}
		for {
			var frame executor.Result
			if err := wsjson.Read(ctx, conn, &frame); err != nil {
				return
			}
			if frame.Type == "command_result" {
				outcome <- frame
				cancel()
				return
			}
		}
	}))
	defer server.Close()
	cfg.ControlServerURL = server.URL
	client := wsclient.New(cfg, path, "abcdef1")
	h.Register(client.Exec())
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()
	select {
	case result := <-outcome:
		if !result.Success {
			t.Fatalf("canonical JWT authentication failed actual Site Link command: %s", result.Output)
		}
	case <-ctx.Done():
		t.Fatal("no command result")
	}
	<-done
	saved, err := config.Load(path)
	if err != nil || saved.Snapshot().AgentID != siteAID || saved.Snapshot().SiteLinkApplied == nil {
		t.Fatal("identity and applied site snapshot not persisted", err)
	}
}
