package websocket

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nwebsocket "nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

func TestConfigureConnectionAllowsLargeControlFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := map[string]any{
		"type": "edge_desired_state",
		"id":   "large-frame",
		"params": map[string]any{
			"dynamic_config": strings.Repeat("x", 40*1024),
		},
	}
	serverErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := nwebsocket.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close(nwebsocket.StatusNormalClosure, "")
		serverErr <- wsjson.Write(ctx, conn, payload)
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := nwebsocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.CloseNow()
	configureConnection(conn)

	var got map[string]any
	if err := wsjson.Read(ctx, conn, &got); err != nil {
		t.Fatalf("read large control frame: %v", err)
	}
	if got["type"] != "edge_desired_state" {
		t.Fatalf("unexpected message type: %v", got["type"])
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("write large control frame: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("server did not write frame: %v", ctx.Err())
	}
}

func TestPingControlConnectionSendsPingAndAcceptsMatchingPong(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pongs := make(chan string, 1)
	var sent map[string]string
	send := func(v any) error {
		var ok bool
		sent, ok = v.(map[string]string)
		if !ok {
			t.Fatalf("unexpected ping payload type: %T", v)
		}
		pongs <- sent["nonce"]
		return nil
	}

	if err := pingControlConnection(ctx, send, pongs, time.Second); err != nil {
		t.Fatalf("ping control connection: %v", err)
	}
	if sent["type"] != "agent_ping" {
		t.Fatalf("unexpected ping type: %q", sent["type"])
	}
	if sent["nonce"] == "" {
		t.Fatal("expected non-empty ping nonce")
	}
}

func TestPingControlConnectionIgnoresStalePong(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pongs := make(chan string, 2)
	pongs <- "stale"
	send := func(v any) error {
		sent := v.(map[string]string)
		pongs <- sent["nonce"]
		return nil
	}

	if err := pingControlConnection(ctx, send, pongs, time.Second); err != nil {
		t.Fatalf("ping control connection: %v", err)
	}
}

func TestPingControlConnectionFailsWhenPeerDoesNotPong(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	send := func(v any) error { return nil }

	if err := pingControlConnection(ctx, send, make(chan string), 20*time.Millisecond); err == nil {
		t.Fatal("expected ping timeout without application pong")
	}
}

func TestPingControlConnectionReturnsSendError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	want := errors.New("write failed")
	send := func(v any) error { return want }

	if err := pingControlConnection(ctx, send, make(chan string), time.Second); !errors.Is(err, want) {
		t.Fatalf("expected send error %v, got %v", want, err)
	}
}
