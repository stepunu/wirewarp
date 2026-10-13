package websocket

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	nwebsocket "nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

type receiptHTTPTransport struct{ base http.RoundTripper }

func (transport receiptHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "ipv4.icanhazip.com" {
		return transport.base.RoundTrip(request)
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func TestAuthenticatedReconnectReplaysReceiptUntilExactACK(t *testing.T) {
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: receiptHTTPTransport{base: http.DefaultTransport}}
	defer func() { http.DefaultClient = oldClient }()
	var attempts atomic.Int32
	var acknowledged atomic.Bool
	serverErr := make(chan error, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := nwebsocket.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var auth map[string]string
		if err := wsjson.Read(ctx, conn, &auth); err != nil {
			serverErr <- err
			return
		}
		if auth["type"] != "auth" {
			serverErr <- errors.New("receipt sent before authentication")
			return
		}
		if err := wsjson.Write(ctx, conn, map[string]string{"type": "authenticated"}); err != nil {
			serverErr <- err
			return
		}
		var receipt executor.Result
		if err := wsjson.Read(ctx, conn, &receipt); err != nil {
			serverErr <- err
			return
		}
		if receipt.ReceiptID != "receipt" || receipt.CommandID != "update" {
			serverErr <- errors.New("pending receipt not replayed after authentication")
			return
		}
		if attempts.Add(1) == 1 {
			serverErr <- nil
			return
		} // Lose the first ACK entirely.
		var heartbeat map[string]any
		if err := wsjson.Read(ctx, conn, &heartbeat); err != nil {
			serverErr <- err
			return
		}
		if heartbeat["type"] != "heartbeat" {
			serverErr <- errors.New("unexpected receipt before ACK")
			return
		}
		if err := wsjson.Write(ctx, conn, map[string]string{"type": "command_result_ack", "agent_id": "foreign", "command_id": "update", "receipt_id": "receipt"}); err != nil {
			serverErr <- err
			return
		}
		extra := make(chan error, 1)
		go func() {
			var frame map[string]any
			err := wsjson.Read(ctx, conn, &frame)
			if err == nil {
				err = errors.New("identity error caused immediate receipt ACK loop")
			}
			extra <- err
		}()
		select {
		case err := <-extra:
			serverErr <- err
			return
		case <-time.After(150 * time.Millisecond):
		}
		if err := wsjson.Write(ctx, conn, map[string]string{"type": "command_result_ack", "agent_id": "owner", "command_id": "update", "receipt_id": "receipt"}); err != nil {
			serverErr <- err
			return
		}
		<-ctx.Done()
	}))
	defer server.Close()
	c := New(&config.Config{AgentID: "owner", AgentJWT: "synthetic-test-token", ControlServerURL: server.URL, Insecure: true}, "", "abcdef1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c.SetUpdateReceipts(func() (*executor.Result, error) {
		if acknowledged.Load() {
			return nil, nil
		}
		return &executor.Result{Type: "command_result", CommandID: "update", ReceiptID: "receipt", Success: true}, nil
	}, func(owner, id, receipt string) error {
		if owner != "owner" || id != "update" || receipt != "receipt" {
			return errors.New("incorrect ACK fields")
		}
		acknowledged.Store(true)
		cancel()
		return nil
	})
	_ = c.connect(ctx)
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("authentication/replay server was not reached")
	}
	_ = c.connect(ctx)
	if !acknowledged.Load() || attempts.Load() != 2 {
		t.Fatal("lost ACK did not replay across authenticated reconnect")
	}
}

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
