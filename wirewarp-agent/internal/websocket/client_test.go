package websocket

import (
	"context"
	"encoding/json"
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

func TestPingControlConnectionSucceedsWhenPeerReads(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := nwebsocket.Accept(w, r, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close(nwebsocket.StatusNormalClosure, "")
		var raw json.RawMessage
		err = wsjson.Read(ctx, conn, &raw)
		if err != nil && ctx.Err() == nil && nwebsocket.CloseStatus(err) != nwebsocket.StatusNormalClosure {
			serverErr <- err
		}
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := nwebsocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.CloseNow()
	clientReadErr := make(chan error, 1)
	go drainWebSocket(ctx, conn, clientReadErr)

	if err := pingControlConnection(ctx, conn, time.Second); err != nil {
		t.Fatalf("ping control connection: %v", err)
	}
	_ = conn.Close(nwebsocket.StatusNormalClosure, "")

	select {
	case err := <-serverErr:
		t.Fatalf("server read failed: %v", err)
	default:
	}
}

func TestPingControlConnectionFailsWhenPeerDoesNotPong(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverCtx, stopServer := context.WithCancel(context.Background())
	accepted := make(chan *nwebsocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := nwebsocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		accepted <- conn
		<-serverCtx.Done()
		conn.CloseNow()
	}))

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := nwebsocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.CloseNow()
	clientReadErr := make(chan error, 1)
	go drainWebSocket(ctx, conn, clientReadErr)
	<-accepted

	if err := pingControlConnection(ctx, conn, 50*time.Millisecond); err == nil {
		t.Fatal("expected ping timeout when peer does not read pong")
	}
	stopServer()
	server.Close()
}

func drainWebSocket(ctx context.Context, conn *nwebsocket.Conn, errs chan<- error) {
	for {
		_, _, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() == nil && nwebsocket.CloseStatus(err) != nwebsocket.StatusNormalClosure {
				errs <- err
			}
			return
		}
	}
}
