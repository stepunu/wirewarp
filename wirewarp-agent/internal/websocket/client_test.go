package websocket

import (
	"context"
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
