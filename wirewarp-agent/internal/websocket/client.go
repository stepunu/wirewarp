package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
)

const (
	heartbeatInterval = 30 * time.Second
	maxBackoff        = 60 * time.Second
	initialBackoff    = 1 * time.Second
)

type Client struct {
	cfg     *config.Config
	cfgPath string
	exec    *executor.Executor
	// sendFn is updated each time a new connection is established
	sendFn func(v any) error
	hostname string
}

func New(cfg *config.Config, cfgPath string) *Client {
	hostname, _ := os.Hostname()
	c := &Client{cfg: cfg, cfgPath: cfgPath, hostname: hostname}
	// Create executor with a send function that routes through the current connection
	c.exec = executor.New(func(result executor.Result) error {
		if c.sendFn == nil {
			return fmt.Errorf("not connected")
		}
		return c.sendFn(result)
	})
	return c
}

// Exec returns the executor so callers can register real handlers.
func (c *Client) Exec() *executor.Executor {
	return c.exec
}

// Run connects and reconnects forever with exponential backoff.
func (c *Client) Run(ctx context.Context) {
	backoff := initialBackoff
	for {
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[ws] disconnected: %v — retrying in %s", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(backoff)):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (c *Client) connect(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, c.cfg.ControlServerURL+"/ws/agent", nil)
	if err != nil {
		return err
	}
	defer conn.CloseNow()

	send := func(v any) error {
		return wsjson.Write(ctx, conn, v)
	}
	c.sendFn = send
	defer func() { c.sendFn = nil }()

	if c.cfg.AgentJWT != "" {
		if err := send(map[string]string{"type": "auth", "jwt": c.cfg.AgentJWT}); err != nil {
			return err
		}
		var resp map[string]string
		if err := wsjson.Read(ctx, conn, &resp); err != nil {
			return err
		}
		if resp["type"] != "authenticated" {
			// JWT expired — clear it and re-register on the next attempt
			c.cfg.AgentJWT = ""
			_ = c.cfg.Save(c.cfgPath)
			return fmt.Errorf("auth rejected: %s", resp["message"])
		}
		log.Printf("[ws] authenticated as agent %s", c.cfg.AgentID)
	} else {
		if err := send(map[string]string{
			"type":       "register",
			"token":      c.cfg.AgentToken,
			"hostname":   c.hostname,
			"agent_type": c.cfg.Mode,
		}); err != nil {
			return err
		}
		var resp map[string]string
		if err := wsjson.Read(ctx, conn, &resp); err != nil {
			return err
		}
		if resp["type"] != "registered" {
			return fmt.Errorf("registration failed: %s", resp["message"])
		}
		c.cfg.AgentID = resp["agent_id"]
		c.cfg.AgentJWT = resp["jwt"]
		c.cfg.AgentToken = ""
		if err := c.cfg.Save(c.cfgPath); err != nil {
			log.Printf("[ws] warning: failed to save config: %v", err)
		}
		log.Printf("[ws] registered as agent %s", c.cfg.AgentID)
	}

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	recvErr := make(chan error, 1)
	go func() {
		for {
			var raw json.RawMessage
			if err := wsjson.Read(ctx, conn, &raw); err != nil {
				recvErr <- err
				return
			}
			var cmd executor.Command
			if err := json.Unmarshal(raw, &cmd); err != nil {
				log.Printf("[ws] failed to unmarshal command: %v", err)
				continue
			}
			c.exec.Dispatch(cmd)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "shutting down")
			return nil
		case err := <-recvErr:
			return err
		case <-ticker.C:
			if err := send(map[string]string{
				"type":      "heartbeat",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				return err
			}
		}
	}
}


func jitter(d time.Duration) time.Duration {
	delta := float64(d) * 0.25
	return d + time.Duration((rand.Float64()*2-1)*delta)
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
