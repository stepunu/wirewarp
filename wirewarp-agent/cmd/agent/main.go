package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/handlers"
	"github.com/wirewarp/agent/internal/validate"
	wsclient "github.com/wirewarp/agent/internal/websocket"
)

// version is set at build time via -ldflags "-X main.version=<git-sha>".
var version = "dev"

func main() {
	mode := flag.String("mode", "", "Agent mode: server or client (required on first run)")
	cfgPath := flag.String("config", config.DefaultPath, "Path to agent config file")
	url := flag.String("url", "", "Control server URL (e.g. https://wirewarp.example.com)")
	token := flag.String("token", "", "Registration token (first run only)")
	insecure := flag.Bool("insecure", false, "Allow plain http:// control-server URL (homelab/bootstrap only — MITM risk)")
	flag.Parse()

	// Load existing config or bootstrap from flags
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Failed to load config: %v", err)
		}
		// First run — build config from flags
		if *mode == "" || *url == "" || *token == "" {
			log.Fatal("First run requires --mode, --url, and --token flags")
		}
		if err := validate.ControlServerURL(*url, *insecure); err != nil {
			log.Fatalf("Invalid --url: %v", err)
		}
		cfg = &config.Config{
			Mode:             *mode,
			ControlServerURL: *url,
			AgentToken:       *token,
			Insecure:         *insecure,
		}
		if err := cfg.Save(*cfgPath); err != nil {
			log.Fatalf("Failed to save initial config: %v", err)
		}
		log.Printf("Config saved to %s", *cfgPath)
	}

	// Reject any saved http:// URL on every startup unless the config was
	// installed with --insecure, so a hand-edited agent.yaml can't silently
	// reintroduce a plaintext WS channel.
	if err := validate.ControlServerURL(cfg.ControlServerURL, cfg.Insecure); err != nil {
		log.Fatalf("Refusing to start with invalid control-server URL %q: %v", cfg.ControlServerURL, err)
	}
	if cfg.Insecure {
		log.Printf("WARNING: agent configured with --insecure — control-server URL is http://, WS channel is plaintext (token + command stream are MITM-able)")
	}

	log.Printf("Starting WireWarp agent (mode=%s, version=%s)", cfg.Mode, version)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client := wsclient.New(cfg, *cfgPath, version)

	// shutdownFn is called after the WebSocket loop exits to clean up.
	var shutdownFn func()

	// Apply last-known config from disk and register real command handlers (task 4.5).
	switch cfg.Mode {
	case "server":
		srv, err := handlers.NewServer(cfg, *cfgPath)
		if err != nil {
			log.Fatalf("Failed to initialise server handlers: %v", err)
		}
		srv.Register(client.Exec())
		srv.StartHealer(ctx)
		shutdownFn = srv.Shutdown
	case "client":
		cli, err := handlers.NewClient(cfg, *cfgPath)
		if err != nil {
			log.Fatalf("Failed to initialise client handlers: %v", err)
		}
		cli.Register(client.Exec())
		cli.StartHealer(ctx)
		shutdownFn = cli.Shutdown
	default:
		log.Fatalf("Unknown mode: %s (must be 'server' or 'client')", cfg.Mode)
	}

	// VPN endpoints live on gateway clients (road-warrior wg) but the
	// handlers register in both modes so a stray vpn_* command from the
	// control server returns a clean error instead of a "no handler" log
	// line. NewVpnHandlers also brings any saved endpoint up immediately
	// for offline-resilience.
	vpn, err := handlers.NewVpnHandlers(cfg, *cfgPath)
	if err != nil {
		log.Fatalf("Failed to initialise VPN handlers: %v", err)
	}
	vpn.Register(client.Exec())
	if cfg.Mode == "client" {
		// The first gateway attachment's LAN egress interface is the
		// homelab WAN, which is what full-tunnel VPN peers MASQUERADE
		// against. Server-mode agents have no LAN attachment.
		for _, a := range cfg.Attachments {
			if a.IsGateway && a.LANIface != "" {
				vpn.SetWanIface(a.LANIface)
				break
			}
		}
	}
	wsclient.SetVpnInterfacesProvider(client, vpn.LiveInterfaces)

	// agent_update works in both modes — download new binary and restart via systemd.
	client.Exec().Register("agent_update", handleAgentUpdate)

	client.Run(ctx)

	if shutdownFn != nil {
		shutdownFn()
	}
	log.Println("Agent stopped")
}

func handleAgentUpdate(_ json.RawMessage) (string, error) {
	const (
		binaryURL  = "https://github.com/stepunu/wirewarp/raw/main/wirewarp-agent/dist/wirewarp-agent"
		binaryPath = "/usr/local/bin/wirewarp-agent"
	)

	resp, err := http.Get(binaryURL) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download binary: HTTP %d", resp.StatusCode)
	}

	tmpPath := binaryPath + ".new"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("write binary: %w", err)
	}
	f.Close()

	if err := os.Rename(tmpPath, binaryPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("replace binary: %w", err)
	}

	// Restart after the result message has been flushed to the WebSocket.
	go func() {
		time.Sleep(500 * time.Millisecond)
		exec.Command("systemctl", "restart", "wirewarp-agent").Run() //nolint:errcheck
	}()

	return "binary updated — restarting", nil
}
