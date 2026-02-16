package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/handlers"
	wsclient "github.com/wirewarp/agent/internal/websocket"
)

func main() {
	mode := flag.String("mode", "", "Agent mode: server or client (required on first run)")
	cfgPath := flag.String("config", config.DefaultPath, "Path to agent config file")
	url := flag.String("url", "", "Control server URL (e.g. https://wirewarp.example.com)")
	token := flag.String("token", "", "Registration token (first run only)")
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
		cfg = &config.Config{
			Mode:             *mode,
			ControlServerURL: *url,
			AgentToken:       *token,
		}
		if err := cfg.Save(*cfgPath); err != nil {
			log.Fatalf("Failed to save initial config: %v", err)
		}
		log.Printf("Config saved to %s", *cfgPath)
	}

	log.Printf("Starting WireWarp agent (mode=%s)", cfg.Mode)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client := wsclient.New(cfg, *cfgPath)

	// Apply last-known config from disk and register real command handlers (task 4.5).
	switch cfg.Mode {
	case "server":
		srv, err := handlers.NewServer(cfg, *cfgPath)
		if err != nil {
			log.Fatalf("Failed to initialise server handlers: %v", err)
		}
		srv.Register(client.Exec())
	case "client":
		cli, err := handlers.NewClient(cfg, *cfgPath)
		if err != nil {
			log.Fatalf("Failed to initialise client handlers: %v", err)
		}
		cli.Register(client.Exec())
	default:
		log.Fatalf("Unknown mode: %s (must be 'server' or 'client')", cfg.Mode)
	}

	client.Run(ctx)
	log.Println("Agent stopped")
}
