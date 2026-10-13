package handlers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccessLogJournalRejectsUnreadableCursor(t *testing.T) {
	dir := t.TempDir()
	if _, err := readTraefikAccessJournalFrom(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "read traefik access cursor") {
		t.Fatalf("expected cursor read failure before journal access, got %v", err)
	}
	missing := filepath.Join(dir, "cursor")
	if value, err := readTraefikEventsCursor(missing); err != nil || value != "" {
		t.Fatalf("missing cursor: value=%q err=%v", value, err)
	}
	if err := os.WriteFile(missing, []byte(" s=existing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := readTraefikEventsCursor(missing); err != nil || value != "s=existing" {
		t.Fatalf("existing cursor: value=%q err=%v", value, err)
	}
}

func TestAccessLogBatchDeliveryPreservesCursorOnFailure(t *testing.T) {
	raw := `{"RequestHost":"qa.example.test","RequestPath":"/","RequestMethod":"GET","DownstreamStatus":404}` + "\n-- cursor: s=qa"
	for _, failure := range []string{"", "delivery", "cursor"} {
		t.Run(failure, func(t *testing.T) {
			h := &EdgeHandlers{}
			delivered, written := false, false
			h.SetEmit(func(kind string, payload map[string]any) error {
				if kind != "edge_access_events" {
					t.Fatalf("unexpected kind %s", kind)
				}
				delivered = true
				if failure == "delivery" {
					return errors.New("websocket unavailable")
				}
				return nil
			})
			err := h.emitTraefikAccessBatch(raw, func(cursor string) error {
				written = true
				if cursor != "s=qa" {
					t.Fatalf("unexpected cursor %s", cursor)
				}
				if failure == "cursor" {
					return os.ErrPermission
				}
				return nil
			})
			if !delivered || written != (failure != "delivery") || (err != nil) != (failure != "") {
				t.Fatalf("delivered=%v written=%v err=%v", delivered, written, err)
			}
		})
	}
}

func TestAccessLogCollectorReportsActualCycle(t *testing.T) {
	for _, tc := range []struct {
		name, config, phase                   string
		disabled, service, running, collected bool
		readErr, collectErr                   error
	}{
		{name: "enabled journal cycle", config: "accessLog: {format: json}", service: true, phase: "healthy", running: true, collected: true},
		{name: "disabled config", config: "log: {level: INFO}", service: true, phase: "disabled"},
		{name: "disabled edge", config: "accessLog: {format: json}", disabled: true, service: true, phase: "disabled"},
		{name: "missing config", readErr: os.ErrNotExist, service: true, phase: "disabled"},
		{name: "unreadable config", readErr: os.ErrPermission, service: true, phase: "degraded"},
		{name: "malformed config", config: "accessLog: [", service: true, phase: "degraded"},
		{name: "file output unsupported", config: "accessLog: {format: json, filePath: /tmp/access.log}", service: true, phase: "degraded"},
		{name: "nonJSON output", config: "accessLog: {format: common}", service: true, phase: "degraded"},
		{name: "Traefik stopped", config: "accessLog: {format: json}", phase: "degraded"},
		{name: "journal unavailable", config: "accessLog: {format: json}", service: true, collectErr: errors.New("journald permission denied"), phase: "degraded", collected: true},
		{name: "delivery unavailable", config: "accessLog: {format: json}", service: true, collectErr: errors.New("delivery failed; cursor retained"), phase: "degraded", collected: true},
		{name: "cursor unwritable", config: "accessLog: {format: json}", service: true, collectErr: errors.New("cursor permission denied"), phase: "degraded", collected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			collected := false
			status := collectAccessLogStatus(tc.disabled, tc.service, func() ([]byte, error) { return []byte(tc.config), tc.readErr }, func() error { collected = true; return tc.collectErr })
			if status["phase"] != tc.phase || status["running"] != tc.running || collected != tc.collected {
				t.Fatalf("status=%v collected=%v", status, collected)
			}
			if tc.phase == "degraded" && status["error"] == nil {
				t.Fatal("collector error was hidden")
			}
		})
	}
}
