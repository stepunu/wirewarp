package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteYAMLReplacesExistingFileAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wirewarp.yml")
	if err := os.WriteFile(path, []byte("previous: true\n"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	before := inodeOf(t, path)

	if err := writeYAML(path, map[string]any{"http": map[string]any{"routers": map[string]any{}}}); err != nil {
		t.Fatalf("writeYAML: %v", err)
	}

	after := inodeOf(t, path)
	if after == before {
		t.Fatalf("writeYAML should replace the file inode so Traefik never reads a truncated watched file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.Contains(string(data), "http:") || strings.Contains(string(data), "previous") {
		t.Fatalf("unexpected YAML output:\n%s", string(data))
	}
}

func TestWriteYAMLSkipsUnchangedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wirewarp.yml")
	cfg := map[string]any{"http": map[string]any{"routers": map[string]any{}}}
	if err := writeYAML(path, cfg); err != nil {
		t.Fatalf("initial writeYAML: %v", err)
	}
	before := inodeOf(t, path)

	if err := writeYAML(path, cfg); err != nil {
		t.Fatalf("second writeYAML: %v", err)
	}

	after := inodeOf(t, path)
	if after != before {
		t.Fatalf("writeYAML should leave unchanged files alone; inode changed from %d to %d", before, after)
	}
}

func TestAtomicTempDirIsOutsideWatchedTargetDir(t *testing.T) {
	path := "/etc/traefik/dynamic/wirewarp.yml"
	if got := atomicTempDir(path); got != "/etc/traefik" {
		t.Fatalf("atomic temp dir: want /etc/traefik, got %s", got)
	}
}

func TestParseTraefikRateLimitAccessEvents(t *testing.T) {
	raw := strings.Join([]string{
		`84.113.55.126 - - [30/May/2026:17:42:53 +0000] "GET /web/manifest.json HTTP/2.0" 429 17 "-" "-" 111 "media-ww-step1-ro@file" "-" 0ms`,
		`84.113.55.126 - - [30/May/2026:17:42:54 +0000] "GET /web/ HTTP/2.0" 200 1408 "-" "-" 112 "media-ww-step1-ro@file" "http://192.168.20.151:8096" 30ms`,
		`-- cursor: s=cursor-after-lines`,
	}, "\n")

	events, cursor := parseTraefikAccessSecurityEvents(raw)

	if cursor != "s=cursor-after-lines" {
		t.Fatalf("cursor: got %q", cursor)
	}
	if len(events) != 1 {
		t.Fatalf("events: got %d, want 1: %#v", len(events), events)
	}
	evt := events[0]
	if evt["source"] != "traefik" || evt["kind"] != "rate_limit" || evt["action"] != "rate_limit" {
		t.Fatalf("unexpected event identity: %#v", evt)
	}
	if evt["ip"] != "84.113.55.126" || evt["value"] != "media-ww-step1-ro@file" {
		t.Fatalf("unexpected event target: %#v", evt)
	}
	rawPayload, ok := evt["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw payload type: %#v", evt["raw"])
	}
	if rawPayload["status"] != 429 || rawPayload["path"] != "/web/manifest.json" {
		t.Fatalf("unexpected raw payload: %#v", rawPayload)
	}
}

func TestShouldAdvanceTraefikCursorWaitsForSuccessfulEventEmit(t *testing.T) {
	if !shouldAdvanceTraefikEventsCursor(0, false) {
		t.Fatal("empty reads should advance the cursor")
	}
	if shouldAdvanceTraefikEventsCursor(1, false) {
		t.Fatal("event reads must not advance the cursor when emit failed")
	}
	if !shouldAdvanceTraefikEventsCursor(1, true) {
		t.Fatal("event reads should advance the cursor after a successful emit")
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s did not return syscall.Stat_t", path)
	}
	return stat.Ino
}
