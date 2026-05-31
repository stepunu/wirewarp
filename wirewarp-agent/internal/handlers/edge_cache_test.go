package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func TestEdgeCachePurgeKeyIsDeterministic(t *testing.T) {
	a := edgeCachePurgeKey("app.example.com", "/assets/app.css")
	b := edgeCachePurgeKey("app.example.com", "/assets/app.css")
	c := edgeCachePurgeKey("app.example.com", "/assets/other.css")

	if a == "" || a != b {
		t.Fatalf("cache key should be stable: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("different paths should produce different keys")
	}
}

func TestEdgeCachePurgePathDeletesDeterministicFile(t *testing.T) {
	root := t.TempDir()
	key := edgeCachePurgeKey("app.example.com", "/assets/app.css")
	cacheFile := nginxCacheFilePath(root, key)
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0755); err != nil {
		t.Fatalf("mkdir cache path: %v", err)
	}
	if err := os.WriteFile(cacheFile, []byte("cached"), 0644); err != nil {
		t.Fatalf("write cache file: %v", err)
	}

	result, err := purgeNginxCacheFiles(root, EdgeCachePurgeParams{
		Scope: "path",
		Host:  "app.example.com",
		Path:  "/assets/app.css",
	})
	if err != nil {
		t.Fatalf("purge path: %v", err)
	}
	if result.Removed != 1 {
		t.Fatalf("removed count: want 1, got %d", result.Removed)
	}
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Fatalf("cache file should be deleted, stat err=%v", err)
	}
}

func TestEdgeCachePurgeNodeClearsManagedCacheRoot(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a/aa/one", "b/bb/two"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("cached"), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	result, err := purgeNginxCacheFiles(root, EdgeCachePurgeParams{Scope: "node"})
	if err != nil {
		t.Fatalf("purge node: %v", err)
	}
	if result.Removed != 2 {
		t.Fatalf("removed count: want 2, got %d", result.Removed)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read cache root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("cache root should be empty, got %d entries", len(entries))
	}
}

func TestRenderNginxCacheConfigIncludesProxyCacheDirectives(t *testing.T) {
	rendered, err := renderNginxCacheConfig(map[string]any{
		"enabled":             true,
		"mode":                "proxy_cache",
		"listen":              "127.0.0.1:18080",
		"cache_path":          "/var/cache/wirewarp/nginx",
		"keys_zone":           "wirewarp_cache:64m",
		"max_size":            "1g",
		"inactive":            "60m",
		"edge_ttl_seconds":    600,
		"cache_status_header": true,
		"routes": []any{
			map[string]any{
				"host":       "app.example.com",
				"origin_url": "http://10.21.0.2:8080",
			},
		},
	})
	if err != nil {
		t.Fatalf("render nginx cache config: %v", err)
	}
	for _, want := range []string{
		"proxy_cache_path /var/cache/wirewarp/nginx",
		"keys_zone=wirewarp_cache:64m",
		"listen 127.0.0.1:18080;",
		"server_name app.example.com;",
		"proxy_cache_key",
		"proxy_cache_valid 200 301 302 600s;",
		"add_header X-WireWarp-Cache-Status $upstream_cache_status always;",
		"proxy_pass http://10.21.0.2:8080;",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, rendered)
		}
	}
}

func TestParseNginxVersion(t *testing.T) {
	if got := parseNginxVersion([]byte("nginx version: nginx/1.24.0\n")); got != "1.24.0" {
		t.Fatalf("version: want 1.24.0, got %q", got)
	}
}

func TestResolveOptionalBinReturnsEmptyWhenMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-nginx")
	if got := resolveOptionalBin("wirewarp-definitely-missing-nginx", missing); got != "" {
		t.Fatalf("missing optional binary should return empty, got %q", got)
	}
}

func TestResolveOptionalBinUsesExistingCandidate(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "nginx")
	if err := os.WriteFile(candidate, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write candidate: %v", err)
	}
	if got := resolveOptionalBin("wirewarp-definitely-missing-nginx", candidate); got != candidate {
		t.Fatalf("candidate path: want %q, got %q", candidate, got)
	}
}

func TestHandleEdgeCacheTestProvesMissThenHitAndEmitsStatus(t *testing.T) {
	var calls int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("X-WireWarp-Cache-Status", "MISS")
		} else {
			w.Header().Set("X-WireWarp-Cache-Status", "HIT")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)

	cfg := map[string]any{
		"enabled": true,
		"mode":    "proxy_cache",
		"listen":  strings.TrimPrefix(origin.URL, "http://"),
		"routes": []any{
			map[string]any{
				"host":       "app.example.com",
				"origin_url": "http://10.21.0.2:8080",
			},
		},
	}
	h := &ServerHandlers{
		cfg: &config.Config{EdgeDesired: &config.EdgeDesiredState{NginxCacheConfig: cfg}},
	}
	var emitted []map[string]any
	emit := func(eventType string, payload map[string]any) error {
		if eventType != "edge_cache_status" {
			t.Fatalf("event type: want edge_cache_status, got %s", eventType)
		}
		emitted = append(emitted, payload)
		return nil
	}
	h.SetEmit(emit)

	out, err := h.handleEdgeCacheTest(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("handle cache test: %v", err)
	}
	if !strings.Contains(out, "miss_hit") {
		t.Fatalf("output should include proof status, got %q", out)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected one cache status emit, got %d", len(emitted))
	}
	if emitted[0]["phase"] != "healthy" || emitted[0]["last_test_status"] != "miss_hit" {
		t.Fatalf("unexpected emitted payload: %#v", emitted[0])
	}
}

func TestHandleEdgeCacheTestRequiresDesiredCacheConfig(t *testing.T) {
	h := &ServerHandlers{cfg: &config.Config{}}
	if _, err := h.handleEdgeCacheTest(json.RawMessage(`{}`)); err == nil {
		t.Fatalf("expected missing desired cache config to fail")
	}
}
