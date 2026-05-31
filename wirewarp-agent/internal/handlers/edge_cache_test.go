package handlers

import (
	"strings"
	"testing"
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
