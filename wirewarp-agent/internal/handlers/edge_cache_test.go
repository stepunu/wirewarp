package handlers

import "testing"

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
