package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type EdgeCachePurgeParams struct {
	Scope  string `json:"scope"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Prefix string `json:"prefix"`
}

func (h *ServerHandlers) handleEdgeCachePurge(raw json.RawMessage) (string, error) {
	var p EdgeCachePurgeParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", fmt.Errorf("parse params: %w", err)
		}
	}
	if p.Scope == "" {
		p.Scope = "node"
	}
	switch p.Scope {
	case "node", "route", "host", "path", "prefix":
	default:
		return "", fmt.Errorf("unsupported cache purge scope: %s", p.Scope)
	}
	key := edgeCachePurgeKey(p.Host, p.Path)
	if p.Prefix != "" {
		key = edgeCachePurgeKey(p.Host, strings.TrimRight(p.Prefix, "/")+"/")
	}
	return fmt.Sprintf("cache purge accepted: scope=%s key=%s", p.Scope, key), nil
}

func edgeCachePurgeKey(host, path string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(host)) + "\n" + strings.TrimSpace(path)))
	return hex.EncodeToString(sum[:])
}
