package handlers

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nginxCacheConfigPath = "/etc/nginx/conf.d/wirewarp-cache.conf"
	nginxCacheUnit       = "nginx"
	nginxCacheDefaultDir = "/var/cache/wirewarp/nginx"
)

type EdgeCachePurgeParams struct {
	Scope  string `json:"scope"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Prefix string `json:"prefix"`
}

type EdgeCachePurgeResult struct {
	Removed     int
	Key         string
	Unsupported bool
	Reason      string
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
	root := nginxCacheDefaultDir
	if h != nil && h.cfg != nil && h.cfg.EdgeDesired != nil && h.cfg.EdgeDesired.NginxCacheConfig != nil {
		root = nginxString(h.cfg.EdgeDesired.NginxCacheConfig, "cache_path", nginxCacheDefaultDir)
	}
	result, err := purgeNginxCacheFiles(root, p)
	if err != nil {
		return "", err
	}
	if result.Unsupported {
		message := fmt.Sprintf("cache purge unsupported: scope=%s reason=%s", p.Scope, result.Reason)
		h.emitNginxCachePurgeResult(message)
		return message, nil
	}
	keyPart := ""
	if result.Key != "" {
		keyPart = " key=" + result.Key
	}
	message := fmt.Sprintf("cache purge completed: scope=%s removed=%d%s", p.Scope, result.Removed, keyPart)
	h.emitNginxCachePurgeResult(message)
	return message, nil
}

func edgeCachePurgeKey(host, path string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	path = cleanCachePurgePath(path)
	sum := md5.Sum([]byte("http|" + host + "|" + path))
	return hex.EncodeToString(sum[:])
}

func cleanCachePurgePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func purgeNginxCacheFiles(root string, p EdgeCachePurgeParams) (EdgeCachePurgeResult, error) {
	root, err := safeNginxCacheRoot(root)
	if err != nil {
		return EdgeCachePurgeResult{}, err
	}
	if p.Scope == "" {
		p.Scope = "node"
	}
	switch p.Scope {
	case "node":
		removed, err := removeCacheRootChildren(root)
		return EdgeCachePurgeResult{Removed: removed}, err
	case "path":
		if strings.TrimSpace(p.Host) == "" || strings.TrimSpace(p.Path) == "" {
			return EdgeCachePurgeResult{Unsupported: true, Reason: "path purge requires host and path"}, nil
		}
		key := edgeCachePurgeKey(p.Host, p.Path)
		path := nginxCacheFilePath(root, key)
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				return EdgeCachePurgeResult{Key: key, Removed: 0}, nil
			}
			return EdgeCachePurgeResult{}, err
		}
		return EdgeCachePurgeResult{Key: key, Removed: 1}, nil
	case "host", "prefix", "route":
		return EdgeCachePurgeResult{Unsupported: true, Reason: "scope requires cache index support"}, nil
	default:
		return EdgeCachePurgeResult{}, fmt.Errorf("unsupported cache purge scope: %s", p.Scope)
	}
}

func nginxCacheFilePath(root, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if len(key) < 3 {
		return filepath.Join(root, key)
	}
	return filepath.Join(root, key[len(key)-1:], key[len(key)-3:len(key)-1], key)
}

func safeNginxCacheRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = nginxCacheDefaultDir
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	parts := strings.Split(strings.Trim(abs, string(os.PathSeparator)), string(os.PathSeparator))
	if abs == string(os.PathSeparator) || abs == "." || len(parts) < 2 {
		return "", fmt.Errorf("refusing unsafe cache root: %s", abs)
	}
	return abs, nil
}

func removeCacheRootChildren(root string) (int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		removed += countFiles(path)
		if err := os.RemoveAll(path); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func countFiles(root string) int {
	count := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			count++
		}
		return nil
	})
	return count
}

func (h *ServerHandlers) emitNginxCachePurgeResult(message string) {
	if h == nil {
		return
	}
	var cfg map[string]any
	if h.cfg != nil && h.cfg.EdgeDesired != nil {
		cfg = h.cfg.EdgeDesired.NginxCacheConfig
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	payload := collectNginxCache(ctx, cfg)
	payload["last_purge_result"] = message
	h.tryEmitNginxCache(payload)
}

type nginxCacheRoute struct {
	Host                       string
	OriginURL                  string
	EdgeTTLSeconds             int
	CacheStatusHeader          bool
	UpstreamInsecureSkipVerify bool
	BypassPathPrefixes         []string
	ProbePath                  string
}

func (h *ServerHandlers) reconcileNginxCache(ctx context.Context, cfg map[string]any) error {
	if !nginxCacheEnabled(cfg) {
		if _, err := os.Stat(nginxCacheConfigPath); err == nil {
			_, _ = edgeSystemctl(ctx, "disable", "--now", nginxCacheUnit)
		}
		return nil
	}

	rendered, err := renderNginxCacheConfig(cfg)
	if err != nil {
		return err
	}
	cachePath := nginxString(cfg, "cache_path", nginxCacheDefaultDir)
	if err := os.MkdirAll(cachePath, 0755); err != nil {
		return fmt.Errorf("mkdir cache path %s: %w", cachePath, err)
	}
	if resolveNginxBinary() == "" {
		if err := assertDebianFamily(); err != nil {
			return fmt.Errorf("install nginx precheck: %w", err)
		}
		if out, err := runCmd(ctx, "apt-get", "update", "-y"); err != nil {
			return fmt.Errorf("apt-get update for nginx: %w\n%s", err, tail(out, 6))
		}
		if out, err := runCmd(ctx, "apt-get", "install", "-y", "nginx"); err != nil {
			return fmt.Errorf("apt-get install nginx: %w\n%s", err, tail(out, 8))
		}
	}

	changed, err := writeBytesChanged(nginxCacheConfigPath, []byte(rendered), 0644)
	if err != nil {
		return fmt.Errorf("write nginx cache config: %w", err)
	}
	bin := resolveNginxBinary()
	if bin == "" {
		return fmt.Errorf("nginx binary not found after install")
	}
	if out, err := runCmd(ctx, bin, "-t"); err != nil {
		return fmt.Errorf("nginx config test: %w\n%s", err, tail(out, 8))
	}
	if out, err := edgeSystemctl(ctx, "enable", "--now", nginxCacheUnit); err != nil {
		return fmt.Errorf("enable nginx cache service: %w\n%s", err, tail(out, 6))
	}
	if changed {
		if out, err := edgeSystemctl(ctx, "reload", nginxCacheUnit); err != nil {
			if out2, err2 := edgeSystemctl(ctx, "restart", nginxCacheUnit); err2 != nil {
				return fmt.Errorf("reload/restart nginx: %w / %v\n%s\n%s", err, err2, out, out2)
			}
		}
	}
	return nil
}

func nginxCacheEnabled(cfg map[string]any) bool {
	if cfg == nil {
		return false
	}
	if enabled, ok := cfg["enabled"].(bool); ok && !enabled {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(fmt.Sprint(cfg["mode"])))
	return mode != "" && mode != "off" && mode != "headers_only"
}

func renderNginxCacheConfig(cfg map[string]any) (string, error) {
	if !nginxCacheEnabled(cfg) {
		return "# AUTO-GENERATED by wirewarp-agent; cache disabled.\n", nil
	}
	routes, err := nginxCacheRoutes(cfg["routes"])
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("nginx cache enabled but no cache routes were rendered")
	}

	cachePath := nginxString(cfg, "cache_path", nginxCacheDefaultDir)
	keysZone := nginxString(cfg, "keys_zone", "wirewarp_cache:64m")
	maxSize := nginxString(cfg, "max_size", "1g")
	inactive := nginxString(cfg, "inactive", "60m")
	listen := nginxString(cfg, "listen", "127.0.0.1:18080")
	if !safeNginxToken(cachePath) || !safeNginxToken(keysZone) || !safeNginxToken(maxSize) || !safeNginxToken(inactive) || !safeNginxListen(listen) {
		return "", fmt.Errorf("unsafe nginx cache scalar in desired config")
	}

	var b strings.Builder
	b.WriteString("# AUTO-GENERATED by wirewarp-agent; do not edit by hand.\n")
	fmt.Fprintf(&b, "proxy_cache_path %s levels=1:2 keys_zone=%s max_size=%s inactive=%s use_temp_path=off;\n\n", cachePath, keysZone, maxSize, inactive)
	b.WriteString("map $request_method $wirewarp_method_cache_bypass {\n")
	b.WriteString("    default 1;\n")
	b.WriteString("    GET 0;\n")
	b.WriteString("    HEAD 0;\n")
	b.WriteString("}\n\n")

	for _, route := range routes {
		fmt.Fprintf(&b, "server {\n")
		fmt.Fprintf(&b, "    listen %s;\n", listen)
		fmt.Fprintf(&b, "    server_name %s;\n", route.Host)
		b.WriteString("    proxy_cache wirewarp_cache;\n")
		b.WriteString("    proxy_cache_key \"$scheme|$host|$request_uri\";\n")
		fmt.Fprintf(&b, "    proxy_cache_valid 200 301 302 %ds;\n", route.EdgeTTLSeconds)
		b.WriteString("    proxy_cache_valid 404 60s;\n")
		b.WriteString("    proxy_cache_bypass $wirewarp_method_cache_bypass $http_authorization $cookie_session;\n")
		b.WriteString("    proxy_no_cache $wirewarp_method_cache_bypass $http_authorization $cookie_session;\n")
		for _, prefix := range route.BypassPathPrefixes {
			fmt.Fprintf(&b, "    location %s {\n", prefix)
			if route.CacheStatusHeader {
				b.WriteString("        add_header X-WireWarp-Cache-Status $upstream_cache_status always;\n")
			}
			b.WriteString("        proxy_no_cache 1;\n")
			b.WriteString("        proxy_cache_bypass 1;\n")
			writeNginxProxyCommon(&b, route)
			b.WriteString("    }\n")
		}
		b.WriteString("    location / {\n")
		if route.CacheStatusHeader {
			b.WriteString("        add_header X-WireWarp-Cache-Status $upstream_cache_status always;\n")
		}
		writeNginxProxyCommon(&b, route)
		b.WriteString("    }\n")
		b.WriteString("}\n\n")
	}
	return b.String(), nil
}

func writeNginxProxyCommon(b *strings.Builder, route nginxCacheRoute) {
	b.WriteString("        proxy_http_version 1.1;\n")
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	if route.UpstreamInsecureSkipVerify {
		b.WriteString("        proxy_ssl_verify off;\n")
	}
	fmt.Fprintf(b, "        proxy_pass %s;\n", route.OriginURL)
}

func nginxCacheRoutes(raw any) ([]nginxCacheRoute, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, nil
	}
	routes := make([]nginxCacheRoute, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		host, ok := cleanNginxHost(m["host"])
		if !ok {
			continue
		}
		origin, ok := cleanNginxURL(m["origin_url"])
		if !ok {
			return nil, fmt.Errorf("invalid origin_url for cache host %s", host)
		}
		ttl := intFromAny(m["edge_ttl_seconds"], 600)
		if ttl <= 0 {
			ttl = 600
		}
		routes = append(routes, nginxCacheRoute{
			Host:                       host,
			OriginURL:                  origin,
			EdgeTTLSeconds:             ttl,
			CacheStatusHeader:          boolFromAny(m["cache_status_header"], true),
			UpstreamInsecureSkipVerify: boolFromAny(m["upstream_insecure_skip_verify"], false),
			BypassPathPrefixes:         cleanNginxPathPrefixes(m["bypass_path_prefixes"]),
			ProbePath:                  cleanNginxPath(fmt.Sprint(m["probe_path"])),
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Host < routes[j].Host })
	return routes, nil
}

func cleanNginxHost(raw any) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(fmt.Sprint(raw)))
	if host == "" {
		return "", false
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return "", false
	}
	return host, true
}

func cleanNginxURL(raw any) (string, bool) {
	value := strings.TrimSpace(fmt.Sprint(raw))
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	if strings.ContainsAny(value, " \t\r\n;{}") {
		return "", false
	}
	return value, true
}

func cleanNginxPathPrefixes(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return []string{"/api", "/auth", "/login", "/admin", "/session"}
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		path := cleanNginxPath(fmt.Sprint(item))
		if path != "" && path != "/" {
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		return []string{"/api", "/auth", "/login", "/admin", "/session"}
	}
	return out
}

func cleanNginxPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "<nil>" {
		return "/"
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	if strings.ContainsAny(value, " \t\r\n;{}") {
		return "/"
	}
	return value
}

func nginxString(cfg map[string]any, key, fallback string) string {
	value := strings.TrimSpace(fmt.Sprint(cfg[key]))
	if value == "" || value == "<nil>" {
		return fallback
	}
	return value
}

func safeNginxToken(value string) bool {
	return value != "" && !strings.ContainsAny(value, " \t\r\n;{}")
}

func safeNginxListen(value string) bool {
	if strings.ContainsAny(value, " \t\r\n;{}") {
		return false
	}
	host, port, ok := strings.Cut(value, ":")
	if !ok || host == "" || port == "" {
		return false
	}
	_, err := strconv.Atoi(port)
	return err == nil
}

func boolFromAny(value any, fallback bool) bool {
	if value == nil {
		return fallback
	}
	if b, ok := value.(bool); ok {
		return b
	}
	switch strings.ToLower(strings.TrimSpace(fmt.Sprint(value))) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return fallback
	}
}

func intFromAny(value any, fallback int) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, err := v.Int64()
		if err == nil {
			return int(i)
		}
	}
	i, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(value)))
	if err != nil {
		return fallback
	}
	return i
}

func resolveNginxBinary() string {
	return resolveBin("nginx", "/usr/sbin/nginx", "/usr/bin/nginx", "/sbin/nginx")
}

func parseNginxVersion(out []byte) string {
	text := string(out)
	if idx := strings.Index(text, "nginx/"); idx >= 0 {
		rest := text[idx+len("nginx/"):]
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			return strings.TrimSpace(fields[0])
		}
	}
	return ""
}

func collectNginxCache(ctx context.Context, cfg map[string]any) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)
	enabled := nginxCacheEnabled(cfg)
	cachePath := nginxString(cfg, "cache_path", nginxCacheDefaultDir)
	payload := map[string]any{
		"backend":    "nginx_proxy_cache",
		"installed":  false,
		"running":    false,
		"phase":      "pending",
		"cache_path": cachePath,
		"timestamp":  now,
	}
	if !enabled {
		payload["phase"] = "disabled"
		return payload
	}
	bin := resolveNginxBinary()
	if bin == "" {
		return payload
	}
	payload["installed"] = true
	if out, err := execNginxVersion(ctx, bin); err == nil {
		payload["version"] = parseNginxVersion(out)
	}
	if rendered, err := renderNginxCacheConfig(cfg); err == nil {
		sum := sha256.Sum256([]byte(rendered))
		payload["last_config_hash"] = hex.EncodeToString(sum[:])
	}
	payload["current_size_bytes"] = dirSize(cachePath)
	payload["max_size_bytes"] = parseNginxSize(nginxString(cfg, "max_size", "1g"))
	payload["keys_zone_size"] = keysZoneSize(nginxString(cfg, "keys_zone", "wirewarp_cache:64m"))

	active, statusMsg := nginxServiceActive(ctx)
	payload["running"] = active
	if !active {
		payload["phase"] = "degraded"
		if statusMsg != "" {
			payload["error"] = statusMsg
			payload["last_error"] = statusMsg
		}
		return payload
	}

	testStatus, testErr := runNginxCacheHealthProbe(ctx, cfg)
	payload["last_test_status"] = testStatus
	if testErr != nil {
		payload["phase"] = "degraded"
		payload["error"] = testErr.Error()
		payload["last_error"] = testErr.Error()
		return payload
	}
	payload["phase"] = "healthy"
	return payload
}

func execNginxVersion(ctx context.Context, bin string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return execCommand(cctx, bin, "-v")
}

var execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func nginxServiceActive(ctx context.Context) (bool, string) {
	out, _ := edgeSystemctl(ctx, "is-active", nginxCacheUnit)
	state := strings.TrimSpace(string(out))
	if state == "active" {
		return true, ""
	}
	status, _ := edgeSystemctl(ctx, "status", "--no-pager", "-n", "12", nginxCacheUnit)
	msg := "nginx service " + state
	if state == "" {
		msg = "nginx service state unknown"
	}
	if t := strings.TrimSpace(tail(status, 12)); t != "" {
		msg += ":\n" + t
	}
	return false, msg
}

func runNginxCacheHealthProbe(ctx context.Context, cfg map[string]any) (string, error) {
	routes, err := nginxCacheRoutes(cfg["routes"])
	if err != nil {
		return "invalid_config", err
	}
	if len(routes) == 0 {
		return "no_routes", fmt.Errorf("no cache routes to probe")
	}
	listen := nginxString(cfg, "listen", "127.0.0.1:18080")
	route := routes[0]
	path := route.ProbePath
	if path == "" {
		path = "/"
	}
	endpoint := "http://" + listen + path
	first, err := fetchNginxCacheStatus(ctx, endpoint, route.Host)
	if err != nil {
		return "probe_failed", err
	}
	if first == "BYPASS" {
		return "bypass", nil
	}
	second, err := fetchNginxCacheStatus(ctx, endpoint, route.Host)
	if err != nil {
		return "probe_failed", err
	}
	if first == "MISS" && second == "HIT" {
		return "miss_hit", nil
	}
	if second == "BYPASS" {
		return "bypass", nil
	}
	return strings.ToLower(first + "_" + second), fmt.Errorf("cache probe expected MISS/HIT or BYPASS, got %s then %s", first, second)
}

func fetchNginxCacheStatus(ctx context.Context, endpoint, host string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Host = host
	client := http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	status := strings.ToUpper(strings.TrimSpace(resp.Header.Get("X-WireWarp-Cache-Status")))
	if status == "" {
		status = strings.ToUpper(strings.TrimSpace(resp.Header.Get("X-Cache-Status")))
	}
	if status == "" {
		return "", fmt.Errorf("cache probe response missing cache-status header")
	}
	return status, nil
}

func (h *ServerHandlers) pollAndEmitNginxCache(ctx context.Context, retry bool) {
	var cfg map[string]any
	if h.cfg.EdgeDesired != nil {
		cfg = h.cfg.EdgeDesired.NginxCacheConfig
	}
	payload := collectNginxCache(ctx, cfg)
	if h.tryEmitNginxCache(payload) {
		return
	}
	if retry {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			if h.tryEmitNginxCache(payload) {
				return
			}
		}
	}
}

func (h *ServerHandlers) tryEmitNginxCache(payload map[string]any) bool {
	p := h.emit.Load()
	if p == nil {
		return false
	}
	fn := *p
	if fn == nil {
		return false
	}
	return fn("edge_cache_status", payload) == nil
}

func dirSize(root string) int64 {
	var size int64
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			size += info.Size()
		}
		return nil
	})
	return size
}

func parseNginxSize(value string) int64 {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return 0
	}
	mult := int64(1)
	switch value[len(value)-1] {
	case 'k':
		mult = 1024
		value = value[:len(value)-1]
	case 'm':
		mult = 1024 * 1024
		value = value[:len(value)-1]
	case 'g':
		mult = 1024 * 1024 * 1024
		value = value[:len(value)-1]
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return n * mult
}

func keysZoneSize(value string) string {
	_, size, ok := strings.Cut(value, ":")
	if !ok {
		return ""
	}
	return size
}
