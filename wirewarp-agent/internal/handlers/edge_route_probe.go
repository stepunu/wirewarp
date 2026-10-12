package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/wirewarp/agent/internal/config"
)

type edgeRouteTestParams struct {
	MigrationID     string `json:"migration_id"`
	RouteID         string `json:"route_id"`
	ConfigVersionID string `json:"config_version_id"`
	DesiredHash     string `json:"desired_hash"`
	Domain          string `json:"domain"`
}

type edgeRouteTestResult struct {
	edgeRouteTestParams
	TLSVerified           bool   `json:"tls_verified"`
	UpstreamReachable     bool   `json:"upstream_reachable"`
	RouteResponseReceived bool   `json:"route_response_received"`
	Status                string `json:"status"`
}

var edgeProbeUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var edgeProbeHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var edgeProbeDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

func (h *EdgeHandlers) handleEdgeRouteTest(raw json.RawMessage) (string, error) {
	var p edgeRouteTestParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse route test: %w", err)
	}
	saved := h.cfg.Snapshot()
	if saved.EdgeDisabled || saved.EdgeRuntimePending {
		return "", fmt.Errorf("edge runtime has not applied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	result, err := probeSavedEdgeRoute(ctx, saved.EdgeDesired, p, nil)
	output, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return "", marshalErr
	}
	return string(output), err
}

func probeSavedEdgeRoute(ctx context.Context, desired *config.EdgeDesiredState, p edgeRouteTestParams, roots *x509.CertPool) (edgeRouteTestResult, error) {
	result := edgeRouteTestResult{edgeRouteTestParams: p, Status: "error"}
	if !edgeProbeUUID.MatchString(p.MigrationID) || !edgeProbeUUID.MatchString(p.RouteID) || !edgeProbeUUID.MatchString(p.ConfigVersionID) || !edgeProbeHash.MatchString(p.DesiredHash) || !edgeProbeDomain.MatchString(p.Domain) || strings.Contains(p.Domain, "..") {
		return result, fmt.Errorf("invalid route probe identity")
	}
	if desired == nil || desired.DesiredHash != p.DesiredHash || desired.ConfigVersionID != p.ConfigVersionID {
		return result, fmt.Errorf("route probe does not match applied desired state")
	}
	dynamic, _ := desired.TraefikDynamicConfig["http"].(map[string]any)
	routers, _ := dynamic["routers"].(map[string]any)
	services, _ := dynamic["services"].(map[string]any)
	var selected map[string]any
	matched := 0
	for _, value := range routers {
		router, _ := value.(map[string]any)
		if router["rule"] != "Host(`"+p.Domain+"`)" {
			continue
		}
		if router["tls"] == nil {
			continue
		}
		entries := edgeProbeStrings(router["entryPoints"])
		for _, name := range entries {
			if name == "websecure" {
				selected = router
				matched++
			}
		}
	}
	if selected == nil || matched != 1 {
		return result, fmt.Errorf("no applied public TLS router for the requested hostname")
	}
	entries, _ := desired.TraefikStaticConfig["entryPoints"].(map[string]any)
	entry, _ := entries["websecure"].(map[string]any)
	address, _ := entry["address"].(string)
	address = strings.TrimSuffix(address, "/tcp")
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || net.ParseIP(host).IsUnspecified() {
		return result, fmt.Errorf("route probe requires an explicit local TLS listener")
	}
	serviceName, _ := selected["service"].(string)
	service, _ := services[strings.TrimSuffix(serviceName, "@file")].(map[string]any)
	lb, _ := service["loadBalancer"].(map[string]any)
	upstreams := edgeProbeObjects(lb["servers"])
	skipVerify := false
	if transportName, _ := lb["serversTransport"].(string); transportName != "" {
		transports, _ := dynamic["serversTransports"].(map[string]any)
		transport, _ := transports[strings.TrimSuffix(transportName, "@file")].(map[string]any)
		skipVerify, _ = transport["insecureSkipVerify"].(bool)
	}
	for _, cached := range edgeProbeObjects(desired.NginxCacheConfig["routes"]) {
		if cached["host"] == p.Domain {
			upstreams = []map[string]any{{"url": cached["origin_url"]}}
			skipVerify, _ = cached["upstream_insecure_skip_verify"].(bool)
		}
	}
	if len(upstreams) == 0 {
		return result, fmt.Errorf("route has no saved upstreams")
	}
	for _, upstream := range upstreams {
		origin, _ := upstream["url"].(string)
		parsed, parseErr := url.Parse(origin)
		if parseErr != nil || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "h2c") || parsed.Hostname() == "" {
			return result, fmt.Errorf("route has an unsupported saved upstream")
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, InsecureSkipVerify: skipVerify}}
		if parsed.Scheme == "h2c" {
			parsed.Scheme = "http"
			origin = parsed.String()
			transport.Protocols = new(http.Protocols)
			transport.Protocols.SetUnencryptedHTTP2(true)
		}
		status, requestErr := edgeProbeHTTP(ctx, origin, transport)
		if requestErr != nil || status >= 500 {
			return result, fmt.Errorf("saved upstream probe failed")
		}
	}
	result.UpstreamReachable = true
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: p.Domain, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		},
	}
	status, err := edgeProbeHTTP(ctx, "https://"+net.JoinHostPort(p.Domain, port)+"/", transport)
	if err != nil {
		return result, fmt.Errorf("gateway TLS route probe failed: %w", err)
	}
	result.TLSVerified = true
	if status >= 500 || status == 404 {
		return result, fmt.Errorf("gateway route returned an unverified response status %d", status)
	}
	result.RouteResponseReceived = true
	result.Status = "verified"
	return result, nil
}

func edgeProbeHTTP(ctx context.Context, address string, transport http.RoundTripper) (int, error) {
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, nil
}

func edgeProbeStrings(value any) []string {
	switch items := value.(type) {
	case []string:
		return items
	case []any:
		result := []string{}
		for _, item := range items {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	}
	return nil
}

func edgeProbeObjects(value any) []map[string]any {
	result := []map[string]any{}
	switch items := value.(type) {
	case []map[string]any:
		return items
	case []any:
		for _, item := range items {
			if object, ok := item.(map[string]any); ok {
				result = append(result, object)
			}
		}
	}
	return result
}
