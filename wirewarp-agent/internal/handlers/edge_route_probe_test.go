package handlers

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
)

func routeProbeFixture(t *testing.T, originStatus int) (*config.EdgeDesiredState, edgeRouteTestParams, *x509.CertPool) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(originStatus) }))
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:"+strings.Split(r.Host, ":")[1] {
			t.Errorf("wrong Host: %s", r.Host)
		}
		if r.TLS.ServerName != "example.com" {
			t.Errorf("wrong SNI: %s", r.TLS.ServerName)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(origin.Close)
	t.Cleanup(front.Close)
	id := "12345678-1234-1234-1234-123456789abc"
	p := edgeRouteTestParams{MigrationID: id, RouteID: id, ConfigVersionID: id, DesiredHash: strings.Repeat("a", 64), Domain: "example.com"}
	desired := &config.EdgeDesiredState{DesiredHash: p.DesiredHash, ConfigVersionID: p.ConfigVersionID,
		TraefikStaticConfig: map[string]any{"entryPoints": map[string]any{"websecure": map[string]any{"address": front.Listener.Addr().String()}}},
		TraefikDynamicConfig: map[string]any{"http": map[string]any{
			"routers":  map[string]any{"app": map[string]any{"rule": "Host(`example.com`)", "entryPoints": []any{"websecure"}, "tls": map[string]any{"certResolver": "letsencrypt"}, "service": "app"}},
			"services": map[string]any{"app": map[string]any{"loadBalancer": map[string]any{"servers": []any{map[string]any{"url": origin.URL}}}}},
		}},
	}
	roots := x509.NewCertPool()
	roots.AddCert(front.Certificate())
	return desired, p, roots
}

func TestEdgeRouteProbeVerifiesActualTLSAndSavedOrigin(t *testing.T) {
	desired, p, roots := routeProbeFixture(t, 200)
	result, err := probeSavedEdgeRoute(context.Background(), desired, p, roots)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "verified" || !result.TLSVerified || !result.UpstreamReachable || !result.RouteResponseReceived || result.edgeRouteTestParams != p {
		t.Fatalf("invalid result: %#v", result)
	}
}

func TestEdgeRouteProbeRejectsStaleAppliedState(t *testing.T) {
	desired, p, roots := routeProbeFixture(t, 200)
	p.DesiredHash = strings.Repeat("b", 64)
	result, err := probeSavedEdgeRoute(context.Background(), desired, p, roots)
	if err == nil || result.UpstreamReachable || result.TLSVerified {
		t.Fatalf("stale state passed: %#v %v", result, err)
	}
}

func TestEdgeRouteProbeDoesNotTrustDefaultCertificate(t *testing.T) {
	desired, p, _ := routeProbeFixture(t, 200)
	result, err := probeSavedEdgeRoute(context.Background(), desired, p, x509.NewCertPool())
	if err == nil || result.TLSVerified || result.Status != "error" || !result.UpstreamReachable {
		t.Fatalf("untrusted certificate passed: %#v %v", result, err)
	}
}

func TestEdgeRouteProbeRequiresSavedUpstreamHealth(t *testing.T) {
	desired, p, roots := routeProbeFixture(t, 503)
	result, err := probeSavedEdgeRoute(context.Background(), desired, p, roots)
	if err == nil || result.UpstreamReachable || result.TLSVerified {
		t.Fatalf("unhealthy origin passed: %#v %v", result, err)
	}
}

func TestEdgeRouteProbeRejectsWildcardListenerAndAmbiguousRouter(t *testing.T) {
	for _, mode := range []string{"wildcard", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			desired, p, roots := routeProbeFixture(t, 200)
			if mode == "wildcard" {
				desired.TraefikStaticConfig["entryPoints"].(map[string]any)["websecure"].(map[string]any)["address"] = ":443"
			} else {
				routers := desired.TraefikDynamicConfig["http"].(map[string]any)["routers"].(map[string]any)
				routers["other"] = routers["app"]
			}
			result, err := probeSavedEdgeRoute(context.Background(), desired, p, roots)
			if err == nil || result.UpstreamReachable {
				t.Fatalf("unsafe listener/router passed: %#v %v", result, err)
			}
		})
	}
}

func TestEdgeRouteProbeBypassesCacheForOriginHealth(t *testing.T) {
	desired, p, roots := routeProbeFixture(t, 200)
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }))
	defer unhealthy.Close()
	desired.NginxCacheConfig = map[string]any{"routes": []any{map[string]any{"host": p.Domain, "origin_url": unhealthy.URL}}}
	result, err := probeSavedEdgeRoute(context.Background(), desired, p, roots)
	if err == nil || result.UpstreamReachable {
		t.Fatalf("cache hid origin failure: %#v %v", result, err)
	}
}

func TestEdgeRouteProbeSupportsSavedDNSAndH2COrigins(t *testing.T) {
	desired, p, roots := routeProbeFixture(t, 200)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			w.WriteHeader(505)
			return
		}
		w.WriteHeader(200)
	}))
	origin.Config.Protocols = new(http.Protocols)
	origin.Config.Protocols.SetHTTP1(true)
	origin.Config.Protocols.SetUnencryptedHTTP2(true)
	origin.Start()
	defer origin.Close()
	address := strings.Replace(origin.URL, "http://127.0.0.1", "h2c://localhost", 1)
	services := desired.TraefikDynamicConfig["http"].(map[string]any)["services"].(map[string]any)
	services["app"].(map[string]any)["loadBalancer"].(map[string]any)["servers"] = []any{map[string]any{"url": address}}
	result, err := probeSavedEdgeRoute(context.Background(), desired, p, roots)
	if err != nil || result.Status != "verified" {
		t.Fatalf("saved DNS/h2c origin failed: %#v %v", result, err)
	}
}
