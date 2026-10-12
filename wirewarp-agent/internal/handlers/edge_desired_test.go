package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wirewarp/agent/internal/config"
)

func TestInjectBouncerKeyReplacesSentinel(t *testing.T) {
	raw := map[string]any{
		"http": map[string]any{
			"middlewares": map[string]any{
				"crowdsec-bouncer": map[string]any{
					"plugin": map[string]any{
						"bouncer": map[string]any{
							"enabled":         true,
							"crowdsecLapiKey": "${WIREWARP_CROWDSEC_BOUNCER_KEY}",
						},
					},
				},
			},
		},
	}

	got := injectBouncerKey(raw, "local-key")
	bouncer := got["http"].(map[string]any)["middlewares"].(map[string]any)["crowdsec-bouncer"].(map[string]any)["plugin"].(map[string]any)["bouncer"].(map[string]any)
	if bouncer["crowdsecLapiKey"] != "local-key" {
		t.Fatalf("crowdsecLapiKey: want local-key, got %#v", bouncer["crowdsecLapiKey"])
	}
	orig := raw["http"].(map[string]any)["middlewares"].(map[string]any)["crowdsec-bouncer"].(map[string]any)["plugin"].(map[string]any)["bouncer"].(map[string]any)
	if orig["crowdsecLapiKey"] != "${WIREWARP_CROWDSEC_BOUNCER_KEY}" {
		t.Fatalf("original map was mutated")
	}
}

func TestBuildAppSecAcquisitionModes(t *testing.T) {
	observe := buildAppSecAcquisition(false)
	block := buildAppSecAcquisition(true)

	if observe["source"] != "appsec" || block["source"] != "appsec" {
		t.Fatalf("source must be appsec")
	}
	if observe["labels"].(map[string]string)["wirewarp_mode"] != "observe" {
		t.Fatalf("observe mode label missing: %#v", observe["labels"])
	}
	if block["labels"].(map[string]string)["wirewarp_mode"] != "block" {
		t.Fatalf("block mode label missing: %#v", block["labels"])
	}
	observeConfigs := observe["appsec_configs"].([]string)
	blockConfigs := block["appsec_configs"].([]string)
	if observeConfigs[0] != "crowdsecurity/appsec-default" || observeConfigs[1] != "crowdsecurity/crs" {
		t.Fatalf("acquisition should follow CrowdSec AppSec default+CRS docs, got %#v", observeConfigs)
	}
	if observeConfigs[len(observeConfigs)-1] != appSecObserveName {
		t.Fatalf("observe acquisition should load %s last, got %#v", appSecObserveName, observeConfigs)
	}
	if blockConfigs[len(blockConfigs)-1] != appSecBlockName {
		t.Fatalf("block acquisition should load %s last, got %#v", appSecBlockName, blockConfigs)
	}
}

func TestBuildAppSecModeConfigs(t *testing.T) {
	observe := buildAppSecModeConfig(false)
	block := buildAppSecModeConfig(true)

	if observe["name"] != appSecObserveName || observe["default_remediation"] != "allow" {
		t.Fatalf("observe config should be non-blocking: %#v", observe)
	}
	if block["name"] != appSecBlockName || block["default_remediation"] != "ban" {
		t.Fatalf("block config should actively remediate: %#v", block)
	}
	if _, ok := observe["labels"]; ok {
		t.Fatalf("CrowdSec AppSec configs do not accept labels: %#v", observe)
	}
	if _, ok := observe["default_pass_action"]; ok {
		t.Fatalf("CrowdSec AppSec configs do not accept default_pass_action: %#v", observe)
	}
}

func TestAppSecBootstrapCommandsEnableReferencedConfigs(t *testing.T) {
	got := appSecBootstrapCommands()
	want := [][]string{
		{"collections", "install", "crowdsecurity/appsec-virtual-patching"},
		{"collections", "install", "crowdsecurity/appsec-generic-rules"},
		{"collections", "install", "crowdsecurity/appsec-crs"},
		{"appsec-configs", "install", "crowdsecurity/appsec-default"},
		{"appsec-configs", "install", "crowdsecurity/crs"},
		{"appsec-rules", "install", "crowdsecurity/crs"},
	}
	if len(got) != len(want) {
		t.Fatalf("bootstrap command count: want %d, got %d (%#v)", len(want), len(got), got)
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("command %d length: want %#v, got %#v", i, want[i], got[i])
		}
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Fatalf("command %d: want %#v, got %#v", i, want[i], got[i])
			}
		}
	}
}

func TestBouncerListDetectsWirewarpTraefik(t *testing.T) {
	out := []byte(`[
		{"name":"cs-firewall-bouncer-1","revoked":false},
		{"name":"wirewarp-traefik","revoked":false}
	]`)
	if !bouncerListHas(out, "wirewarp-traefik") {
		t.Fatalf("wirewarp-traefik bouncer should be detected")
	}
	revoked := []byte(`[{"name":"wirewarp-traefik","revoked":true}]`)
	if bouncerListHas(revoked, "wirewarp-traefik") {
		t.Fatalf("revoked wirewarp-traefik bouncer should not count as registered")
	}
}

func TestDesiredAppSecModeDefaultsToObserve(t *testing.T) {
	uses, block := desiredUsesWAF(map[string]any{})
	if !uses {
		t.Fatalf("edge reconcile should keep AppSec installed even when there are no HTTP routes yet")
	}
	if block {
		t.Fatalf("empty desired state should use observe mode, not block")
	}
}

func TestBackoffDurationCapsAtThirtyMinutes(t *testing.T) {
	if got := edgeBackoffDuration(0); got != 60*time.Second {
		t.Fatalf("attempt 0: want 60s, got %v", got)
	}
	if got := edgeBackoffDuration(10); got != 30*time.Minute {
		t.Fatalf("attempt 10: want 30m cap, got %v", got)
	}
}

func TestDesiredStateJSONShape(t *testing.T) {
	raw := []byte(`{
		"whitelist":{"ips":["1.2.3.4"],"cidrs":["10.21.0.0/24"]},
		"traefik_static_config":{"entryPoints":{"web":{"address":":80"}}},
		"traefik_dynamic_config":{"http":{"routers":{}}},
		"nginx_cache_config":{"enabled":true,"mode":"proxy_cache","routes":[{"host":"app.example.com","origin_url":"http://10.21.0.2:8080"}]},
		"traefik_acme":{"cloudflare_dns_api_token":"secret-token"}
	}`)
	var p EdgeDesiredStateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Whitelist.IPs[0] != "1.2.3.4" || p.TraefikStaticConfig["entryPoints"] == nil {
		t.Fatalf("unexpected decoded shape: %#v", p)
	}
	if p.TraefikACME.CloudflareDNSToken != "secret-token" {
		t.Fatalf("acme token not decoded: %#v", p.TraefikACME)
	}
	if p.NginxCacheConfig["mode"] != "proxy_cache" {
		t.Fatalf("nginx cache config not decoded: %#v", p.NginxCacheConfig)
	}

	persisted := config.EdgeDesiredState{
		Whitelist:            config.EdgeWhitelist{IPs: p.Whitelist.IPs, CIDRs: p.Whitelist.CIDRs},
		TraefikStaticConfig:  p.TraefikStaticConfig,
		TraefikDynamicConfig: p.TraefikDynamicConfig,
		NginxCacheConfig:     p.NginxCacheConfig,
	}
	data, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshal persisted desired state: %v", err)
	}
	if strings.Contains(string(data), "secret-token") {
		t.Fatalf("ACME secret must not be persisted in agent config: %s", data)
	}
}

func TestApplyTraefikACMESecretsWritesTokenFileAndEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "traefik.env")
	tokenPath := filepath.Join(dir, "secrets", "cloudflare_dns_api_token")

	changed, err := applyTraefikACMESecrets(TraefikACMEParams{CloudflareDNSToken: "secret-token"}, envPath, tokenPath)
	if err != nil {
		t.Fatalf("apply acme secrets: %v", err)
	}
	if !changed {
		t.Fatalf("first write should report changed")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(token) != "secret-token" {
		t.Fatalf("token file content mismatch: %q", token)
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("token file mode: want 0600, got %v", info.Mode().Perm())
	}
	env, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if string(env) != "CF_DNS_API_TOKEN_FILE="+tokenPath+"\n" {
		t.Fatalf("env file mismatch: %q", env)
	}

	changed, err = applyTraefikACMESecrets(TraefikACMEParams{}, envPath, tokenPath)
	if err != nil {
		t.Fatalf("remove acme secrets: %v", err)
	}
	if !changed {
		t.Fatalf("removing existing files should report changed")
	}
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Fatalf("env file should be removed, got err=%v", err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token file should be removed, got err=%v", err)
	}
}

func TestTraefikUnitLoadsManagedEnvironmentFile(t *testing.T) {
	if !strings.Contains(traefikUnitTemplate, "EnvironmentFile=-/etc/traefik/traefik.env") {
		t.Fatalf("traefik systemd unit must load the managed ACME env file")
	}
}

func TestApplyTraefikACMERFC2136SecretsAndProviderSwitch(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "traefik.env")
	tokenPath := filepath.Join(dir, "secrets", "cloudflare_dns_api_token")
	p := TraefikACMEParams{
		RFC2136Nameserver:    "ns1.example.com:53",
		RFC2136TSIGKey:       "acme.example.com.",
		RFC2136TSIGAlgorithm: "hmac-sha256",
		RFC2136TSIGSecret:    "dGVzdC1zZWNyZXQ=",
	}
	changed, err := applyTraefikACMESecrets(p, envPath, tokenPath)
	if err != nil || !changed {
		t.Fatalf("first RFC2136 apply: changed=%v err=%v", changed, err)
	}
	secretPath := rfc2136CredentialPath(p, tokenPath)
	secret, err := os.ReadFile(secretPath)
	if err != nil || string(secret) != p.RFC2136TSIGSecret {
		t.Fatal("RFC2136 secret file missing or incorrect")
	}
	env, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"RFC2136_NAMESERVER=ns1.example.com:53\n",
		"RFC2136_TSIG_KEY=acme.example.com.\n",
		"RFC2136_TSIG_ALGORITHM=hmac-sha256\n",
		"RFC2136_TSIG_SECRET_FILE=" + secretPath + "\n",
	} {
		if !strings.Contains(string(env), want) {
			t.Fatalf("missing RFC2136 setting %s", strings.Split(want, "=")[0])
		}
	}
	if strings.Contains(string(env), p.RFC2136TSIGSecret) {
		t.Fatal("secret leaked into environment file")
	}
	for _, path := range []string{secretPath, envPath} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("ACME file must be root-readable only: %s", path)
		}
	}
	changed, err = applyTraefikACMESecrets(p, envPath, tokenPath)
	if err != nil || changed {
		t.Fatalf("repeat apply must be unchanged: changed=%v err=%v", changed, err)
	}
	_, err = applyTraefikACMESecrets(TraefikACMEParams{CloudflareDNSToken: "test-token"}, envPath, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secretPath); err != nil {
		t.Fatal("switch must retain the immutable key for pending DNS cleanup")
	}
	_, err = applyTraefikACMESecrets(TraefikACMEParams{}, envPath, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{envPath, tokenPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("disabled ACME must remove managed credential file %s", path)
		}
	}
}

func TestApplyTraefikACMERFC2136RejectsInvalidSettingsBeforeWrites(t *testing.T) {
	valid := TraefikACMEParams{
		RFC2136Nameserver: "ns1.example.com:53", RFC2136TSIGKey: "acme.example.com.",
		RFC2136TSIGAlgorithm: "hmac-sha256", RFC2136TSIGSecret: "dGVzdC1zZWNyZXQ=",
	}
	for _, mutate := range []func(*TraefikACMEParams){
		func(p *TraefikACMEParams) { p.RFC2136Nameserver = "ns1.example.com:53\nEVIL=yes" },
		func(p *TraefikACMEParams) { p.RFC2136TSIGKey = "key\nEVIL=yes" },
		func(p *TraefikACMEParams) { p.RFC2136TSIGAlgorithm = "unknown" },
		func(p *TraefikACMEParams) { p.RFC2136TSIGSecret = "invalid secret" },
		func(p *TraefikACMEParams) { p.RFC2136TSIGSecret = "" },
		func(p *TraefikACMEParams) { p.CloudflareDNSToken = "other-provider" },
	} {
		dir := t.TempDir()
		envPath := filepath.Join(dir, "traefik.env")
		tokenPath := filepath.Join(dir, "secrets", "cloudflare_dns_api_token")
		p := valid
		mutate(&p)
		if _, err := applyTraefikACMESecrets(p, envPath, tokenPath); err == nil {
			t.Fatal("invalid settings accepted")
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatal("invalid settings changed the filesystem")
		}
	}
}

func TestACMERestartRetriesAfterFailureAndUnchangedCredentialReplay(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "traefik.env")
	tokenPath := filepath.Join(dir, "secrets", "cloudflare_dns_api_token")
	p := TraefikACMEParams{CloudflareDNSToken: "test-token"}
	if _, err := applyTraefikACMESecrets(p, envPath, tokenPath); err != nil {
		t.Fatal(err)
	}
	previous := edgeSystemctl
	t.Cleanup(func() { edgeSystemctl = previous })
	calls := 0
	edgeSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if len(args) != 2 || args[0] != "restart" || args[1] != traefikUnitName {
			t.Fatal("unexpected credential reload command")
		}
		if calls == 1 {
			return nil, errors.New("service unavailable")
		}
		return nil, nil
	}
	if err := reconcileTraefikACMESecrets(context.Background(), envPath); err == nil {
		t.Fatal("failed restart must be reported")
	}
	if changed, err := applyTraefikACMESecrets(p, envPath, tokenPath); err != nil || changed {
		t.Fatal("unchanged credential replay must be idempotent")
	}
	if err := reconcileTraefikACMESecrets(context.Background(), envPath); err != nil {
		t.Fatal(err)
	}
	if err := reconcileTraefikACMESecrets(context.Background(), envPath); err != nil || calls != 2 {
		t.Fatal("successful credential reload must clear retry state")
	}
}

func TestACMECredentialRotationCannotRacePendingRestart(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "traefik.env")
	tokenPath := filepath.Join(dir, "secrets", "cloudflare_dns_api_token")
	if _, err := applyTraefikACMESecrets(TraefikACMEParams{CloudflareDNSToken: "old-test-token"}, envPath, tokenPath); err != nil {
		t.Fatal(err)
	}
	previous := edgeSystemctl
	t.Cleanup(func() { edgeSystemctl = previous })
	started, release := make(chan struct{}), make(chan struct{})
	edgeSystemctl = func(_ context.Context, _ ...string) ([]byte, error) {
		close(started)
		<-release
		return nil, nil
	}
	restarted := make(chan error, 1)
	go func() { restarted <- reconcileTraefikACMESecrets(context.Background(), envPath) }()
	<-started
	applied := make(chan error, 1)
	go func() {
		_, err := applyTraefikACMESecrets(TraefikACMEParams{CloudflareDNSToken: "new-test-token"}, envPath, tokenPath)
		applied <- err
	}()
	select {
	case err := <-applied:
		close(release)
		<-restarted
		t.Fatalf("credential rotation ran during restart: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-restarted; err != nil {
		t.Fatal(err)
	}
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(envPath + ".pending-restart"); err != nil {
		t.Fatal("new credentials must retain their own pending restart")
	}
}
