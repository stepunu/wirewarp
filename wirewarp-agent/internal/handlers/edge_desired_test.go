package handlers

import (
	"encoding/json"
	"testing"
	"time"
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
		"traefik_dynamic_config":{"http":{"routers":{}}}
	}`)
	var p EdgeDesiredStateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Whitelist.IPs[0] != "1.2.3.4" || p.TraefikStaticConfig["entryPoints"] == nil {
		t.Fatalf("unexpected decoded shape: %#v", p)
	}
}
