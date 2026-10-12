package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	edgeBackoffBase       = 60 * time.Second
	edgeBackoffMax        = 30 * time.Minute
	appSecAcquisitionFile = "/etc/crowdsec/acquis.d/wirewarp-appsec.yaml"
	appSecConfigDir       = "/etc/crowdsec/appsec-configs"
	appSecObserveName     = "wirewarp/observe"
	appSecBlockName       = "wirewarp/block"
)

type EdgeDesiredStateParams struct {
	DesiredHash          string                     `json:"desired_hash"`
	ConfigVersionID      string                     `json:"config_version_id"`
	RuntimeMode          string                     `json:"runtime_mode"`
	PublicIngress        []config.EdgePublicIngress `json:"public_ingress"`
	Whitelist            CrowdSecInstallParams      `json:"whitelist"`
	TraefikStaticConfig  map[string]any             `json:"traefik_static_config"`
	TraefikDynamicConfig map[string]any             `json:"traefik_dynamic_config"`
	NginxCacheConfig     map[string]any             `json:"nginx_cache_config"`
	TraefikACME          TraefikACMEParams          `json:"traefik_acme"`
}

func (h *EdgeHandlers) handleEdgeDesiredState(raw json.RawMessage) (string, error) {
	var p EdgeDesiredStateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("parse params: %w", err)
	}
	desired := &config.EdgeDesiredState{
		DesiredHash: p.DesiredHash, ConfigVersionID: p.ConfigVersionID,
		RuntimeMode:   p.RuntimeMode,
		PublicIngress: append([]config.EdgePublicIngress(nil), p.PublicIngress...),
		Whitelist: config.EdgeWhitelist{
			IPs:   append([]string(nil), p.Whitelist.IPs...),
			CIDRs: append([]string(nil), p.Whitelist.CIDRs...),
		},
		TraefikStaticConfig:  p.TraefikStaticConfig,
		TraefikDynamicConfig: p.TraefikDynamicConfig,
		NginxCacheConfig:     p.NginxCacheConfig,
	}
	previous := h.cfg.Snapshot()
	if err := validateEdgeRuntime(previous, desired); err != nil {
		return "", err
	}
	restoreFiles, err := h.snapshotRuntime()
	if err != nil {
		return "", err
	}
	key := previous.EdgeBouncerKey
	if key == "" && desired.RuntimeMode != "relay_only" {
		key, err = generateBouncerKey()
		if err != nil {
			return "", err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	previousIngress := savedEdgeIngress(previous)
	stagedIngress := unionEdgeIngress(previousIngress, desired.PublicIngress)
	save := func() error {
		if err := h.applyIngress(ctx, stagedIngress); err != nil {
			return err
		}
		err := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
			next.EdgeDesired = desired
			next.EdgeBouncerKey = key
			next.EdgeDisabled = false
			next.EdgeIngressGuard = append([]config.EdgePublicIngress(nil), stagedIngress...)
			next.EdgeRuntimePending = true
			return nil
		})
		if err != nil {
			if rollbackErr := h.applyIngress(ctx, previousIngress); rollbackErr != nil {
				return fmt.Errorf("%w; ingress rollback degraded: %v", err, rollbackErr)
			}
		}
		return err
	}
	if err := h.persistSecrets(p.TraefikACME, save); err != nil {
		return "", fmt.Errorf("persist desired edge state: %w", err)
	}

	if err := h.convergeEdgeRuntime(ctx); err != nil {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer rollbackCancel()
		if rollbackErr := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
			next.EdgeDesired = previous.EdgeDesired
			next.EdgeBouncerKey = previous.EdgeBouncerKey
			next.EdgeDisabled = previous.EdgeDisabled
			if previous.EdgeDesired == nil {
				next.EdgeDisabled = true
			}
			next.EdgeIngressGuard = append([]config.EdgePublicIngress(nil), stagedIngress...)
			next.EdgeRuntimePending = true
			return nil
		}); rollbackErr != nil {
			return "edge reconcile failed; rollback degraded; new desired state retained", fmt.Errorf("edge reconcile failed: %w; saved-state rollback degraded: %v", err, rollbackErr)
		}
		var failures []string
		// Keep new ownership markers until newly started services are stopped.
		if previous.EdgeDisabled || previous.EdgeDesired == nil {
			if _, rollbackErr := h.stopEdgeServices(nil); rollbackErr != nil {
				failures = append(failures, rollbackErr.Error())
			}
		}
		if len(failures) == 0 {
			if rollbackErr := restoreFiles(); rollbackErr != nil {
				failures = append(failures, rollbackErr.Error())
			}
		}
		if len(failures) == 0 {
			if previous.EdgeDisabled || previous.EdgeDesired == nil {
				if rollbackErr := h.finalizeEdgeIngress(rollbackCtx); rollbackErr != nil {
					failures = append(failures, rollbackErr.Error())
				}
			} else {
				if rollbackErr := h.applyDesired(rollbackCtx); rollbackErr != nil {
					failures = append(failures, "runtime: "+rollbackErr.Error())
				}
				owned, probeErr := h.ownedService(traefikUnitName)
				if probeErr != nil {
					failures = append(failures, probeErr.Error())
				} else if owned {
					if _, restartErr := edgeSystemctl(rollbackCtx, "restart", traefikUnitName); restartErr != nil {
						failures = append(failures, "restart previous Traefik: "+restartErr.Error())
					}
				}
				if len(failures) == 0 {
					if rollbackErr := h.finalizeEdgeIngress(rollbackCtx); rollbackErr != nil {
						failures = append(failures, rollbackErr.Error())
					}
				}
			}
		}
		if len(failures) != 0 {
			return "edge reconcile failed; rollback degraded", fmt.Errorf("edge reconcile failed: %w; rollback degraded: %s", err, strings.Join(failures, "; "))
		}
		return "edge reconcile failed; previous state restored", fmt.Errorf("edge reconcile failed: %w; previous state restored", err)
	}
	return "desired edge state saved and reconciled", nil
}

func generateBouncerKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate bouncer key: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func edgeBackoffDuration(attempt int) time.Duration {
	if attempt <= 0 {
		return edgeBackoffBase
	}
	d := edgeBackoffBase << attempt
	if d > edgeBackoffMax {
		return edgeBackoffMax
	}
	return d
}

func injectBouncerKey(in map[string]any, key string) map[string]any {
	if in == nil {
		return nil
	}
	data, err := json.Marshal(in)
	if err != nil {
		return in
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return in
	}
	http, _ := out["http"].(map[string]any)
	middlewares, _ := http["middlewares"].(map[string]any)
	for _, mwRaw := range middlewares {
		mw, _ := mwRaw.(map[string]any)
		plugin, _ := mw["plugin"].(map[string]any)
		bouncer, _ := plugin["bouncer"].(map[string]any)
		if bouncer == nil {
			continue
		}
		if _, ok := bouncer["crowdsecLapiKey"]; ok {
			bouncer["crowdsecLapiKey"] = key
		}
	}
	return out
}

func buildAppSecAcquisition(block bool) map[string]any {
	mode := "observe"
	modeConfig := appSecObserveName
	listen := "127.0.0.1:7423"
	if block {
		mode = "block"
		modeConfig = appSecBlockName
		listen = "127.0.0.1:7422"
	}
	return map[string]any{
		"source":      "appsec",
		"listen_addr": listen,
		"path":        "/",
		"appsec_configs": []string{
			"crowdsecurity/appsec-default",
			"crowdsecurity/crs",
			modeConfig,
		},
		"labels": map[string]string{
			"type":          "appsec",
			"wirewarp_mode": mode,
		},
	}
}

func buildAppSecModeConfig(block bool) map[string]any {
	name := appSecObserveName
	remediation := "allow"
	if block {
		name = appSecBlockName
		remediation = "ban"
	}
	return map[string]any{
		"name":                name,
		"default_remediation": remediation,
	}
}

func writeAppSecModeConfigs() error {
	if err := os.MkdirAll(appSecConfigDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", appSecConfigDir, err)
	}
	for _, mode := range []struct {
		block bool
		file  string
	}{
		{block: false, file: filepath.Join(appSecConfigDir, "wirewarp-observe.yaml")},
		{block: true, file: filepath.Join(appSecConfigDir, "wirewarp-block.yaml")},
	} {
		data, err := yaml.Marshal(buildAppSecModeConfig(mode.block))
		if err != nil {
			return fmt.Errorf("marshal appsec mode config: %w", err)
		}
		header := "# AUTO-GENERATED by wirewarp-agent; do not edit by hand.\n"
		if err := os.WriteFile(mode.file, append([]byte(header), data...), 0644); err != nil {
			return fmt.Errorf("write %s: %w", mode.file, err)
		}
	}
	return nil
}

func renderAppSecAcquisition() ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	for _, block := range []bool{true, false} {
		if err := encoder.Encode(buildAppSecAcquisition(block)); err != nil {
			return nil, err
		}
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeAppSecAcquisition(_ bool) (bool, error) {
	if err := writeAppSecModeConfigs(); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(appSecAcquisitionFile), 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(appSecAcquisitionFile), err)
	}
	data, err := renderAppSecAcquisition()
	if err != nil {
		return false, fmt.Errorf("marshal appsec acquisition: %w", err)
	}
	header := "# AUTO-GENERATED by wirewarp-agent; do not edit by hand.\n"
	next := append([]byte(header), data...)
	if current, err := os.ReadFile(appSecAcquisitionFile); err == nil && string(current) == string(next) {
		return false, nil
	}
	return true, os.WriteFile(appSecAcquisitionFile, next, 0644)
}

func desiredUsesWAF(dynamic map[string]any) (uses bool, block bool) {
	uses = true
	http, _ := dynamic["http"].(map[string]any)
	middlewares, _ := http["middlewares"].(map[string]any)
	for _, mwRaw := range middlewares {
		mw, _ := mwRaw.(map[string]any)
		plugin, _ := mw["plugin"].(map[string]any)
		bouncer, _ := plugin["bouncer"].(map[string]any)
		if bouncer == nil {
			continue
		}
		if failureBlock, _ := bouncer["crowdsecAppsecFailureBlock"].(bool); failureBlock {
			block = true
		}
	}
	return uses, block
}

func (h *EdgeHandlers) desiredWhitelist() CrowdSecInstallParams {
	saved := h.cfg.Snapshot()
	if saved.EdgeDesired == nil {
		return CrowdSecInstallParams{}
	}
	return CrowdSecInstallParams{
		IPs:   append([]string(nil), saved.EdgeDesired.Whitelist.IPs...),
		CIDRs: append([]string(nil), saved.EdgeDesired.Whitelist.CIDRs...),
	}
}

func (h *EdgeHandlers) reconcileDesiredEdge(ctx context.Context) error {
	saved := h.cfg.Snapshot()
	if saved.EdgeDesired == nil || saved.EdgeDisabled {
		return nil
	}
	if err := validateEdgeRuntime(saved, saved.EdgeDesired); err != nil {
		return err
	}
	if err := h.applyIngress(ctx, savedEdgeIngress(saved)); err != nil {
		return err
	}
	if saved.EdgeDesired.RuntimeMode == "relay_only" {
		if _, err := h.stopEdgeServices([]string{"crowdsec", "nginx"}); err != nil {
			return err
		}
		return h.applyTraefik(ctx, saved)
	}

	var firstErr error
	usesWAF, block := desiredUsesWAF(saved.EdgeDesired.TraefikDynamicConfig)
	if usesWAF && saved.EdgeBouncerKey == "" {
		key, err := generateBouncerKey()
		if err != nil && firstErr == nil {
			firstErr = err
		} else {
			err = h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
				next.EdgeBouncerKey = key
				return nil
			})
			if err != nil {
				return fmt.Errorf("persist edge bouncer key: %w", err)
			}
			saved.EdgeBouncerKey = key
		}
	}

	whitelist := h.desiredWhitelist()
	if resolveCSCli() == "" {
		raw, _ := json.Marshal(whitelist)
		if _, err := h.handleCrowdSecInstall(raw); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if usesWAF {
		appsecChanged, err := writeAppSecAcquisition(block)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		needsBootstrap := appsecChanged
		if bin := resolveCSCli(); bin != "" && !crowdSecBouncerRegistered(ctx, bin) {
			needsBootstrap = true
		}
		if !appSecBootstrapFilesPresent() {
			needsBootstrap = true
		}
		if needsBootstrap {
			appsecRaw, _ := json.Marshal(CrowdSecAppSecParams{BouncerKey: saved.EdgeBouncerKey})
			if _, err := h.handleCrowdSecAppSecEnable(appsecRaw); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if resolveCSCli() != "" {
		raw, _ := json.Marshal(whitelist)
		if _, err := h.handleCrowdSecSyncWhitelist(raw); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if saved.EdgeDesired.TraefikStaticConfig != nil {
		raw, _ := json.Marshal(TraefikInstallParams{StaticConfig: saved.EdgeDesired.TraefikStaticConfig})
		if _, err := h.handleTraefikInstall(raw); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if saved.EdgeDesired.TraefikDynamicConfig != nil {
		dynamic := injectBouncerKey(saved.EdgeDesired.TraefikDynamicConfig, saved.EdgeBouncerKey)
		raw, _ := json.Marshal(TraefikSyncConfigParams{DynamicConfig: dynamic})
		if _, err := h.handleTraefikSyncConfig(raw); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if saved.EdgeDesired.TraefikStaticConfig != nil {
		if err := reconcileTraefikACMESecrets(ctx, traefikEnvPath); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if saved.EdgeDesired.NginxCacheConfig != nil {
		if err := h.reconcileNginxCache(ctx, saved.EdgeDesired.NginxCacheConfig); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	h.pollAndEmitCrowdSec(ctx, false)
	h.pollAndEmitTraefik(ctx, false)
	h.pollAndEmitNginxCache(ctx, false)
	return firstErr
}
