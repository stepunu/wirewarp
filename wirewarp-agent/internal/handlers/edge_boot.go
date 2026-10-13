package handlers

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/wirewarp/agent/internal/config"
	"gopkg.in/yaml.v3"
)

// RestoreEdgeIngressGuard runs before networking. Old transition guards remain
// until the reconciler confirms that their listeners have stopped.
func RestoreEdgeIngressGuard(ctx context.Context, cfg *config.Config) error {
	saved := cfg.Snapshot()
	guard := savedEdgeIngress(saved)
	for _, ingress := range guard {
		if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`).MatchString(ingress.Interface) {
			return fmt.Errorf("saved edge ingress interface is invalid")
		}
		if _, err := edgeIPv4(ingress.SourceIP); err != nil {
			return err
		}
		if _, err := edgeIPv4(ingress.ListenIP); err != nil {
			return err
		}
	}
	if !saved.EdgeDisabled && saved.EdgeDesired != nil {
		if err := validateEdgeRuntime(saved, saved.EdgeDesired); err != nil {
			return err
		}
	}
	if len(guard) == 0 {
		return nil
	}
	if err := preflightFirewallOwnership(ctx, saved); err != nil {
		return err
	}
	return reconcileEdgeIngress(ctx, guard)
}

// PrepareEdgeStart also blocks systemd from restarting a persistently disabled
// proxy. A missing client desired state cannot authorize a gateway listener.
func PrepareEdgeStart(ctx context.Context, cfg *config.Config) error {
	return prepareEdgeStart(ctx, cfg, traefikStaticCfg)
}

func prepareEdgeStart(ctx context.Context, cfg *config.Config, staticPath string) error {
	saved := cfg.Snapshot()
	if saved.EdgeDisabled || (saved.Mode != "server" && (saved.EdgeDesired == nil || !saved.Gateway())) {
		return fmt.Errorf("saved edge state does not permit Traefik startup")
	}
	if saved.Mode != "server" {
		data, err := os.ReadFile(staticPath)
		if err != nil {
			return fmt.Errorf("cannot verify installed gateway listeners")
		}
		var installed map[string]any
		if yaml.Unmarshal(data, &installed) != nil || !reflect.DeepEqual(installed["entryPoints"], saved.EdgeDesired.TraefikStaticConfig["entryPoints"]) {
			return fmt.Errorf("installed gateway listeners do not match saved guarded state")
		}
	}
	return RestoreEdgeIngressGuard(ctx, cfg)
}

func edgeTraefikUnit(configPath string) (string, error) {
	if configPath == "" || strings.ContainsAny(configPath, "\x00\r\n") {
		return "", fmt.Errorf("invalid edge config path")
	}
	// systemd expands specifiers and environment variables even in quotes.
	arg := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%", "$", "$$").Replace(configPath)
	pre := `ExecStartPre=/usr/local/bin/wirewarp-agent --restore-edge-ingress --config "` + arg + "\"\n"
	return strings.Replace(traefikUnitTemplate, "ExecStart=", pre+"ExecStart=", 1), nil
}

func validatePublishedAttachmentChange(saved *config.Config, next config.AttachmentState) error {
	for _, ingress := range savedEdgeIngress(saved) {
		for _, old := range saved.Attachments {
			if old.WGInterface != ingress.Interface || stripEdgePrefix(old.TunnelIP) != ingress.ListenIP {
				continue
			}
			if old.AttachmentID != next.AttachmentID && old.WGInterface != next.WGInterface {
				continue
			}
			if old.AttachmentID != next.AttachmentID || old.WGInterface != next.WGInterface || old.TunnelIP != next.TunnelIP || old.VPSTunnelIP != next.VPSTunnelIP || old.ServerPublicKey != next.ServerPublicKey || old.IsGateway != next.IsGateway || old.LANIP != next.LANIP || old.LANIface != next.LANIface || old.LANNetwork != next.LANNetwork || old.Fwmark != next.Fwmark || old.RouteTableID != next.RouteTableID {
				return fmt.Errorf("unpublish edge ingress before changing its WireGuard attachment")
			}
		}
	}
	return nil
}
