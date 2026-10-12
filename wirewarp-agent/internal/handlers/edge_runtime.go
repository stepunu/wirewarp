package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wirewarp/agent/internal/config"
)

func unionEdgeIngress(groups ...[]config.EdgePublicIngress) []config.EdgePublicIngress {
	seen := map[config.EdgePublicIngress]bool{}
	var union []config.EdgePublicIngress
	for _, group := range groups {
		for _, entry := range group {
			if !seen[entry] {
				seen[entry] = true
				union = append(union, entry)
			}
		}
	}
	return union
}

func savedEdgeIngress(saved *config.Config) []config.EdgePublicIngress {
	var desired []config.EdgePublicIngress
	if saved.EdgeDesired != nil {
		desired = saved.EdgeDesired.PublicIngress
	}
	return unionEdgeIngress(saved.EdgeIngressGuard, desired)
}

func (h *EdgeHandlers) convergeEdgeRuntime(ctx context.Context) error {
	saved := h.cfg.Snapshot()
	if err := h.applyIngress(ctx, savedEdgeIngress(saved)); err != nil {
		return err
	}
	if err := h.applyDesired(ctx); err != nil {
		return err
	}
	if saved.EdgeRuntimePending {
		owned, err := h.ownedService(traefikUnitName)
		if err != nil {
			return err
		}
		if owned {
			restartCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if _, err := edgeSystemctl(restartCtx, "restart", traefikUnitName); err != nil {
				return fmt.Errorf("restart pending edge runtime: %w", err)
			}
		}
	}
	return h.finalizeEdgeIngress(ctx)
}

func (h *EdgeHandlers) finalizeEdgeIngress(ctx context.Context) error {
	saved := h.cfg.Snapshot()
	var desired []config.EdgePublicIngress
	if saved.EdgeDesired != nil && !saved.EdgeDisabled {
		desired = saved.EdgeDesired.PublicIngress
	}
	if err := h.applyIngress(ctx, desired); err != nil {
		return err
	}
	if err := h.cfg.UpdateAndSave(h.cfgPath, func(next *config.Config) error {
		next.EdgeIngressGuard = append([]config.EdgePublicIngress(nil), desired...)
		next.EdgeRuntimePending = false
		return nil
	}); err != nil {
		return fmt.Errorf("persist applied edge runtime guard: %w", err)
	}
	return nil
}

func validateEdgeRuntime(saved *config.Config, desired *config.EdgeDesiredState) error {
	if desired == nil {
		return nil
	}
	if saved.Mode != "server" && (saved.Mode != "client" || !saved.Gateway()) {
		return fmt.Errorf("Security Edge requires a server or gateway node")
	}
	switch desired.RuntimeMode {
	case "", "security_edge":
	case "relay_only":
		if saved.Mode != "server" {
			return fmt.Errorf("relay_only requires a server node")
		}
		if len(desired.PublicIngress) != 0 || len(desired.Whitelist.IPs) != 0 || len(desired.Whitelist.CIDRs) != 0 || len(desired.NginxCacheConfig) != 0 {
			return fmt.Errorf("relay_only cannot configure gateway ingress, WAF, or cache")
		}
		if desired.TraefikStaticConfig == nil || desired.TraefikDynamicConfig == nil {
			return fmt.Errorf("relay_only requires Traefik static and dynamic config")
		}
		if containsWAF(desired.TraefikDynamicConfig) || containsWAF(desired.TraefikStaticConfig) {
			return fmt.Errorf("relay_only cannot configure WAF middleware")
		}
	default:
		return fmt.Errorf("unsupported edge runtime_mode")
	}
	if saved.Mode == "server" {
		if len(desired.PublicIngress) != 0 {
			return fmt.Errorf("public_ingress applies only to gateway nodes")
		}
		return nil
	}
	// Legacy empty state has no listeners to expose. Gateway listeners must use
	// explicit IPv4 binds, including LAN-only deployments.
	if desired.TraefikStaticConfig == nil && len(desired.PublicIngress) == 0 {
		return nil
	}
	entrypoints, _ := desired.TraefikStaticConfig["entryPoints"].(map[string]any)
	if len(entrypoints) == 0 {
		return fmt.Errorf("gateway Traefik requires explicit IPv4 entrypoints")
	}
	sources := map[string]map[string]bool{}
	seen := map[string]bool{}
	for _, ingress := range desired.PublicIngress {
		if !regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`).MatchString(ingress.Interface) {
			return fmt.Errorf("public_ingress interface is invalid")
		}
		source, err := edgeIPv4(ingress.SourceIP)
		if err != nil {
			return err
		}
		listen, err := edgeIPv4(ingress.ListenIP)
		if err != nil {
			return err
		}
		matched := false
		for _, attachment := range saved.Attachments {
			if attachment.IsGateway && attachment.WGInterface == ingress.Interface && stripEdgePrefix(attachment.VPSTunnelIP) == source && stripEdgePrefix(attachment.TunnelIP) == listen {
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("public_ingress must match a saved gateway WireGuard attachment")
		}
		key := ingress.Interface + "/" + source + "/" + listen
		if seen[key] {
			return fmt.Errorf("public_ingress contains a duplicate attachment")
		}
		seen[key] = true
		if sources[listen] == nil {
			sources[listen] = map[string]bool{}
		}
		sources[listen][source] = true
	}
	if len(desired.PublicIngress) > 1 {
		return fmt.Errorf("public_ingress currently supports one IPv4 gateway attachment")
	}
	ports := map[string]map[string]bool{}
	binds := map[string]bool{}
	for name, raw := range entrypoints {
		ep, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("gateway entrypoint %s is invalid", name)
		}
		address, _ := ep["address"].(string)
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("gateway entrypoint %s requires an explicit IPv4 TCP bind", name)
		}
		host, err = edgeIPv4(host)
		if err != nil {
			return err
		}
		if port != "80" && port != "443" {
			return fmt.Errorf("gateway edge listeners support only IPv4 TCP80 and TCP443")
		}
		if binds[address] {
			return fmt.Errorf("gateway entrypoints cannot share the same listen address")
		}
		binds[address] = true
		if name == "lan" || name == "lansecure" {
			if sources[host] != nil {
				return fmt.Errorf("LAN entrypoints cannot bind the public ingress address")
			}
		}
		if name == "web" || name == "websecure" {
			if sources[host] == nil {
				return fmt.Errorf("public entrypoints require matching public_ingress")
			}
		}
		if _, enabled := ep["http3"]; enabled {
			return fmt.Errorf("gateway public ingress does not support HTTP3 or UDP")
		}
		forwarded, _ := ep["forwardedHeaders"].(map[string]any)
		if value, exists := ep["forwardedHeaders"]; exists && value != nil && forwarded == nil {
			return fmt.Errorf("gateway forwardedHeaders must be an object")
		}
		if value, exists := forwarded["insecure"]; exists && value != false {
			return fmt.Errorf("gateway entrypoints cannot trust insecure forwarded headers")
		}
		if insecure, _ := forwarded["insecure"].(bool); insecure || len(edgeStrings(forwarded["trustedIPs"])) != 0 {
			return fmt.Errorf("gateway entrypoints cannot trust forwarded headers")
		}
		proxy, _ := ep["proxyProtocol"].(map[string]any)
		if value, exists := ep["proxyProtocol"]; exists && value != nil && proxy == nil {
			return fmt.Errorf("gateway proxyProtocol must be an object")
		}
		if value, exists := proxy["insecure"]; exists && value != false {
			return fmt.Errorf("gateway entrypoints cannot trust insecure PROXY protocol")
		}
		if insecure, _ := proxy["insecure"].(bool); insecure {
			return fmt.Errorf("gateway entrypoints cannot trust insecure PROXY protocol")
		}
		if expected := sources[host]; expected != nil {
			actual := edgeStrings(proxy["trustedIPs"])
			if len(actual) != len(expected) {
				return fmt.Errorf("public entrypoint PROXY trustedIPs must match selected VPS WireGuard addresses")
			}
			for _, value := range actual {
				if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Bits() == 32 {
					value = prefix.Addr().String()
				}
				if !expected[value] {
					return fmt.Errorf("public entrypoint PROXY trustedIPs must match selected VPS WireGuard addresses")
				}
			}
			if ports[host] == nil {
				ports[host] = map[string]bool{}
			}
			ports[host][port] = true
		} else {
			if proxy != nil {
				return fmt.Errorf("LAN entrypoints cannot accept PROXY protocol")
			}
			for _, attachment := range saved.Attachments {
				if stripEdgePrefix(attachment.TunnelIP) == host {
					return fmt.Errorf("WireGuard public listener requires matching public_ingress")
				}
			}
			lanIP := ""
			if saved.GatewayLANIP != nil {
				lanIP = *saved.GatewayLANIP
			} else {
				for _, attachment := range saved.Attachments {
					if attachment.IsGateway && stripEdgePrefix(attachment.LANIP) == host {
						lanIP = host
					}
				}
			}
			if host != lanIP {
				return fmt.Errorf("LAN listener bind must match the saved gateway LAN IP")
			}
		}
	}
	for listen := range sources {
		if !ports[listen]["80"] || !ports[listen]["443"] {
			return fmt.Errorf("public_ingress requires matching explicit TCP80 and TCP443 entrypoints")
		}
	}
	return nil
}

func (h *EdgeHandlers) validateTraefikUpdate(static, dynamic map[string]any) error {
	saved := h.cfg.Snapshot()
	desired := saved.EdgeDesired
	if desired == nil {
		desired = &config.EdgeDesiredState{}
	}
	if static != nil {
		desired.TraefikStaticConfig = static
	}
	if dynamic != nil {
		desired.TraefikDynamicConfig = dynamic
	}
	return validateEdgeRuntime(saved, desired)
}

func edgeIPv4(value string) (string, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || !ip.IsGlobalUnicast() {
		return "", fmt.Errorf("edge ingress requires a valid unicast IPv4 address; IPv6 is not supported")
	}
	return ip.String(), nil
}

func stripEdgePrefix(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().String()
	}
	return value
}

func edgeStrings(raw any) []string {
	switch values := raw.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		out := make([]string, 0, len(values))
		for _, v := range values {
			s, ok := v.(string)
			if !ok {
				return []string{"invalid"}
			}
			out = append(out, s)
		}
		return out
	case nil:
		return nil
	default:
		return []string{"invalid"}
	}
}

func containsWAF(raw any) bool {
	switch value := raw.(type) {
	case map[string]any:
		for key, nested := range value {
			if strings.EqualFold(key, "bouncer") || strings.HasPrefix(strings.ToLower(key), "crowdsec") {
				return true
			}
			if containsWAF(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range value {
			if containsWAF(nested) {
				return true
			}
		}
	}
	return false
}

func (h *EdgeHandlers) reconcileEdgeTraefik(ctx context.Context, saved *config.Config) error {
	if saved.EdgeDesired.TraefikStaticConfig != nil {
		raw, _ := json.Marshal(TraefikInstallParams{StaticConfig: saved.EdgeDesired.TraefikStaticConfig})
		if _, err := h.handleTraefikInstall(raw); err != nil {
			return err
		}
	}
	if saved.EdgeDesired.TraefikDynamicConfig != nil {
		dynamic := saved.EdgeDesired.TraefikDynamicConfig
		if saved.EdgeDesired.RuntimeMode != "relay_only" {
			dynamic = injectBouncerKey(dynamic, saved.EdgeBouncerKey)
		}
		raw, _ := json.Marshal(TraefikSyncConfigParams{DynamicConfig: dynamic})
		if _, err := h.handleTraefikSyncConfig(raw); err != nil {
			return err
		}
	}
	if saved.EdgeDesired.TraefikStaticConfig != nil {
		if err := reconcileTraefikACMESecrets(ctx, traefikEnvPath); err != nil {
			return err
		}
	}
	h.pollAndEmitTraefik(ctx, false)
	return nil
}

func edgeIngressRules(ingress []config.EdgePublicIngress) []string {
	var rules []string
	listens := map[string]bool{}
	for _, entry := range ingress {
		rules = append(rules, fmt.Sprintf("-A %s -i %s -s %s/32 -d %s/32 -p tcp -m multiport --dports 80,443 -j ACCEPT", edgeIngressChain, entry.Interface, entry.SourceIP, entry.ListenIP))
		listens[entry.ListenIP] = true
	}
	var ips []string
	for ip := range listens {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		rules = append(rules, fmt.Sprintf("-A %s -i lo -s %s/32 -d %s/32 -p tcp -m multiport --dports 80,443 -j ACCEPT", edgeIngressChain, ip, ip))
		rules = append(rules, fmt.Sprintf("-A %s -d %s/32 -p tcp -m multiport --dports 80,443 -j DROP", edgeIngressChain, ip))
	}
	return rules
}
