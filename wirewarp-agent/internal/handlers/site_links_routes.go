package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/wirewarp/agent/internal/config"
)

const siteRouteProtocol = "242"

var siteNetworkCommand = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
	path := resolveBin(binary, "/usr/sbin/"+binary, "/sbin/"+binary, "/usr/bin/"+binary)
	return exec.CommandContext(ctx, path, args...).CombinedOutput()
}

func siteRouteKey(r config.SiteLinkRoute) string {
	return r.Source + "|" + r.Destination + "|" + r.Interface + "|" + r.NextHop
}

func siteRoutePlan(saved *config.Config, p *config.SiteLinkSnapshot) ([]config.SiteLinkRoute, error) {
	unique := map[string]config.SiteLinkRoute{}
	add := func(src, dst, site string, endpoint config.SiteLinkSite) error {
		r := config.SiteLinkRoute{Source: src, Destination: dst}
		if p.NodeRole == "hub" {
			if saved.Server == nil || !saved.Server.Initialized || !siteInterface.MatchString(saved.Server.WGInterface) {
				return fmt.Errorf("site-link hub WireGuard interface is not ready")
			}
			r.Interface = saved.Server.WGInterface
		} else {
			if site != saved.AgentID {
				return nil
			}
			att, ok := siteAttachment(saved, endpoint.AttachmentID)
			if !ok {
				return fmt.Errorf("site-link attachment is not ready")
			}
			r.Interface, r.NextHop = att.WGInterface, att.VPSTunnelIP
			if _, err := edgeIPv4(r.NextHop); err != nil {
				return fmt.Errorf("site-link next hop must be IPv4")
			}
		}
		unique[siteRouteKey(r)] = r
		return nil
	}
	for _, flow := range compileSiteFlows(p) {
		if err := add(flow.source, flow.destination, flow.sourceSite.GatewayAgentID, flow.sourceSite); err != nil {
			return nil, err
		}
		if err := add(flow.destination, flow.source, flow.destinationSite.GatewayAgentID, flow.destinationSite); err != nil {
			return nil, err
		}
	}
	if len(unique) > 499 {
		return nil, fmt.Errorf("site-link route limit exceeded")
	}
	old := map[string]config.SiteLinkRoute{}
	used := map[int]bool{}
	for _, r := range saved.SiteLinkRoutes {
		old[siteRouteKey(r)] = r
		used[r.Priority] = true
	}
	var keys []string
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result []config.SiteLinkRoute
	for _, key := range keys {
		r := unique[key]
		if previous, ok := old[key]; ok {
			r.Table, r.Priority = previous.Table, previous.Priority
		} else {
			for priority := 4501; priority < 5000; priority++ {
				if !used[priority] {
					r.Priority, r.Table = priority, 60000+priority-4501
					used[priority] = true
					break
				}
			}
			if r.Priority == 0 {
				return nil, fmt.Errorf("site-link policy priority range exhausted")
			}
		}
		result = append(result, r)
	}
	return result, nil
}

func siteJSONNumber(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

func siteRulePrefix(rule map[string]any, key string) string {
	value := siteJSONNumber(rule[key])
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked().String()
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	bits := 32
	if length, exists := rule[key+"len"]; exists {
		bits, _ = strconv.Atoi(siteJSONNumber(length))
	}
	return netip.PrefixFrom(ip, bits).Masked().String()
}

func preflightSiteRoutes(ctx context.Context, old, next []config.SiteLinkRoute) error {
	out, err := siteNetworkCommand(ctx, "ip", "-4", "-N", "-j", "rule", "show")
	if err != nil {
		return fmt.Errorf("inspect site-link policy priorities: %w", err)
	}
	var rules []map[string]any
	if json.Unmarshal(out, &rules) != nil {
		return fmt.Errorf("invalid policy rule inspection")
	}
	owned := map[int]config.SiteLinkRoute{}
	for _, r := range old {
		owned[r.Priority] = r
	}
	wanted := map[int]bool{}
	for _, r := range append(append([]config.SiteLinkRoute{}, old...), next...) {
		if r.Priority < 4501 || r.Priority >= 5000 || r.Table != 60000+r.Priority-4501 || !siteInterface.MatchString(r.Interface) {
			return fmt.Errorf("invalid persisted site-link route ownership")
		}
		wanted[r.Priority] = true
	}
	for _, rule := range rules {
		priority, _ := strconv.Atoi(siteJSONNumber(rule["priority"]))
		if !wanted[priority] {
			continue
		}
		r, ok := owned[priority]
		if !ok || siteJSONNumber(rule["protocol"]) != siteRouteProtocol || siteJSONNumber(rule["table"]) != strconv.Itoa(r.Table) || siteRulePrefix(rule, "src") != r.Source || siteRulePrefix(rule, "dst") != r.Destination {
			return fmt.Errorf("site-link policy priority conflicts with another rule")
		}
	}
	checked := map[int]bool{}
	for _, r := range append(append([]config.SiteLinkRoute{}, old...), next...) {
		if checked[r.Table] {
			continue
		}
		checked[r.Table] = true
		out, err := siteNetworkCommand(ctx, "ip", "-4", "-N", "-j", "route", "show", "table", strconv.Itoa(r.Table))
		if err != nil && !strings.Contains(string(out), "FIB table does not exist") {
			return fmt.Errorf("inspect site-link route table: %w", err)
		}
		if err != nil {
			continue
		}
		var routes []map[string]any
		if json.Unmarshal(out, &routes) != nil {
			return fmt.Errorf("invalid site-link route inspection")
		}
		for _, route := range routes {
			_, known := owned[r.Priority]
			destination := siteJSONNumber(route["dst"])
			if !known || siteJSONNumber(route["protocol"]) != siteRouteProtocol || (destination != "default" && destination != r.Destination) {
				return fmt.Errorf("site-link route table conflicts with another owner")
			}
		}
	}
	return nil
}

func applySiteRoutes(ctx context.Context, old, next []config.SiteLinkRoute) error {
	keep := map[string]bool{}
	for _, r := range next {
		keep[siteRouteKey(r)] = true
		table := strconv.Itoa(r.Table)
		if _, err := siteNetworkCommand(ctx, "ip", "-4", "route", "replace", "unreachable", "default", "table", table, "proto", siteRouteProtocol); err != nil {
			return fmt.Errorf("install site-link fail-closed route: %w", err)
		}
		out, linkErr := siteNetworkCommand(ctx, "ip", "-j", "link", "show", "dev", r.Interface)
		var links []struct {
			Flags []string `json:"flags"`
		}
		_ = json.Unmarshal(out, &links)
		up := false
		if linkErr == nil && len(links) == 1 {
			for _, flag := range links[0].Flags {
				if flag == "UP" {
					up = true
				}
			}
		}
		args := []string{"-4", "route", "replace"}
		if up {
			args = append(args, r.Destination)
			if r.NextHop != "" {
				args = append(args, "via", r.NextHop)
			}
			args = append(args, "dev", r.Interface)
			if r.NextHop != "" {
				args = append(args, "onlink")
			}
		} else {
			args = append(args, "unreachable", r.Destination)
		}
		args = append(args, "table", table, "proto", siteRouteProtocol)
		if _, err := siteNetworkCommand(ctx, "ip", args...); err != nil {
			return fmt.Errorf("install site-link destination route: %w", err)
		}
		args = []string{"-4", "rule", "add", "pref", strconv.Itoa(r.Priority), "from", r.Source, "to", r.Destination, "lookup", table, "protocol", siteRouteProtocol}
		present, err := siteRulePresent(ctx, r)
		if err != nil {
			return err
		}
		if !present {
			if _, err := siteNetworkCommand(ctx, "ip", args...); err != nil {
				return fmt.Errorf("install site-link policy route: %w", err)
			}
		}
	}
	for _, r := range old {
		if keep[siteRouteKey(r)] {
			continue
		}
		if err := removeSiteRoute(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func siteRulePresent(ctx context.Context, r config.SiteLinkRoute) (bool, error) {
	out, err := siteNetworkCommand(ctx, "ip", "-4", "-N", "-j", "rule", "show")
	if err != nil {
		return false, fmt.Errorf("inspect owned site-link policy rule: %w", err)
	}
	var rules []map[string]any
	if json.Unmarshal(out, &rules) != nil {
		return false, fmt.Errorf("invalid owned site-link rule inspection")
	}
	for _, rule := range rules {
		if siteJSONNumber(rule["priority"]) != strconv.Itoa(r.Priority) {
			continue
		}
		if siteJSONNumber(rule["protocol"]) != siteRouteProtocol || siteJSONNumber(rule["table"]) != strconv.Itoa(r.Table) || siteRulePrefix(rule, "src") != r.Source || siteRulePrefix(rule, "dst") != r.Destination {
			return false, fmt.Errorf("site-link policy priority changed during apply")
		}
		return true, nil
	}
	return false, nil
}

func removeSiteRoute(ctx context.Context, r config.SiteLinkRoute) error {
	for _, args := range [][]string{
		{"-4", "rule", "del", "pref", strconv.Itoa(r.Priority), "from", r.Source, "to", r.Destination, "lookup", strconv.Itoa(r.Table), "protocol", siteRouteProtocol},
		{"-4", "route", "del", r.Destination, "table", strconv.Itoa(r.Table), "proto", siteRouteProtocol},
		{"-4", "route", "del", "unreachable", "default", "table", strconv.Itoa(r.Table), "proto", siteRouteProtocol},
	} {
		out, err := siteNetworkCommand(ctx, "ip", args...)
		if err != nil && !strings.Contains(string(out), "No such file") && !strings.Contains(string(out), "Cannot find") && !strings.Contains(string(out), "FIB table does not exist") {
			return fmt.Errorf("remove exact owned site-link route: %w", err)
		}
	}
	return nil
}
