package iptables

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildVpnPeerPlanSplitUsesOnlyPermissionRules(t *testing.T) {
	plan, err := buildVpnPeerPlan("10.21.0.2", false, "", []VpnRule{
		{Destination: "192.168.1.0/24", Protocol: "any"},
		{Destination: "192.168.2.20", Protocol: "tcp", PortRangeStart: 443},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"FORWARD", "-s", "10.21.0.2/32", "-d", "192.168.1.0/24", "-j", "ACCEPT"},
		{"FORWARD", "-s", "10.21.0.2/32", "-d", "192.168.2.20", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"},
	}
	if !reflect.DeepEqual(plan.acceptRules, want) {
		t.Fatalf("split accept rules:\nwant %#v\n got %#v", want, plan.acceptRules)
	}
	if len(plan.masqueradeRule) != 0 {
		t.Fatalf("split plan has masquerade rule: %#v", plan.masqueradeRule)
	}
}

func TestBuildVpnPeerPlanFullScopesInternetAcceptToWan(t *testing.T) {
	plan, err := buildVpnPeerPlan("10.21.0.3", true, "eth0", []VpnRule{
		{Destination: "192.168.1.0/24", Protocol: "any"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantWan := []string{
		"FORWARD", "-s", "10.21.0.3/32", "-o", "eth0", "-j", "ACCEPT",
	}
	if !reflect.DeepEqual(plan.acceptRules[1], wantWan) {
		t.Fatalf("WAN accept:\nwant %#v\n got %#v", wantWan, plan.acceptRules[1])
	}
	blanket := []string{"FORWARD", "-s", "10.21.0.3/32", "-j", "ACCEPT"}
	for _, rule := range plan.acceptRules {
		if reflect.DeepEqual(rule, blanket) {
			t.Fatalf("full plan contains blanket source-only ACCEPT: %#v", rule)
		}
	}
	wantMasquerade := []string{
		"-t", "nat", "POSTROUTING", "-s", "10.21.0.3/32", "-o", "eth0", "-j", "MASQUERADE",
	}
	if !reflect.DeepEqual(plan.masqueradeRule, wantMasquerade) {
		t.Fatalf("masquerade:\nwant %#v\n got %#v", wantMasquerade, plan.masqueradeRule)
	}
}

func TestBuildVpnPeerPlanFullFailsWithoutWan(t *testing.T) {
	plan, err := buildVpnPeerPlan("10.21.0.4", true, "", nil)
	if err == nil || !strings.Contains(err.Error(), "WAN interface is unavailable") {
		t.Fatalf("expected missing WAN error, got %v", err)
	}
	if len(plan.acceptRules) != 0 || len(plan.masqueradeRule) != 0 {
		t.Fatalf("missing WAN returned an open plan: %#v", plan)
	}
}

func TestVpnPeerDeleteArgsRemoveOldPermissionAndWanRules(t *testing.T) {
	filter := strings.Join([]string{
		"-A FORWARD -s 10.21.0.5/32 -d 192.168.1.20/32 -j ACCEPT",
		"-A FORWARD -s 10.21.0.5/32 -o eth0 -j ACCEPT",
		"-A FORWARD -s 10.21.0.6/32 -d 192.168.1.20/32 -j ACCEPT",
	}, "\n")
	commands := vpnPeerDeleteArgs("10.21.0.5", "filter", filter)
	if len(commands) != 2 {
		t.Fatalf("filter delete count: want 2, got %d (%#v)", len(commands), commands)
	}
	for _, command := range commands {
		joined := strings.Join(command, " ")
		if !strings.Contains(joined, "-s 10.21.0.5/32") || strings.Contains(joined, "10.21.0.6") {
			t.Fatalf("unexpected delete command: %s", joined)
		}
	}

	nat := "-A POSTROUTING -s 10.21.0.5/32 -o eth0 -j MASQUERADE"
	commands = vpnPeerDeleteArgs("10.21.0.5", "nat", nat)
	want := [][]string{{
		"-t", "nat", "-D", "POSTROUTING", "-s", "10.21.0.5/32", "-o", "eth0", "-j", "MASQUERADE",
	}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("nat delete:\nwant %#v\n got %#v", want, commands)
	}
}
