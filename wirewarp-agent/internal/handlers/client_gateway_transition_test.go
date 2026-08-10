package handlers

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/wireguard"
)

func TestCleanupGatewayRoleTransitionUsesOldRulesAndReplayIsIdempotent(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "iptables.log")
	iptablesPath := filepath.Join(binDir, "iptables")
	if err := os.WriteFile(iptablesPath, []byte(`#!/bin/sh
printf '%s\n' "$*" >> "$IPTABLES_LOG"
exit 1
`), 0755); err != nil {
		t.Fatalf("write iptables stub: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("IPTABLES_LOG", logPath)

	old := config.AttachmentState{
		AttachmentID: "attachment-1",
		WGInterface:  "wg1",
		LANIface:     "eth9",
		IsGateway:    true,
	}
	next := old
	next.LANIface = "eth0"
	next.IsGateway = false
	h := &ClientHandlers{cfg: &config.Config{Attachments: []config.AttachmentState{old}}}

	if err := h.cleanupGatewayRoleTransition(&next); err != nil {
		t.Fatalf("clean up gateway role transition: %v", err)
	}
	if !h.cfg.Attachments[0].IsGateway {
		t.Fatal("cleanup mutated saved attachment before replacement succeeded")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read iptables log: %v", err)
	}
	want := strings.Join([]string{
		"-C DOCKER-USER -i wg1 -o eth9 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i eth9 -o wg1 -m comment --comment wirewarp-gateway-docker-user -j ACCEPT",
		"-C DOCKER-USER -i wg1 -o eth9 -j ACCEPT",
		"-C DOCKER-USER -i eth9 -o wg1 -j ACCEPT",
	}, "\n")
	if strings.TrimSpace(string(data)) != want {
		t.Fatalf("transition cleanup calls\nwant %q\n got %q", want, strings.TrimSpace(string(data)))
	}

	h.cfg.UpsertAttachment(next)
	if err := h.cleanupGatewayRoleTransition(&next); err != nil {
		t.Fatalf("replay plain-client attachment: %v", err)
	}
	afterReplay, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read replay log: %v", err)
	}
	if string(afterReplay) != string(data) {
		t.Fatalf("plain-client replay repeated role cleanup:\n%s", afterReplay)
	}
}

func TestRollbackWGAttachConfigRestoresGatewayStateBeforeRouting(t *testing.T) {
	old := config.AttachmentState{
		AttachmentID: "attachment-1",
		WGInterface:  "wg1",
		LANIface:     "eth0",
		IsGateway:    true,
	}
	demoted := old
	demoted.IsGateway = false
	h := &ClientHandlers{cfg: &config.Config{Attachments: []config.AttachmentState{demoted}}}
	routingRestored := false

	err := h.rollbackWGAttachConfig([]config.AttachmentState{old}, func() error {
		routingRestored = true
		if !h.cfg.Attachments[0].IsGateway {
			t.Fatal("old attachment state was not restored before routing")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("rollback attachment config: %v", err)
	}
	if !routingRestored || !h.cfg.Attachments[0].IsGateway {
		t.Fatalf("gateway demotion rollback did not restore old state: %#v", h.cfg.Attachments)
	}
}

func TestSaveWGAttachIPTablesReturnsPersistenceFailure(t *testing.T) {
	binDir := t.TempDir()
	netfilterPath := filepath.Join(binDir, "netfilter-persistent")
	if err := os.WriteFile(netfilterPath, []byte("#!/bin/sh\necho save-failed\nexit 2\n"), 0755); err != nil {
		t.Fatalf("write netfilter-persistent stub: %v", err)
	}
	t.Setenv("PATH", binDir)

	err := saveWGAttachIPTables()
	if err == nil || !strings.Contains(err.Error(), "save-failed") {
		t.Fatalf("expected iptables persistence failure, got %v", err)
	}
}

func TestBringWGAttachFailureRestoresOldRoutingAfterFailure(t *testing.T) {
	var order []string
	bringErr := errors.New("bring failed")
	client, err := bringWGAttachWithRollback(
		func() (*wireguard.Client, error) {
			order = append(order, "bring")
			return nil, bringErr
		},
		func() error {
			order = append(order, "restore old routing")
			return nil
		},
	)
	if client != nil {
		t.Fatalf("failed bring returned a client: %#v", client)
	}
	if !errors.Is(err, bringErr) || !strings.Contains(err.Error(), "previous attachment routing restored") {
		t.Fatalf("expected bring failure with restored routing, got %v", err)
	}
	want := []string{"bring", "restore old routing"}
	if len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Fatalf("rollback order: want %#v, got %#v", want, order)
	}
}

func TestBringWGAttachFailureReportsRoutingRollbackFailure(t *testing.T) {
	bringErr := errors.New("bring failed")
	rollbackErr := errors.New("routing restore failed")
	_, err := bringWGAttachWithRollback(
		func() (*wireguard.Client, error) { return nil, bringErr },
		func() error { return rollbackErr },
	)
	if !errors.Is(err, bringErr) || !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(err.Error(), rollbackErr.Error()) {
		t.Fatalf("expected original and rollback failure context, got %v", err)
	}
}
