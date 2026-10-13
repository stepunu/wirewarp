package updater

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
)

var executable []byte

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "wirewarp-update-fixture-*")
	if err != nil {
		panic(err)
	}
	cmd := exec.Command("go", "build", "-ldflags", "-X main.version=abcdef1", "-o", filepath.Join(dir, "agent"), "./cmd/agent")
	cmd.Dir = "../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		panic(string(out) + err.Error())
	}
	executable, err = os.ReadFile(filepath.Join(dir, "agent"))
	if err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func fixture(t *testing.T) (*Updater, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{AgentID: "owner", Mode: "client"}
	u := New(cfg, filepath.Join(dir, "agent.yaml"), "1234567")
	u.Path = filepath.Join(dir, "agent")
	if err := os.WriteFile(u.Path, []byte("old executable"), 0755); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(executable) }))
	t.Cleanup(server.Close)
	u.URL = server.URL
	count := &atomic.Int32{}
	u.Restart = func(context.Context) error { count.Add(1); return nil }
	return u, count
}

func install(t *testing.T, u *Updater) executor.Result {
	t.Helper()
	v, err := u.Handle(executor.Command{ID: "command", Type: "agent_update"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNoRestartBeforeCommittedReceipt(t *testing.T) {
	u, count := fixture(t)
	var sent executor.Result
	e := executor.New(func(v executor.Result) error {
		sent = v
		time.Sleep(750 * time.Millisecond)
		if count.Load() != 0 {
			t.Error("restart while result send was blocked")
		}
		return errors.New("connection lost")
	})
	e.RegisterCommand("agent_update", u.Handle)
	e.Dispatch(executor.Command{ID: "command", Type: "agent_update"})
	if count.Load() != 0 {
		t.Fatal("unacknowledged update restarted")
	}
	loaded, err := config.Load(u.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	r := loaded.Snapshot().UpdateReceipt
	stat, err := os.Stat(u.ConfigPath)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("receipt file is not private", err)
	}
	hash, version, err := InspectBinary(u.Path)
	if err != nil || hash != r.SHA256 || version != r.Version || !r.Installed {
		t.Fatal("receipt does not prove installed executable", err)
	}
	if err := u.Acknowledge("owner", "command", sent.ReceiptID); err != nil {
		t.Fatal(err)
	}
	if err := u.Acknowledge("owner", "command", sent.ReceiptID); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatalf("restart count=%d", count.Load())
	}
}

func TestReceiptReplaysAcrossRestartAndClearsExactACK(t *testing.T) {
	u, count := fixture(t)
	v := install(t, u)
	if err := u.Acknowledge("foreign", "command", v.ReceiptID); err == nil {
		t.Fatal("matching receipt with wrong authenticated owner did not report identity mismatch")
	}
	for _, args := range [][3]string{{"owner", "foreign", v.ReceiptID}, {"owner", "command", "bad"}, {"foreign", "foreign", "bad"}} {
		if err := u.Acknowledge(args[0], args[1], args[2]); err != nil {
			t.Fatal(err)
		}
	}
	if count.Load() != 0 || u.Cfg.Snapshot().UpdateReceipt == nil {
		t.Fatal("unbound acknowledgement changed receipt")
	}
	cfg, err := config.Load(u.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	next := New(cfg, u.ConfigPath, "abcdef1")
	next.Path = u.Path
	next.RunningSHA = cfg.Snapshot().UpdateReceipt.SHA256
	next.Restart = func(context.Context) error { t.Fatal("new process restarted again"); return nil }
	replay, err := next.PendingResult()
	if err != nil || replay.ReceiptID != v.ReceiptID || !replay.Success {
		t.Fatal("durable replay mismatch", err)
	}
	if err := next.Acknowledge("owner", "command", v.ReceiptID); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(u.ConfigPath)
	if err != nil || cfg.Snapshot().UpdateReceipt != nil {
		t.Fatal("receipt not durably cleared", err)
	}
}

func TestMissingInstalledBinaryReportsFailureWithoutRestart(t *testing.T) {
	u, count := fixture(t)
	v := install(t, u)
	if err := os.Remove(u.Path); err != nil {
		t.Fatal(err)
	}
	pending, err := u.PendingResult()
	if err != nil || pending.Success || pending.ReceiptID == v.ReceiptID {
		t.Fatal("missing binary reported success", err)
	}
	if err := u.Acknowledge("owner", "command", v.ReceiptID); err != nil {
		t.Fatal(err)
	}
	if u.Cfg.Snapshot().UpdateReceipt == nil || count.Load() != 0 {
		t.Fatal("stale ACK changed failed receipt")
	}
	if err := u.Acknowledge("owner", "command", pending.ReceiptID); err != nil {
		t.Fatal(err)
	}
	if u.Cfg.Snapshot().UpdateReceipt != nil || count.Load() != 0 {
		t.Fatal("failed receipt not cleared safely")
	}
}

func TestUpdateCrashIntentRecoveryAndDuplicateCommand(t *testing.T) {
	u, count := fixture(t)
	v := install(t, u)
	if err := u.Cfg.UpdateAndSave(u.ConfigPath, func(next *config.Config) error { next.UpdateReceipt.Installed = false; return nil }); err != nil {
		t.Fatal(err)
	}
	pending, err := u.PendingResult()
	if err != nil || !pending.Success || pending.ReceiptID != v.ReceiptID || !u.Cfg.Snapshot().UpdateReceipt.Installed {
		t.Fatal("intent recovery failed", err)
	}
	u.URL = "http://127.0.0.1:1"
	duplicate, err := u.Handle(executor.Command{ID: "command"})
	if err != nil || duplicate.ReceiptID != v.ReceiptID {
		t.Fatal("duplicate update downloaded again", err)
	}
	if _, err := u.Handle(executor.Command{ID: "new-command"}); err == nil {
		t.Fatal("new command replaced outstanding receipt")
	}
	if count.Load() != 0 {
		t.Fatal("intent recovery restarted without ACK")
	}
}

func TestRestartFailureIsDurableAndRequiresNewReceiptACK(t *testing.T) {
	u, _ := fixture(t)
	v := install(t, u)
	u.Restart = func(context.Context) error { return errors.New("systemd refused") }
	if err := u.Acknowledge("owner", "command", v.ReceiptID); err == nil {
		t.Fatal("restart error hidden")
	}
	pending, err := u.PendingResult()
	if err != nil || pending.Success || pending.ReceiptID == v.ReceiptID {
		t.Fatal("restart failure lost", err)
	}
	if err := u.Acknowledge("owner", "command", v.ReceiptID); err != nil {
		t.Fatal(err)
	}
	if u.Cfg.Snapshot().UpdateReceipt == nil {
		t.Fatal("old success ACK cleared new failure")
	}
}

func TestRejectInvalidDownloadAndPersistenceFailureBeforeReplacement(t *testing.T) {
	for _, kind := range []string{"invalid-binary", "persist-failure"} {
		t.Run(kind, func(t *testing.T) {
			u, count := fixture(t)
			if kind == "invalid-binary" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not an agent")) }))
				defer server.Close()
				u.URL = server.URL
			} else {
				u.ConfigPath = filepath.Join(u.Path, "impossible.yaml")
			}
			if _, err := u.Handle(executor.Command{ID: "command"}); err == nil {
				t.Fatal("invalid update accepted")
			}
			data, err := os.ReadFile(u.Path)
			if err != nil || string(data) != "old executable" || count.Load() != 0 || u.Cfg.Snapshot().UpdateReceipt != nil {
				t.Fatal("failed update changed installation", err)
			}
		})
	}
}

func TestReceiptOwnerMismatchFailsClosed(t *testing.T) {
	u, count := fixture(t)
	install(t, u)
	if err := u.Cfg.UpdateAndSave(u.ConfigPath, func(next *config.Config) error { next.AgentID = "another"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := u.PendingResult(); err == nil {
		t.Fatal("receipt rebound to another node")
	}
	if count.Load() != 0 || u.Cfg.Snapshot().UpdateReceipt.OwnerAgentID != "owner" {
		t.Fatal("mismatch changed owned state")
	}
}
