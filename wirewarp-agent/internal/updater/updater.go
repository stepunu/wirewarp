package updater

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wirewarp/agent/internal/config"
	"github.com/wirewarp/agent/internal/executor"
	"github.com/wirewarp/agent/internal/firewall"
)

const BinaryURL = "https://github.com/stepunu/wirewarp/raw/main/wirewarp-agent/dist/wirewarp-agent"
const BinaryPath = "/usr/local/bin/wirewarp-agent"

type Updater struct {
	Cfg                                               *config.Config
	ConfigPath, URL, Path, RunningVersion, RunningSHA string
	HTTP                                              *http.Client
	Restart                                           func(context.Context) error
	mu                                                sync.Mutex
	restarted                                         map[string]bool
}

func New(cfg *config.Config, path, version string) *Updater {
	u := &Updater{Cfg: cfg, ConfigPath: path, URL: BinaryURL, Path: BinaryPath, RunningVersion: version, HTTP: &http.Client{Timeout: 60 * time.Second}, restarted: map[string]bool{}}
	u.RunningSHA, _, _ = InspectBinary("/proc/self/exe")
	u.Restart = func(ctx context.Context) error {
		out, err := firewall.Run(ctx, "", "systemctl", "--no-block", "restart", "wirewarp-agent")
		if err != nil {
			return fmt.Errorf("restart request failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return u
}

// InspectBinary verifies the executable and reads its embedded build version.
func InspectBinary(path string) (string, string, error) {
	e, err := elf.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("download is not an ELF executable")
	}
	e.Close()
	info, err := buildinfo.ReadFile(path)
	if err != nil || info.Path != "github.com/wirewarp/agent/cmd/agent" {
		return "", "", fmt.Errorf("download is not a WireWarp agent executable")
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != runtime.GOARCH {
		return "", "", fmt.Errorf("download has an incompatible operating system or architecture")
	}
	version := ""
	for _, field := range strings.Fields(settings["-ldflags"]) {
		if strings.HasPrefix(field, "main.version=") {
			version = strings.TrimPrefix(field, "main.version=")
		}
	}
	if !regexp.MustCompile(`^[a-f0-9]{7,40}$`).MatchString(version) {
		return "", "", fmt.Errorf("download has no valid embedded agent version")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(h.Sum(nil)), version, nil
}

func nonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func validReceipt(r *config.AgentUpdateReceipt, owner string) bool {
	return r != nil && r.OwnerAgentID == owner && owner != "" && r.CommandID != "" && regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(r.ReceiptID) && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.SHA256) && regexp.MustCompile(`^[a-f0-9]{7,40}$`).MatchString(r.Version)
}
func result(r *config.AgentUpdateReceipt) executor.Result {
	output, _ := json.Marshal(map[string]any{"installed": r.Installed, "version": r.Version, "sha256": r.SHA256, "detail": r.Detail})
	return executor.Result{Type: "command_result", CommandID: r.CommandID, ReceiptID: r.ReceiptID, Success: r.Success, Output: string(output)}
}
func (u *Updater) save(r *config.AgentUpdateReceipt) error {
	return u.Cfg.UpdateAndSave(u.ConfigPath, func(next *config.Config) error {
		if next.AgentID != r.OwnerAgentID {
			return fmt.Errorf("agent update owner changed")
		}
		copy := *r
		next.UpdateReceipt = &copy
		return nil
	})
}

func (u *Updater) fail(r *config.AgentUpdateReceipt, detail string) (executor.Result, error) {
	copy := *r
	copy.Success = false
	copy.Detail = detail
	copy.ReceiptID = nonce()
	if copy.ReceiptID == "" {
		return executor.Result{}, fmt.Errorf("create update receipt failed")
	}
	if err := u.save(&copy); err != nil {
		return executor.Result{}, fmt.Errorf("persist failed update receipt: %w", err)
	}
	v := result(&copy)
	return v, fmt.Errorf("%s", v.Output)
}

func (u *Updater) Handle(cmd executor.Command) (executor.Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	saved := u.Cfg.Snapshot()
	if saved.UpdateReceipt != nil {
		if !validReceipt(saved.UpdateReceipt, saved.AgentID) {
			return executor.Result{}, fmt.Errorf("saved update receipt belongs to another installation or is invalid")
		}
		if saved.UpdateReceipt.CommandID != cmd.ID {
			return executor.Result{}, fmt.Errorf("previous update receipt awaits controller acknowledgement")
		}
		return u.prepareLocked()
	}
	if saved.AgentID == "" || cmd.ID == "" {
		return executor.Result{}, fmt.Errorf("agent update requires a registered owner and command ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return executor.Result{}, err
	}
	resp, err := u.HTTP.Do(req)
	if err != nil {
		return executor.Result{}, fmt.Errorf("download agent binary failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return executor.Result{}, fmt.Errorf("download agent binary: HTTP %d", resp.StatusCode)
	}
	f, err := os.CreateTemp(filepath.Dir(u.Path), ".wirewarp-agent-update-*")
	if err != nil {
		return executor.Result{}, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0755); err == nil {
		var n int64
		n, err = io.Copy(f, io.LimitReader(resp.Body, 64<<20+1))
		if n > 64<<20 {
			err = fmt.Errorf("agent binary exceeds size limit")
		}
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return executor.Result{}, fmt.Errorf("stage agent binary: %w", err)
	}
	hash, version, err := InspectBinary(tmp)
	if err != nil {
		return executor.Result{}, err
	}
	r := &config.AgentUpdateReceipt{OwnerAgentID: saved.AgentID, CommandID: cmd.ID, ReceiptID: nonce(), SHA256: hash, Version: version, Success: true, Detail: "binary installation pending"}
	if !validReceipt(r, saved.AgentID) {
		return executor.Result{}, fmt.Errorf("create agent update receipt failed")
	}
	if err := u.save(r); err != nil {
		return executor.Result{}, fmt.Errorf("persist update intent: %w", err)
	}
	if err := os.Rename(tmp, u.Path); err != nil {
		return u.fail(r, "agent binary replacement failed")
	}
	dir, err := os.Open(filepath.Dir(u.Path))
	if err != nil {
		return u.fail(r, "agent binary directory open failed")
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return u.fail(r, "agent binary directory persistence failed")
	}
	actual, actualVersion, err := InspectBinary(u.Path)
	if err != nil || actual != hash || actualVersion != version {
		return u.fail(r, "installed agent binary verification failed")
	}
	r.Installed = true
	r.Detail = "binary installed; waiting for controller receipt before restart"
	if err := u.save(r); err != nil {
		return executor.Result{}, fmt.Errorf("binary replaced; persist installed receipt failed: %w", err)
	}
	return result(r), nil
}

func (u *Updater) prepareLocked() (executor.Result, error) {
	saved := u.Cfg.Snapshot()
	r := saved.UpdateReceipt
	if r == nil {
		return executor.Result{}, nil
	}
	if !validReceipt(r, saved.AgentID) {
		return executor.Result{}, fmt.Errorf("saved update receipt belongs to another installation or is invalid")
	}
	if r.Success {
		hash, version, err := InspectBinary(u.Path)
		if err != nil || hash != r.SHA256 || version != r.Version {
			return u.fail(r, "installed agent binary does not match its receipt")
		}
		if !r.Installed {
			copy := *r
			copy.Installed = true
			copy.Detail = "binary installed; recovered pending update receipt"
			if err := u.save(&copy); err != nil {
				return executor.Result{}, err
			}
			r = &copy
		}
	}
	v := result(r)
	if !r.Success {
		return v, fmt.Errorf("%s", v.Output)
	}
	return v, nil
}

func (u *Updater) PendingResult() (*executor.Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Cfg.Snapshot().UpdateReceipt == nil {
		return nil, nil
	}
	v, err := u.prepareLocked()
	if v.CommandID != "" {
		return &v, nil
	}
	return nil, err
}

// Acknowledge runs only after the server has committed the exact result.
func (u *Updater) Acknowledge(owner, commandID, receiptID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	saved := u.Cfg.Snapshot()
	r := saved.UpdateReceipt
	if r == nil || !validReceipt(r, saved.AgentID) || commandID != r.CommandID || receiptID != r.ReceiptID {
		return nil
	}
	if owner != saved.AgentID {
		return fmt.Errorf("update receipt acknowledgement identity does not match this agent")
	}
	if !r.Success || u.RunningVersion == r.Version && u.RunningSHA == r.SHA256 {
		err := u.Cfg.UpdateAndSave(u.ConfigPath, func(next *config.Config) error {
			current := next.UpdateReceipt
			if next.AgentID == owner && current != nil && current.CommandID == commandID && current.ReceiptID == receiptID {
				next.UpdateReceipt = nil
			}
			return nil
		})
		if err == nil {
			log.Printf("[update] committed receipt cleared command=%s version=%s installed=%t success=%t", commandID, r.Version, r.Installed, r.Success)
		}
		return err
	}
	if u.restarted[receiptID] {
		return nil
	}
	if _, err := u.prepareLocked(); err != nil {
		return err
	}
	u.restarted[receiptID] = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := u.Restart(ctx); err != nil {
		_, saveErr := u.fail(r, "binary installed but service restart request failed")
		if saveErr != nil {
			return fmt.Errorf("%w; %v", err, saveErr)
		}
		return err
	}
	return nil
}
