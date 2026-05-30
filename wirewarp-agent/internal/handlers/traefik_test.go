package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteYAMLReplacesExistingFileAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wirewarp.yml")
	if err := os.WriteFile(path, []byte("previous: true\n"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	before := inodeOf(t, path)

	if err := writeYAML(path, map[string]any{"http": map[string]any{"routers": map[string]any{}}}); err != nil {
		t.Fatalf("writeYAML: %v", err)
	}

	after := inodeOf(t, path)
	if after == before {
		t.Fatalf("writeYAML should replace the file inode so Traefik never reads a truncated watched file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.Contains(string(data), "http:") || strings.Contains(string(data), "previous") {
		t.Fatalf("unexpected YAML output:\n%s", string(data))
	}
}

func TestAtomicTempDirIsOutsideWatchedTargetDir(t *testing.T) {
	path := "/etc/traefik/dynamic/wirewarp.yml"
	if got := atomicTempDir(path); got != "/etc/traefik" {
		t.Fatalf("atomic temp dir: want /etc/traefik, got %s", got)
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s did not return syscall.Stat_t", path)
	}
	return stat.Ino
}
