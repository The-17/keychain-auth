//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigPathUsesUnreadableSystemStore pins the reporting fix: a system
// install is identified by the presence of its trust store, not by whether this
// process may read it. The store is 0600 and daemon-owned, so an unprivileged
// CLI can stat it but cannot open it. Before this fix ConfigPath fell back to
// the user path, so `status` reported mode "user" on a system install and
// `doctor` validated the wrong file's permissions.
func TestConfigPathUsesUnreadableSystemStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000 file, so the unreadable case cannot be reproduced")
	}

	dir := t.TempDir()
	store := filepath.Join(dir, "config.json")
	if err := os.WriteFile(store, []byte(`{"registered_binaries":[]}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	// Present but unreadable by its owner: os.Stat succeeds, os.Open fails.
	if err := os.Chmod(store, 0o000); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(store, 0o600) })

	// Guard the premise: the file really is unreadable, or this test proves nothing.
	if f, err := os.Open(store); err == nil {
		f.Close()
		t.Fatal("fixture is readable; the regression case is not being exercised")
	}

	prevSystem := SystemConfigPath
	prevOverride := ConfigPathOverride
	SystemConfigPath = store
	ConfigPathOverride = ""
	t.Cleanup(func() {
		SystemConfigPath = prevSystem
		ConfigPathOverride = prevOverride
	})

	if got := ConfigPath(); got != store {
		t.Fatalf("ConfigPath() = %q, want the system store %q", got, store)
	}
	if !IsSystemStore() {
		t.Fatal("IsSystemStore() = false for a present system store")
	}
}

// TestConfigPathFallsBackWhenNoSystemStore keeps the user-mode path working: no
// system install means the per-user store, unchanged.
func TestConfigPathFallsBackWhenNoSystemStore(t *testing.T) {
	prevSystem := SystemConfigPath
	prevOverride := ConfigPathOverride
	SystemConfigPath = filepath.Join(t.TempDir(), "absent", "config.json")
	ConfigPathOverride = ""
	t.Cleanup(func() {
		SystemConfigPath = prevSystem
		ConfigPathOverride = prevOverride
	})

	got := ConfigPath()
	if got == SystemConfigPath {
		t.Fatalf("ConfigPath() returned the absent system store %q", got)
	}
	if IsSystemStore() {
		t.Fatal("IsSystemStore() = true with no system store present")
	}
}
