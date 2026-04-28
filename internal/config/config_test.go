package config_test

import (
	"path/filepath"
	"testing"

	"github.com/The-17/keychain-auth/internal/config"
)

func TestConfigLoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Load non-existent — should return empty config with defaults
	c, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load failed for non-existent file: %v", err)
	}
	if len(c.RegisteredBinaries) != 0 {
		t.Errorf("Expected empty config, got %d binaries", len(c.RegisteredBinaries))
	}
	if c.ProtocolVersion != "1" {
		t.Errorf("Expected default protocol_version '1', got %q", c.ProtocolVersion)
	}

	// Add and Save
	if err := c.Register("/bin/test", "hash1"); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if err := c.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Reload
	c2, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load failed for existing file: %v", err)
	}
	if len(c2.RegisteredBinaries) != 1 {
		t.Errorf("Expected 1 binary, got %d", len(c2.RegisteredBinaries))
	}

	rb := c2.FindByHash("hash1")
	if rb == nil || rb.Path != "/bin/test" {
		t.Error("FindByHash failed after reload")
	}

	// Replace existing path
	if err := c2.Register("/bin/test", "hash2"); err != nil {
		t.Fatalf("Register failed on existing path: %v", err)
	}
	if len(c2.RegisteredBinaries) != 1 {
		t.Errorf("Expected count to remain 1, got %d", len(c2.RegisteredBinaries))
	}
	if c2.FindByHash("hash2") == nil {
		t.Error("FindByHash failed for updated hash")
	}
}

func TestFindByHashReturnsSlicePointer(t *testing.T) {
	c := &config.Config{
		RegisteredBinaries: []config.RegisteredBinary{
			{Path: "/bin/test", Hash: "hash1"},
		},
	}

	rb := c.FindByHash("hash1")
	if rb == nil {
		t.Fatal("FindByHash returned nil")
	}

	// Mutating the returned pointer should modify the config's slice
	rb.Hash = "modified"
	if c.RegisteredBinaries[0].Hash != "modified" {
		t.Error("FindByHash returned a copy, not a pointer to the slice element")
	}
}
