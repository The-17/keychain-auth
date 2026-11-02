package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var ConfigPathOverride string

type RegisteredBinary struct {
	Path                 string   `json:"path"`
	Hash                 string   `json:"hash"`
	RegisteredAt         string   `json:"registered_at"`
	AllowedReadServices  []string `json:"allowed_read_services"`
	AllowedWriteServices []string `json:"allowed_write_services"`
	CanSearch            bool     `json:"can_search"`
}

type TrustedSigner struct {
	Service   string `json:"service"`
	PublicKey string `json:"public_key"` // Base64 Ed25519 Public Key
}

type Config struct {
	RegisteredBinaries []RegisteredBinary `json:"registered_binaries"`
	ProtocolVersion    string             `json:"protocol_version,omitempty"`
	TrustedSigners     []TrustedSigner    `json:"trusted_signers,omitempty"`
}

// Load reads the config file from disk. If it doesn't exist, returns an empty config.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{
				RegisteredBinaries: []RegisteredBinary{},
				ProtocolVersion:    "1",
			}, nil
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &c, nil
}

// Save writes the config to disk atomically via write-rename.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Write-rename pattern for atomic updates
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}

	if err := applyPermissions(tmp, path); err != nil {
		// Log or ignore warning, do not block save unless critical
	}

	return os.Rename(tmp, path)
}

func (c *Config) Register(path, hash string) error {
	for i, rb := range c.RegisteredBinaries {
		if rb.Path == path {
			// A changed hash is a different binary. Never silently carry the old
			// binary's service grants over to a new hash: otherwise a process
			// could overwrite a trusted binary, re-register it, and inherit its
			// access. Reset to Zero Trust; the operator must re-authorize the new
			// binary explicitly. An unchanged hash is an idempotent no-op.
			if rb.Hash != hash {
				c.RegisteredBinaries[i].Hash = hash
				c.RegisteredBinaries[i].RegisteredAt = time.Now().UTC().Format(time.RFC3339)
				c.RegisteredBinaries[i].AllowedReadServices = []string{}
				c.RegisteredBinaries[i].AllowedWriteServices = []string{}
				c.RegisteredBinaries[i].CanSearch = false
			}
			return nil
		}
	}
	
	// Maximally restrictive default (Zero Trust)
	c.RegisteredBinaries = append(c.RegisteredBinaries, RegisteredBinary{
		Path:                 path,
		Hash:                 hash,
		RegisteredAt:         time.Now().UTC().Format(time.RFC3339),
		AllowedReadServices:  []string{},
		AllowedWriteServices: []string{},
		CanSearch:            false,
	})
	return nil
}

// FindByHash returns a pointer to the registered binary with the given hash.
// Returns nil if no match is found.
func (c *Config) FindByHash(hash string) *RegisteredBinary {
	for i := range c.RegisteredBinaries {
		if c.RegisteredBinaries[i].Hash == hash {
			return &c.RegisteredBinaries[i]
		}
	}
	return nil
}

func PendingPath() string {
	return filepath.Join(filepath.Dir(ConfigPath()), "pending.json")
}

// IsSystemStore reports whether the active trust store is the system-wide one
// under /etc. On a system store the daemon runs as its own unprivileged user, so
// administrative actions (authorize) must come from root. On a user-mode store
// the daemon runs as the user who owns it, and that user is the trust root.
func IsSystemStore() bool {
	return ConfigPath() == "/etc/keychain-auth/config.json"
}
