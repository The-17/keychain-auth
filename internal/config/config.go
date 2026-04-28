package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RegisteredBinary struct {
	Path         string `json:"path"`
	Hash         string `json:"hash"`
	RegisteredAt string `json:"registered_at"`
}

type Config struct {
	RegisteredBinaries []RegisteredBinary `json:"registered_binaries"`
	ProtocolVersion    string             `json:"protocol_version,omitempty"`
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
	return os.Rename(tmp, path)
}

func (c *Config) Register(path, hash string) error {
	for i, rb := range c.RegisteredBinaries {
		if rb.Path == path {
			c.RegisteredBinaries[i].Hash = hash
			c.RegisteredBinaries[i].RegisteredAt = time.Now().UTC().Format(time.RFC3339)
			return nil
		}
	}
	c.RegisteredBinaries = append(c.RegisteredBinaries, RegisteredBinary{
		Path:         path,
		Hash:         hash,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
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
