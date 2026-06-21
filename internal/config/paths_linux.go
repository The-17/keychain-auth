//go:build linux

package config

import (
	"os"
	"path/filepath"
)

func ConfigPath() string {
	if ConfigPathOverride != "" {
		return ConfigPathOverride
	}
	// Check if the system-wide config exists (dedicated user mode)
	sysPath := "/etc/keychain-auth/config.json"
	if _, err := os.Stat(sysPath); err == nil {
		return sysPath
	}

	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "keychain-auth", "config.json")
}

func AuditLogPath() string {
	sysDir := "/var/lib/keychain-auth"
	if _, err := os.Stat(sysDir); err == nil {
		return filepath.Join(sysDir, "audit.log")
	}

	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		dir = filepath.Join(os.Getenv("HOME"), ".local", "share")
	}
	return filepath.Join(dir, "keychain-auth", "audit.log")
}

func DefaultSocketPath() string {
	sysPath := "/run/keychain-auth/agent.sock"
	if _, err := os.Stat(sysPath); err == nil {
		return sysPath
	}
	if _, err := os.Stat("/run/keychain-auth"); err == nil {
		return sysPath
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(runtimeDir, "keychain-auth", "agent.sock")
}
