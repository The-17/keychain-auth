//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// ConfigPath returns the path to the keychain-auth config.json file on Windows.
func ConfigPath() string {
	if ConfigPathOverride != "" {
		return ConfigPathOverride
	}
	dir := os.Getenv("APPDATA")
	if dir == "" {
		dir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
	}
	return filepath.Join(dir, "keychain-auth", "config.json")
}

// AuditLogPath returns the path to the keychain-auth audit.log file on Windows.
func AuditLogPath() string {
	dir := os.Getenv("LOCALAPPDATA")
	if dir == "" {
		dir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	return filepath.Join(dir, "keychain-auth", "audit.log")
}

// DefaultSocketPath returns the default named pipe path for Windows.
func DefaultSocketPath() string {
	return `\\.\pipe\keychain-auth`
}
