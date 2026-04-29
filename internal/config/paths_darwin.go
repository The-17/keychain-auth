//go:build darwin

package config

import (
    "os"
    "path/filepath"
)

func ConfigPath() string {
    return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "keychain-auth", "config.json")
}

func AuditLogPath() string {
    return filepath.Join(os.Getenv("HOME"), "Library", "Logs", "keychain-auth", "audit.log")
}

func DefaultSocketPath() string {
    return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "keychain-auth", "agent.sock")
}
