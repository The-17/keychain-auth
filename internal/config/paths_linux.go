//go:build linux

package config

import (
    "os"
    "path/filepath"
)

func ConfigPath() string {
    dir := os.Getenv("XDG_CONFIG_HOME")
    if dir == "" {
        dir = filepath.Join(os.Getenv("HOME"), ".config")
    }
    return filepath.Join(dir, "keychain-auth", "config.json")
}

func AuditLogPath() string {
    dir := os.Getenv("XDG_DATA_HOME")
    if dir == "" {
        dir = filepath.Join(os.Getenv("HOME"), ".local", "share")
    }
    return filepath.Join(dir, "keychain-auth", "audit.log")
}

func DefaultSocketPath() string {
    return "/var/run/keychain-auth/agent.sock"
}
