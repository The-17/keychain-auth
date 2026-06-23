//go:build linux

package config

import (
	"os"
	"path/filepath"
	"syscall"
)

func ConfigPath() string {
	if ConfigPathOverride != "" {
		return ConfigPathOverride
	}
	// Check if the system-wide config directory exists (dedicated user mode)
	sysDir := "/etc/keychain-auth"
	if _, err := os.Stat(sysDir); err == nil {
		return filepath.Join(sysDir, "config.json")
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

func applyPermissions(tmpPath, targetPath string) error {
	var uid, gid int = -1, -1
	var mode os.FileMode = 0600
	if info, err := os.Stat(targetPath); err == nil {
		mode = info.Mode().Perm()
		if statT, ok := info.Sys().(*syscall.Stat_t); ok {
			uid = int(statT.Uid)
			gid = int(statT.Gid)
		}
	}

	if targetPath == "/etc/keychain-auth/config.json" {
		mode = 0600
	}

	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if uid != -1 || gid != -1 {
		_ = os.Chown(tmpPath, uid, gid)
	}
	return nil
}
