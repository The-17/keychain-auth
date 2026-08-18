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
	// Prefer system config if it exists and is readable by the current process
	sysFile := "/etc/keychain-auth/config.json"
	if f, err := os.Open(sysFile); err == nil {
		f.Close()
		return sysFile
	}
	if os.Getuid() == 0 {
		if _, err := os.Stat("/etc/keychain-auth"); err == nil {
			return sysFile
		}
	}

	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
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
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "share")
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
		home, _ := os.UserHomeDir()
		runtimeDir = filepath.Join(home, ".cache")
	}
	return filepath.Join(runtimeDir, "keychain-auth", "agent.sock")
}

func applyPermissions(tmpPath, targetPath string) error {
	var uid, gid int = -1, -1
	var mode os.FileMode = 0644
	if info, err := os.Stat(targetPath); err == nil {
		mode = info.Mode().Perm()
		if statT, ok := info.Sys().(*syscall.Stat_t); ok {
			uid = int(statT.Uid)
			gid = int(statT.Gid)
		}
	}

	if targetPath == "/etc/keychain-auth/config.json" {
		mode = 0644
	}

	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if uid != -1 || gid != -1 {
		_ = os.Chown(tmpPath, uid, gid)
	}
	return nil
}
