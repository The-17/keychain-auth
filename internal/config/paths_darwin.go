//go:build darwin

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
	return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "keychain-auth", "config.json")
}

func AuditLogPath() string {
	return filepath.Join(os.Getenv("HOME"), "Library", "Logs", "keychain-auth", "audit.log")
}

func DefaultSocketPath() string {
	return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "keychain-auth", "agent.sock")
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

	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if uid != -1 || gid != -1 {
		_ = os.Chown(tmpPath, uid, gid)
	}
	return nil
}
