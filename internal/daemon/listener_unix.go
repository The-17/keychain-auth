//go:build !windows

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

func ensureDir(path string) error {
	// If socket is in system directory, don't use 0700 if it already exists.
	// The installer will set correct permissions for /run/keychain-auth.
	if strings.Contains(path, "/run/keychain-auth") {
		return os.MkdirAll(filepath.Dir(path), 0775)
	}
	return os.MkdirAll(filepath.Dir(path), 0700)
}

func listen(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

func chmod(path string) error {
	// If running under the dedicated system user (socket in /run/keychain-auth),
	// use 0660 to allow the agentgroup to write to it.
	if strings.Contains(path, "/run/keychain-auth") {
		return os.Chmod(path, 0660)
	}
	return os.Chmod(path, 0600)
}

func removeStale(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
