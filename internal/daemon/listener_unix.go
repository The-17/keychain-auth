//go:build !windows

package daemon

import (
	"net"
	"os"
	"path/filepath"
)

func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0700)
}

func listen(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

func chmod(path string) error {
	return os.Chmod(path, 0600)
}

func removeStale(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
