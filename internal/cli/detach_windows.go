//go:build windows

package cli

import (
	"fmt"
	"os"
	"os/exec"
)

func startDetached(sockPath string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable: %w", err)
	}
	cmd := exec.Command(self, "start", "--socket", sockPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	return nil
}
