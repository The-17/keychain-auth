package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/The-17/keychain-auth/install"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install system-wide keychain-auth sandbox configurations (requires sudo/root, Linux-only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("system installation is only supported on Linux")
		}

		if os.Geteuid() != 0 {
			return fmt.Errorf("this command must be run as root (e.g. sudo keychain-auth install)")
		}

		// Write the embedded install.sh script to a temporary file
		tmpFile := filepath.Join(os.TempDir(), "kca-install.sh")
		if err := os.WriteFile(tmpFile, []byte(install.InstallScript), 0700); err != nil {
			return fmt.Errorf("failed to write temporary install script: %w", err)
		}
		defer os.Remove(tmpFile)

		// Run the script
		runCmd := exec.Command("/bin/bash", tmpFile)
		runCmd.Stdout = os.Stdout
		runCmd.Stderr = os.Stderr
		
		// If running from a build/repo folder, set Dir to the binary's folder
		// so that install.sh can locate the local keychain-auth binary to copy.
		selfPath, err := os.Executable()
		if err == nil {
			selfPath, err = filepath.EvalSymlinks(selfPath)
			if err == nil {
				runCmd.Dir = filepath.Dir(selfPath)
			}
		}

		if err := runCmd.Run(); err != nil {
			return fmt.Errorf("installation script failed: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
}
