package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/The-17/keychain-auth/internal/config"
	"github.com/spf13/cobra"
)

// LifecycleResult is the machine-readable result of ensure-running and restart.
type LifecycleResult struct {
	Running    bool   `json:"running"`
	Started    bool   `json:"started"`
	SocketPath string `json:"socket_path"`
	Version    string `json:"version"`
	Mode       string `json:"mode"`
}

var lifecycleSocket string

func resolveLifecycleSocket() string {
	if lifecycleSocket != "" {
		return lifecycleSocket
	}
	if env := os.Getenv("KEYCHAIN_AUTH_SOCKET"); env != "" {
		return env
	}
	return config.DefaultSocketPath()
}

func socketDialable(path string) bool {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func waitForSocket(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if socketDialable(path) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return socketDialable(path)
}

func systemdUnitPresent() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := os.Stat("/etc/systemd/system/keychain-auth.service")
	return err == nil
}

func startDetached(sockPath string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable: %w", err)
	}
	cmd := exec.Command(self, "start", "--socket", sockPath)
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	return nil
}

func stopByPidFile(sockPath string) error {
	data, err := os.ReadFile(sockPath + ".pid")
	if err != nil {
		return nil // no pid file means nothing to signal
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	_ = process.Signal(syscall.SIGTERM)
	for i := 0; i < 50; i++ {
		if !socketDialable(sockPath) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("daemon PID %d did not stop within 5s", pid)
}

func lifecycleResult(sockPath string, started bool) *LifecycleResult {
	mode := "user"
	if config.IsSystemStore() {
		mode = "system"
	}
	return &LifecycleResult{
		Running:    socketDialable(sockPath),
		Started:    started,
		SocketPath: sockPath,
		Version:    daemonVersion,
		Mode:       mode,
	}
}

func printLifecycle(cmd *cobra.Command, result *LifecycleResult) error {
	asJSON, _ := cmd.Flags().GetBool("json")
	if !asJSON {
		fmt.Printf("Running:    %t\nStarted:    %t\nSocket:     %s\nVersion:    %s\nMode:       %s\n",
			result.Running, result.Started, result.SocketPath, result.Version, result.Mode)
		return nil
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

var ensureRunningCmd = &cobra.Command{
	Use:   "ensure-running",
	Short: "Start the daemon if it is not already running, and report the dialable socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("ensure-running is not supported on Windows; use the Windows service manager")
		}
		sockPath := resolveLifecycleSocket()
		if socketDialable(sockPath) {
			return printLifecycle(cmd, lifecycleResult(sockPath, false))
		}
		started := false
		if systemdUnitPresent() && sockPath == config.DefaultSocketPath() {
			out, err := exec.Command("systemctl", "is-active", "--quiet", "keychain-auth").CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "" {
				if err := exec.Command("systemctl", "start", "keychain-auth").Run(); err != nil {
					return fmt.Errorf("start keychain-auth service: %w", err)
				}
				started = true
			}
		} else {
			if err := startDetached(sockPath); err != nil {
				return err
			}
			started = true
		}
		if !waitForSocket(sockPath, 5*time.Second) {
			return fmt.Errorf("daemon did not become dialable on %s", sockPath)
		}
		return printLifecycle(cmd, lifecycleResult(sockPath, started))
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the daemon and report the dialable socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS == "windows" {
			return fmt.Errorf("restart is not supported on Windows; use the Windows service manager")
		}
		sockPath := resolveLifecycleSocket()
		if systemdUnitPresent() && sockPath == config.DefaultSocketPath() {
			if err := exec.Command("systemctl", "restart", "keychain-auth").Run(); err != nil {
				return fmt.Errorf("restart keychain-auth service: %w", err)
			}
		} else {
			if err := stopByPidFile(sockPath); err != nil {
				return err
			}
			if err := startDetached(sockPath); err != nil {
				return err
			}
		}
		if !waitForSocket(sockPath, 5*time.Second) {
			return fmt.Errorf("daemon did not become dialable on %s", sockPath)
		}
		return printLifecycle(cmd, lifecycleResult(sockPath, true))
	},
}

func init() {
	for _, command := range []*cobra.Command{ensureRunningCmd, restartCmd} {
		command.Flags().Bool("json", false, "Output in JSON format")
		command.Flags().StringVar(&lifecycleSocket, "socket", "", "Socket path override")
		rootCmd.AddCommand(command)
	}
}
