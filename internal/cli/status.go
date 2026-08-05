package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/The-17/keychain-auth/internal/config"
)

type StatusInfo struct {
	DaemonRunning bool   `json:"daemon_running"`
	Version       string `json:"version"`
	Mode          string `json:"mode"`
	ConfigPath    string `json:"config_path"`
	SocketPath    string `json:"socket_path"`
	RequiresSudo  bool   `json:"requires_sudo"`
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check the status and health of the keychain-auth daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		info := StatusInfo{
			Version:    daemonVersion,
			ConfigPath: config.ConfigPath(),
			SocketPath: config.DefaultSocketPath(),
		}

		if runtime.GOOS == "linux" {
			if info.ConfigPath == "/etc/keychain-auth/config.json" {
				info.Mode = "system"
				info.RequiresSudo = true
			} else {
				info.Mode = "user"
				info.RequiresSudo = false
			}
		} else {
			info.Mode = "user"
			info.RequiresSudo = false
		}

		// Try to query daemon over socket
		conn, err := net.DialTimeout("unix", info.SocketPath, 100*time.Millisecond)
		if err == nil {
			info.DaemonRunning = true
			conn.Close()
		}

		asJson, _ := cmd.Flags().GetBool("json")
		if asJson {
			data, _ := json.MarshalIndent(info, "", "  ")
			fmt.Println(string(data))
		} else {
			daemonStr := "stopped"
			if info.DaemonRunning {
				daemonStr = "running"
			}
			fmt.Printf("Daemon:       %s\n", daemonStr)
			fmt.Printf("Version:      %s\n", info.Version)
			fmt.Printf("Mode:         %s\n", info.Mode)
			fmt.Printf("RequiresSudo: %t\n", info.RequiresSudo)
			fmt.Printf("ConfigPath:   %s\n", info.ConfigPath)
			fmt.Printf("SocketPath:   %s\n", info.SocketPath)
		}

		return nil
	},
}

func init() {
	statusCmd.Flags().Bool("json", false, "Output in JSON format")
	rootCmd.AddCommand(statusCmd)
}
