package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/verify"
	"github.com/spf13/cobra"
)

// DaemonIdentity is the client-neutral identity of this keychain-auth binary.
// It contains no application-specific policy. Integrators can compare it with
// the peer process observed on the socket before sending any sensitive data.
type DaemonIdentity struct {
	Version         string `json:"version"`
	BinaryHash      string `json:"binary_hash"`
	StoreMode       string `json:"store_mode"`
	ConfigPath      string `json:"config_path"`
	SocketPath      string `json:"socket_path"`
	PID             int    `json:"pid"`
	ProtocolVersion string `json:"protocol_version"`
}

func daemonIdentity() (*DaemonIdentity, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve own executable: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(self)
	if err != nil {
		return nil, fmt.Errorf("resolve own executable symlink: %w", err)
	}
	hash, err := verify.HashBinary(resolved)
	if err != nil {
		return nil, fmt.Errorf("hash own executable: %w", err)
	}

	mode := "user"
	if config.IsSystemStore() {
		mode = "system"
	}
	return &DaemonIdentity{
		Version:         daemonVersion,
		BinaryHash:      hash,
		StoreMode:       mode,
		ConfigPath:      config.ConfigPath(),
		SocketPath:      config.DefaultSocketPath(),
		PID:             os.Getpid(),
		ProtocolVersion: "1",
	}, nil
}

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Print the identity of this keychain-auth binary for client verification",
	RunE: func(cmd *cobra.Command, args []string) error {
		identity, err := daemonIdentity()
		if err != nil {
			return err
		}
		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			encoded, err := json.MarshalIndent(identity, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(encoded))
			return nil
		}
		fmt.Printf("Version:         %s\n", identity.Version)
		fmt.Printf("Binary hash:     %s\n", identity.BinaryHash)
		fmt.Printf("Store mode:      %s\n", identity.StoreMode)
		fmt.Printf("Config path:     %s\n", identity.ConfigPath)
		fmt.Printf("Socket path:     %s\n", identity.SocketPath)
		fmt.Printf("PID:             %d\n", identity.PID)
		fmt.Printf("Protocol:        %s\n", identity.ProtocolVersion)
		return nil
	},
}

func init() {
	identityCmd.Flags().Bool("json", false, "Output in JSON format")
	rootCmd.AddCommand(identityCmd)
}
