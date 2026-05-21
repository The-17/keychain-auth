package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/pending"
)

var approveCmd = &cobra.Command{
	Use:   "approve [hash] [optional path]",
	Short: "Approve a binary hash and path, creating a Zero-Trust policy",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]
		var path string

		pendingStore := pending.NewPendingStore(config.PendingPath())
		attempts, err := pendingStore.Load()
		if err != nil {
			return fmt.Errorf("failed to load pending attempts: %w", err)
		}

		if len(args) == 2 {
			absPath, err := filepath.Abs(args[1])
			if err != nil {
				return err
			}
			path = absPath
		} else {
			// Find path from pending attempts
			for _, a := range attempts {
				if a.Hash == hash {
					path = a.Path
					break
				}
			}
			if path == "" {
				return fmt.Errorf("hash %s not found in pending attempts; please specify the binary path: approve %s [path]", hash, hash)
			}
		}

		cfgPath := config.ConfigPath()
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}

		// Create Zero-Trust policy entry
		newBinary := config.RegisteredBinary{
			Path:                 path,
			Hash:                 hash,
			AllowedReadServices:  []string{},
			AllowedWriteServices: []string{},
			CanSearch:            false,
		}

		// Update or append
		found := false
		for i, rb := range cfg.RegisteredBinaries {
			if rb.Path == path {
				cfg.RegisteredBinaries[i].Hash = hash
				cfg.RegisteredBinaries[i].AllowedReadServices = []string{}
				cfg.RegisteredBinaries[i].AllowedWriteServices = []string{}
				cfg.RegisteredBinaries[i].CanSearch = false
				found = true
				break
			}
		}

		if !found {
			cfg.RegisteredBinaries = append(cfg.RegisteredBinaries, newBinary)
		}

		if err := cfg.Save(cfgPath); err != nil {
			return err
		}

		// Remove from pending store
		if err := pendingStore.Remove(hash); err != nil {
			fmt.Printf("Warning: failed to remove from pending attempts: %v\n", err)
		}

		fmt.Printf("Approved binary %s with hash %s (Zero-Trust policy created)\n", path, hash)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(approveCmd)
}
