package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/verify"
	"github.com/spf13/cobra"
)

var authorizeCmd = &cobra.Command{
	Use:   "authorize [path/to/binary] [service-name]",
	Short: "Authorize a binary to access a specific service namespace",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		service := args[1]

		hash, err := verify.HashBinary(path)
		if err != nil {
			return fmt.Errorf("failed to hash binary: %w", err)
		}

		cfgPath := config.ConfigPath()
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}

		// Look for existing policy entry
		var policy *config.RegisteredBinary
		for i := range cfg.RegisteredBinaries {
			if cfg.RegisteredBinaries[i].Path == path {
				policy = &cfg.RegisteredBinaries[i]
				break
			}
		}

		if policy != nil {
			policy.Hash = hash
			policy.RegisteredAt = time.Now().UTC().Format(time.RFC3339)
		} else {
			newBinary := config.RegisteredBinary{
				Path:         path,
				Hash:         hash,
				RegisteredAt: time.Now().UTC().Format(time.RFC3339),
			}
			cfg.RegisteredBinaries = append(cfg.RegisteredBinaries, newBinary)
			policy = &cfg.RegisteredBinaries[len(cfg.RegisteredBinaries)-1]
		}

		// Ensure the service is in AllowedReadServices and AllowedWriteServices
		hasRead := false
		for _, s := range policy.AllowedReadServices {
			if s == service {
				hasRead = true
				break
			}
		}
		if !hasRead {
			policy.AllowedReadServices = append(policy.AllowedReadServices, service)
		}

		hasWrite := false
		for _, s := range policy.AllowedWriteServices {
			if s == service {
				hasWrite = true
				break
			}
		}
		if !hasWrite {
			policy.AllowedWriteServices = append(policy.AllowedWriteServices, service)
		}

		policy.CanSearch = true

		if err := cfg.Save(cfgPath); err != nil {
			return err
		}

		fmt.Printf("Authorized %s for service %s\n", path, service)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(authorizeCmd)
}
