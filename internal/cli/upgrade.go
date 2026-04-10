package cli

import (
    "fmt"
    "path/filepath"

    "github.com/spf13/cobra"
    "github.com/The-17/keychain-auth/internal/config"
    "github.com/The-17/keychain-auth/internal/verify"
)

var upgradeCmd = &cobra.Command{
    Use:   "upgrade [path/to/agentsecrets]",
    Short: "Update the hash for an already registered binary path",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        path, err := filepath.Abs(args[0])
        if err != nil {
            return err
        }

        hash, err := verify.HashBinary(path)
        if err != nil {
            return fmt.Errorf("failed to hash binary: %w", err)
        }

        cfgPath := config.ConfigPath()
        cfg, err := config.Load(cfgPath)
        if err != nil {
            return err
        }

        found := false
        for i, rb := range cfg.RegisteredBinaries {
            if rb.Path == path {
                cfg.RegisteredBinaries[i].Hash = hash
                found = true
                break
            }
        }

        if !found {
            return fmt.Errorf("path %s is not registered. use 'register' instead", path)
        }

        if err := cfg.Save(cfgPath); err != nil {
            return err
        }

        fmt.Printf("Upgraded %s to new hash %s\n", path, hash)
        return nil
    },
}

func init() {
    rootCmd.AddCommand(upgradeCmd)
}
