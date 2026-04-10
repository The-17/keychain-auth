package cli

import (
    "fmt"
    "path/filepath"

    "github.com/spf13/cobra"
    "github.com/The-17/keychain-auth/internal/config"
    "github.com/The-17/keychain-auth/internal/verify"
)

var registerCmd = &cobra.Command{
    Use:   "register [path/to/agentsecrets]",
    Short: "Register a trusted AgentSecrets binary",
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

        if err := cfg.Register(path, hash); err != nil {
            return err
        }

        if err := cfg.Save(cfgPath); err != nil {
            return err
        }

        fmt.Printf("Registered %s with hash %s\n", path, hash)
        return nil
    },
}

func init() {
    rootCmd.AddCommand(registerCmd)
}
