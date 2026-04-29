package cli

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use:   "keychain-auth",
    Short: "keychain-auth is a security policy daemon for AgentSecrets",
    Long: `A long-running daemon that mediates access between AgentSecrets and the OS keychain.
It enforces identity verification and namespace isolation on every secret read.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
