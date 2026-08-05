package cli

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use:   "keychain-auth",
    Short: "keychain-auth is a security policy daemon for OS Keychain access",
    Long: `A long-running daemon that mediates access between registered binaries and the OS keychain.
It enforces identity verification and namespace isolation on every request.`,
}

// daemonVersion holds the build version, captured in Execute so subcommands
// (e.g. `status --json`) can report the running binary's version to integrators.
var daemonVersion = "dev"

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(version string) {
	daemonVersion = version
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
