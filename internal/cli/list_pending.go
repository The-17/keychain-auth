package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/pending"
)

var listPendingCmd = &cobra.Command{
	Use:   "list-pending",
	Short: "List binaries currently waiting for authorization",
	RunE: func(cmd *cobra.Command, args []string) error {
		pendingStore := pending.NewPendingStore(config.PendingPath())
		attempts, err := pendingStore.Load()
		if err != nil {
			return fmt.Errorf("failed to load pending attempts: %w", err)
		}

		if len(attempts) == 0 {
			fmt.Println("No pending binaries waiting for authorization.")
			return nil
		}

		fmt.Printf("Found %d pending binaries waiting for authorization:\n\n", len(attempts))
		for _, a := range attempts {
			fmt.Printf("Path:       %s\n", a.Path)
			fmt.Printf("Hash:       %s\n", a.Hash)
			fmt.Printf("Command:    %s\n", strings.Join(a.CommandLine, " "))
			fmt.Printf("Attempted:  %s\n", a.Timestamp.Local().Format(time.RFC3339))
			fmt.Println(strings.Repeat("-", 60))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listPendingCmd)
}
