package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/The-17/keychain-auth/internal/audit"
	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/daemon"
	"github.com/The-17/keychain-auth/internal/handler"
	"github.com/The-17/keychain-auth/internal/keychain"
	"github.com/The-17/keychain-auth/internal/pending"
	"github.com/The-17/keychain-auth/internal/verify"
)

var socketPathOverride string

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the keychain-auth daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		sockPath := socketPathOverride
		if sockPath == "" {
			sockPath = os.Getenv("KEYCHAIN_AUTH_SOCKET")
			if sockPath == "" {
				sockPath = config.DefaultSocketPath()
			}
		}

		// Fail-fast: validate config is loadable at startup.
		// The handler re-reads config per connection for live reload.
		if _, err := config.Load(config.ConfigPath()); err != nil {
			return err
		}

		auditLog, err := audit.New(config.AuditLogPath())
		if err != nil {
			return err
		}
		defer auditLog.Close()

		pendingStore := pending.NewPendingStore(config.PendingPath())
		verifier := verify.New()
		kcReader := keychain.New()

		h := handler.New(verifier, kcReader, auditLog, pendingStore)
		d := daemon.New(sockPath, h)

		return d.Run()
	},
}

func init() {
	startCmd.Flags().StringVarP(&socketPathOverride, "socket", "s", "", "Override socket path (default /var/run/keychain-auth/agent.sock)")
	rootCmd.AddCommand(startCmd)
}
