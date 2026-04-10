package cli

import (
    "log"
    "os"

    "github.com/spf13/cobra"

    "github.com/The-17/keychain-auth/internal/audit"
    "github.com/The-17/keychain-auth/internal/config"
    "github.com/The-17/keychain-auth/internal/daemon"
    "github.com/The-17/keychain-auth/internal/handler"
    "github.com/The-17/keychain-auth/internal/keychain"
    "github.com/The-17/keychain-auth/internal/session"
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

        cfg, err := config.Load(config.ConfigPath())
        if err != nil {
            return err
        }

        auditLog, err := audit.New(config.AuditLogPath())
        if err != nil {
            return err
        }
        defer auditLog.Close()

        sessions := session.NewStore()
        verifier := verify.New()
        kcReader := keychain.New()

        h := handler.New(sessions, verifier, kcReader, auditLog, cfg)
        d := daemon.New(sockPath, h)

        return d.Run()
    },
}

func init() {
    startCmd.Flags().StringVarP(&socketPathOverride, "socket", "s", "", "Override socket path (default /var/run/keychain-auth/agent.sock)")
    rootCmd.AddCommand(startCmd)
}
