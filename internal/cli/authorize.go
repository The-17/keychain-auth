package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/protocol"
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

		// Preferred: ask the daemon to write the trust store. The daemon owns the
		// store and runs as its own unprivileged user, so this needs no elevation
		// from the caller. This is the normal path for re-authorizing a binary
		// after an upgrade (the hash changed), and it is what makes registration
		// passwordless.
		if err := queryDaemonToAuthorize(path, service); err == nil {
			fmt.Printf("Authorized %s for service %s\n", path, service)
			return nil
		}

		// Fallback: direct write, used only when the daemon is not reachable (for
		// example the very first install, which runs elevated). Writing the system
		// store this way requires root; the daemon path above is the passwordless
		// one and is preferred whenever the daemon is up.
		hash, err := verify.HashBinary(path)
		if err != nil {
			return fmt.Errorf("failed to hash binary: %w", err)
		}

		cfgPath := config.ConfigPath()
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}

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
			cfg.RegisteredBinaries = append(cfg.RegisteredBinaries, config.RegisteredBinary{
				Path:         path,
				Hash:         hash,
				RegisteredAt: time.Now().UTC().Format(time.RFC3339),
			})
			policy = &cfg.RegisteredBinaries[len(cfg.RegisteredBinaries)-1]
		}

		if !containsService(policy.AllowedReadServices, service) {
			policy.AllowedReadServices = append(policy.AllowedReadServices, service)
		}
		if !containsService(policy.AllowedWriteServices, service) {
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

// queryDaemonToAuthorize asks the running daemon to write the trust-store entry.
// The daemon only honors this from the keychain-auth CLI binary, and it writes
// the store as its own user, so the caller never needs elevation.
func queryDaemonToAuthorize(path, service string) error {
	sockPath := config.DefaultSocketPath()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	dec := protocol.NewDecoder(conn)
	enc := protocol.NewEncoder(conn)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionAuthorize,
		Service: service,
		Targets: []string{path},
	}
	if err := enc.Write(req); err != nil {
		return err
	}

	raw, err := dec.ReadRaw()
	if err != nil {
		return err
	}

	var resp protocol.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	if resp.Status != "success" {
		return fmt.Errorf("daemon authorize failed: status=%s reason=%s", resp.Status, resp.Reason)
	}
	return nil
}

func containsService(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func init() {
	rootCmd.AddCommand(authorizeCmd)
}
