package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/protocol"
	"github.com/The-17/keychain-auth/internal/verify"
)

var checkCmd = &cobra.Command{
	Use:   "check [path/to/binary] [service-name]",
	Short: "Check if a binary is registered and authorized for a service namespace",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		service := args[1]

		// 1. Try to query the daemon over the UNIX socket first
		if ok, queryErr := queryDaemonToCheck(path, service); queryErr == nil {
			if ok {
				fmt.Printf("Binary %s is fully registered and authorized for service %s\n", path, service)
				return nil
			}
		}

		// 2. Fallback to direct config loading (for root/sudo or when daemon is stopped)
		hash, err := verify.HashBinary(path)
		if err != nil {
			return fmt.Errorf("failed to hash binary: %w", err)
		}

		cfgPath := config.ConfigPath()
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}

		policy := cfg.FindByHash(hash)
		if policy == nil {
			return fmt.Errorf("binary not registered or hash mismatch")
		}
		if policy.Path != path {
			return fmt.Errorf("binary path mismatch: expected %s, got %s", policy.Path, path)
		}

		hasRead := false
		for _, s := range policy.AllowedReadServices {
			if s == service {
				hasRead = true
				break
			}
		}
		hasWrite := false
		for _, s := range policy.AllowedWriteServices {
			if s == service {
				hasWrite = true
				break
			}
		}

		if !hasRead || !hasWrite || !policy.CanSearch {
			return fmt.Errorf("binary is registered but lacks authorized read/write/search permissions for service %s", service)
		}

		fmt.Printf("Binary %s is fully registered and authorized for service %s\n", path, service)
		return nil
	},
}

func queryDaemonToCheck(path, service string) (bool, error) {
	sockPath := config.DefaultSocketPath()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	dec := protocol.NewDecoder(conn)
	enc := protocol.NewEncoder(conn)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionType("check"),
		Service: service,
		Targets: []string{path},
	}
	if err := enc.Write(req); err != nil {
		return false, err
	}

	raw, err := dec.ReadRaw()
	if err != nil {
		return false, err
	}

	var resp protocol.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, err
	}

	if resp.Status == "success" {
		return true, nil
	}
	return false, fmt.Errorf("daemon check failed: status=%s reason=%s", resp.Status, resp.Reason)
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
