package verify

import "net"

// Verifier validates process identity. Platform-specific implementations
// are in verify_linux.go and verify_darwin.go.
type Verifier interface {
	// ResolveBinaryPath returns the OS-verified executable path for the given PID.
	ResolveBinaryPath(pid int) (string, error)

	// IsProcessAlive checks whether the given PID is still running.
	IsProcessAlive(pid int) (bool, error)

	// PeerPID retrieves the process ID of the other end of the local socket connection.
	PeerPID(conn net.Conn) (int, error)

	// ResolveCommandLine retrieves the command line arguments of the process.
	ResolveCommandLine(pid int) ([]string, error)
}
