package verify

// Verifier validates process identity. Platform-specific implementations
// are in verify_linux.go and verify_darwin.go.
type Verifier interface {
    // ResolveBinaryPath returns the OS-verified executable path for the given PID.
    ResolveBinaryPath(pid int) (string, error)

    // IsProcessAlive checks whether the given PID is still running.
    IsProcessAlive(pid int) (bool, error)
}
