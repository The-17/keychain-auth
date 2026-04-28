//go:build darwin

package verify

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type DarwinVerifier struct{}

func New() *DarwinVerifier {
	return &DarwinVerifier{}
}

// ResolveBinaryPath finds the absolute path of the executable for a given PID on macOS.
// Uses the pure-Go unix.ProcPidPath which avoids CGO.
func (v *DarwinVerifier) ResolveBinaryPath(pid int) (string, error) {
	buf := make([]byte, unix.PROC_PIDPATHINFO_MAXSIZE)
	n, err := unix.ProcPidPath(pid, buf)
	if err != nil {
		return "", fmt.Errorf("proc_pidpath failed for pid %d: %w", pid, err)
	}

	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath returned empty path for pid %d", pid)
	}

	// unix.ProcPidPath returns the number of bytes written into the buffer
	return string(buf[:n]), nil
}

// IsProcessAlive checks if a process exists and is not a zombie.
func (v *DarwinVerifier) IsProcessAlive(pid int) (bool, error) {
	// signal 0 checks if the process exists and we have permission to talk to it
	err := unix.Kill(pid, 0)
	if err == nil {
		return true, nil
	}
	if err == unix.ESRCH {
		return false, nil
	}
	return false, err
}
