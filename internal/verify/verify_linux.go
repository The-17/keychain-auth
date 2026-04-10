//go:build linux

package verify

import (
    "fmt"
    "os"
)

type LinuxVerifier struct{}

func New() *LinuxVerifier {
    return &LinuxVerifier{}
}

func (v *LinuxVerifier) ResolveBinaryPath(pid int) (string, error) {
    exePath := fmt.Sprintf("/proc/%d/exe", pid)
    resolved, err := os.Readlink(exePath)
    if err != nil {
        return "", fmt.Errorf("cannot resolve exe for PID %d: %w", pid, err)
    }
    return resolved, nil
}

func (v *LinuxVerifier) IsProcessAlive(pid int) (bool, error) {
    exePath := fmt.Sprintf("/proc/%d/exe", pid)
    _, err := os.Readlink(exePath)
    if err != nil {
        if os.IsNotExist(err) {
            return false, nil
        }
        return false, fmt.Errorf("check PID %d liveness: %w", pid, err)
    }
    return true, nil
}
