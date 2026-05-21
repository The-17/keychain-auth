//go:build linux

package verify

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
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

func (v *LinuxVerifier) PeerPID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("connection is not a UNIX socket")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("get syscall connection: %w", err)
	}

	var ucred *syscall.Ucred
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		ucred, sysErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, fmt.Errorf("syscall control error: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("getsockopt peercred error: %w", sysErr)
	}
	return int(ucred.Pid), nil
}

func (v *LinuxVerifier) ResolveCommandLine(pid int) ([]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, fmt.Errorf("read cmdline for PID %d: %w", pid, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	parts := strings.Split(string(data), "\x00")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts, nil
}
