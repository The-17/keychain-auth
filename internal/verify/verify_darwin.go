//go:build darwin

package verify

/*
#include <libproc.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

type DarwinVerifier struct{}

func New() *DarwinVerifier {
	return &DarwinVerifier{}
}

// ResolveBinaryPath finds the absolute path of the executable for a given PID on macOS.
func (v *DarwinVerifier) ResolveBinaryPath(pid int) (string, error) {
	buf := make([]C.char, C.PROC_PIDPATHINFO_MAXSIZE)
	res := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint(len(buf)))
	if res <= 0 {
		return "", fmt.Errorf("proc_pidpath failed for pid %d", pid)
	}

	return C.GoString(&buf[0]), nil
}

// IsProcessAlive checks if a process exists and is not a zombie.
func (v *DarwinVerifier) IsProcessAlive(pid int) (bool, error) {
	err := unix.Kill(pid, 0)
	if err == nil {
		return true, nil
	}
	if err == unix.ESRCH {
		return false, nil
	}
	return false, err
}

func (v *DarwinVerifier) PeerPID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("connection is not a UNIX socket")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("get syscall connection: %w", err)
	}

	var peerPID int
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		peerPID, sysErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return 0, fmt.Errorf("syscall control error: %w", err)
	}
	if sysErr != nil {
		return 0, fmt.Errorf("getsockopt local_peerpid error: %w", sysErr)
	}
	return peerPID, nil
}

func (v *DarwinVerifier) ResolveCommandLine(pid int) ([]string, error) {
	path, err := v.ResolveBinaryPath(pid)
	if err != nil {
		return nil, err
	}
	return []string{path}, nil
}
