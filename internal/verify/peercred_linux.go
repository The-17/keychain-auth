//go:build linux

package verify

import (
	"net"
	"syscall"
)

// PeerUID returns the effective UID of the process on the other end of a UNIX
// socket, read from SO_PEERCRED. The second return value is false when the
// credential cannot be read (for example a non-UNIX connection), which callers
// must treat as "unknown" and fail closed.
//
// This is the trust boundary for administrative actions: the kernel records the
// connecting process's credentials at connect() time, so an unprivileged process
// cannot forge them. A peer that is not root cannot act as administrator.
func PeerUID(conn net.Conn) (uint32, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, false
	}

	var ucred *syscall.Ucred
	var sysErr error
	if err := rawConn.Control(func(fd uintptr) {
		ucred, sysErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || sysErr != nil || ucred == nil {
		return 0, false
	}
	return ucred.Uid, true
}
