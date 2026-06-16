//go:build windows

package verify

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

type WindowsVerifier struct{}

// New creates a new WindowsVerifier.
func New() *WindowsVerifier {
	return &WindowsVerifier{}
}

// ResolveBinaryPath returns the OS-verified executable path for the given PID on Windows.
func (v *WindowsVerifier) ResolveBinaryPath(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("open process PID %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	var size uint32 = windows.MAX_PATH
	buf := make([]uint16, size)
	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return "", fmt.Errorf("query process image name for PID %d: %w", pid, err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// IsProcessAlive checks whether the given PID is still running on Windows.
func (v *WindowsVerifier) IsProcessAlive(pid int) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// If process cannot be opened because it doesn't exist
		if err == windows.ERROR_INVALID_PARAMETER {
			return false, nil
		}
		return false, nil
	}
	defer windows.CloseHandle(h)

	var exitCode uint32
	err = windows.GetExitCodeProcess(h, &exitCode)
	if err != nil {
		return false, err
	}
	return exitCode == 259, nil // 259 is STILL_ACTIVE
}

// PeerPID retrieves the process ID of the client connecting via the Windows Named Pipe.
func (v *WindowsVerifier) PeerPID(conn net.Conn) (int, error) {
	if pipeConn, ok := conn.(*PipeConn); ok {
		var pid uint32
		err := windows.GetNamedPipeClientProcessId(pipeConn.handle, &pid)
		if err != nil {
			return 0, fmt.Errorf("get named pipe client PID: %w", err)
		}
		return int(pid), nil
	}
	return 0, fmt.Errorf("connection is not a Windows named pipe")
}

// ResolveCommandLine retrieves the command line arguments of the process on Windows.
// Note: On Windows, getting command line of another process is complex and typically
// requires WMI or reading process parameters via NtQueryInformationProcess.
// For security audits, returning a single-element list with the binary path is a safe fallback.
func (v *WindowsVerifier) ResolveCommandLine(pid int) ([]string, error) {
	path, err := v.ResolveBinaryPath(pid)
	if err != nil {
		return nil, err
	}
	return []string{path}, nil
}

// PipeConn implements net.Conn for a Windows Named Pipe.
type PipeConn struct {
	handle windows.Handle
}

func NewPipeConn(h windows.Handle) *PipeConn {
	return &PipeConn{handle: h}
}

func (c *PipeConn) Read(b []byte) (int, error) {
	var done uint32
	err := windows.ReadFile(c.handle, b, &done, nil)
	if err != nil {
		if err == windows.ERROR_BROKEN_PIPE {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	return int(done), nil
}

func (c *PipeConn) Write(b []byte) (int, error) {
	var done uint32
	err := windows.WriteFile(c.handle, b, &done, nil)
	if err != nil {
		return 0, err
	}
	return int(done), nil
}

func (c *PipeConn) Close() error {
	return windows.CloseHandle(c.handle)
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func (c *PipeConn) LocalAddr() net.Addr  { return pipeAddr("keychain-auth-pipe") }
func (c *PipeConn) RemoteAddr() net.Addr { return pipeAddr("keychain-auth-pipe") }

func (c *PipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *PipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *PipeConn) SetWriteDeadline(t time.Time) error { return nil }
