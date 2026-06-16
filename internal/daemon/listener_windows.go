//go:build windows

package daemon

import (
	"net"

	"github.com/The-17/keychain-auth/internal/verify"
	"golang.org/x/sys/windows"
)

type PipeListener struct {
	pipePath string
}

func ensureDir(path string) error {
	return nil
}

// Accept waits for and returns the next connection to the listener.
func (l *PipeListener) Accept() (net.Conn, error) {
	h, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(l.pipePath),
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		1024,
		1024,
		0,
		nil,
	)
	if err != nil {
		return nil, err
	}

	err = windows.ConnectNamedPipe(h, nil)
	if err != nil {
		if err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(h)
			return nil, err
		}
	}

	return verify.NewPipeConn(h), nil
}

// Close closes the listener.
func (l *PipeListener) Close() error {
	return nil
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

// Addr returns the listener's network address.
func (l *PipeListener) Addr() net.Addr {
	return pipeAddr(l.pipePath)
}

func listen(path string) (net.Listener, error) {
	return &PipeListener{pipePath: path}, nil
}

func chmod(path string) error {
	return nil
}

func removeStale(path string) error {
	return nil
}
