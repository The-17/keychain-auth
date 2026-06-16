//go:build darwin && !cgo

package verify

import (
	"errors"
	"net"
)

type DarwinVerifier struct{}

func New() *DarwinVerifier {
	return &DarwinVerifier{}
}

func (v *DarwinVerifier) ResolveBinaryPath(pid int) (string, error) {
	return "", errors.New("not implemented without cgo")
}

func (v *DarwinVerifier) IsProcessAlive(pid int) (bool, error) {
	return false, errors.New("not implemented without cgo")
}

func (v *DarwinVerifier) PeerPID(conn net.Conn) (int, error) {
	return 0, errors.New("not implemented without cgo")
}

func (v *DarwinVerifier) ResolveCommandLine(pid int) ([]string, error) {
	return nil, errors.New("not implemented without cgo")
}
