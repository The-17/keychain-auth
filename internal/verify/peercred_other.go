//go:build !linux

package verify

import "net"

// PeerUID is unsupported on this platform. Callers must treat ok=false as
// "unknown" and fail closed for administrative actions.
func PeerUID(conn net.Conn) (uint32, bool) {
	return 0, false
}
