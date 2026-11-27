package cli

import (
	"net"
	"path/filepath"
	"testing"
)

func TestSocketDialableTracksLiveListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	if socketDialable(path) {
		t.Fatal("a socket that does not exist must not be dialable")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if !socketDialable(path) {
		t.Fatal("a live listener must be dialable")
	}
	listener.Close()
	if socketDialable(path) {
		t.Fatal("a closed listener must not be dialable")
	}
}

func TestLifecycleResultReportsRequestedSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	result := lifecycleResult(path, false)
	if result.SocketPath != path {
		t.Errorf("SocketPath = %q", result.SocketPath)
	}
	if result.Running {
		t.Error("a socket that does not exist must not be reported as running")
	}
}
