package cli

import (
	"os"
	"strings"
	"testing"
)

func TestDaemonIdentityReportsVerifiableFacts(t *testing.T) {
	identity, err := daemonIdentity()
	if err != nil {
		t.Fatalf("daemonIdentity: %v", err)
	}
	if identity.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", identity.PID, os.Getpid())
	}
	if !strings.HasPrefix(identity.BinaryHash, "sha256:") {
		t.Errorf("BinaryHash = %q, want a sha256 digest", identity.BinaryHash)
	}
	if len(identity.BinaryHash) != len("sha256:")+64 {
		t.Errorf("BinaryHash has unexpected length %d", len(identity.BinaryHash))
	}
	if identity.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty")
	}
	if identity.SocketPath == "" || identity.ConfigPath == "" {
		t.Error("identity must report its socket and config paths")
	}
	if identity.StoreMode != "system" && identity.StoreMode != "user" {
		t.Errorf("StoreMode = %q", identity.StoreMode)
	}
}
