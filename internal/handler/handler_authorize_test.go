package handler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/protocol"
	"github.com/The-17/keychain-auth/internal/verify"
)

// TestAuthorizeRejectedForNonCLI proves a random registered binary cannot write
// the trust store: the authorize action is gated on the caller being the
// keychain-auth CLI, so a compromised registered binary cannot authorize a
// malicious one.
func TestAuthorizeRejectedForNonCLI(t *testing.T) {
	v := &mockVerifier{peerPID: 1234, cmdLine: []string{"./dummy_bin"}}
	kc := &mockKeychain{}
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"agentsecrets"}, []string{"agentsecrets"}, true)
	defer auditLog.Close()

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target binary"), 0755); err != nil {
		t.Fatalf("write target: %v", err)
	}

	client, server := socketPair(t)
	defer client.Close()
	go h.Handle(server)

	if err := sendJSON(client, protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionAuthorize,
		Service: "agentsecrets",
		Targets: []string{target},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Status != "denied" || resp.Reason != protocol.ReasonActionNotInPolicy {
		t.Fatalf("authorize from non-CLI = %+v, want denied/action_not_in_policy", resp)
	}
}

// TestAuthorizeByCLIWritesStore proves the CLI can authorize a target and the
// daemon persists it to the trust store, with read+write+search granted.
func TestAuthorizeByCLIWritesStore(t *testing.T) {
	v := &mockVerifier{peerPID: 1234, cmdLine: []string{"keychain-auth", "authorize"}}
	kc := &mockKeychain{}
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"agentsecrets"}, []string{"agentsecrets"}, true)
	defer auditLog.Close()

	// Make the caller look like the CLI binary so isCLIBinary passes.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	v.binaryPath = self

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target binary content"), 0755); err != nil {
		t.Fatalf("write target: %v", err)
	}
	targetHash, err := verify.HashBinary(target)
	if err != nil {
		t.Fatalf("hash target: %v", err)
	}

	client, server := socketPair(t)
	defer client.Close()
	go h.Handle(server)

	if err := sendJSON(client, protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionAuthorize,
		Service: "agentsecrets",
		Targets: []string{target},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Status != "success" {
		t.Fatalf("authorize by CLI = %+v, want success", resp)
	}

	cfg, err := config.Load(config.ConfigPathOverride)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	var found *config.RegisteredBinary
	for i := range cfg.RegisteredBinaries {
		if cfg.RegisteredBinaries[i].Path == target {
			found = &cfg.RegisteredBinaries[i]
		}
	}
	if found == nil {
		t.Fatal("target was not written to the trust store")
	}
	if found.Hash != targetHash {
		t.Errorf("hash = %s, want %s", found.Hash, targetHash)
	}
	if !containsStr(found.AllowedReadServices, "agentsecrets") ||
		!containsStr(found.AllowedWriteServices, "agentsecrets") ||
		!found.CanSearch {
		t.Errorf("policy not granted: %+v", found)
	}
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
