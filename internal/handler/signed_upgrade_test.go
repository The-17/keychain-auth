package handler_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/The-17/keychain-auth/internal/audit"
	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/handler"
	"github.com/The-17/keychain-auth/internal/pending"
	"github.com/The-17/keychain-auth/internal/protocol"
	"github.com/The-17/keychain-auth/internal/verify"
)

// signBinary returns content with an Ed25519 signature and the KCAS trailer, in
// the exact format verify.VerifySignatureBytes expects.
func signBinary(t *testing.T, priv ed25519.PrivateKey, content []byte) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, content)
	out := append([]byte{}, content...)
	out = append(out, sig...)
	out = append(out, []byte("KCAS")...)
	return out
}

func newHandlerWithConfig(t *testing.T, v *mockVerifier, kc *mockKeychain, cfg *config.Config) *handler.Handler {
	t.Helper()
	dir := t.TempDir()
	auditLog, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	pendingStore := pending.NewPendingStore(filepath.Join(dir, "pending.json"))
	cfgPath := filepath.Join(dir, "config.json")
	config.ConfigPathOverride = cfgPath
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return handler.New(v, kc, auditLog, pendingStore)
}

// expectDenied sends a read and asserts the connection was rejected before it was
// authorized.
func expectDenied(t *testing.T, h *handler.Handler) {
	t.Helper()
	client, server := socketPair(t)
	defer client.Close()
	go h.Handle(server)

	_ = sendJSON(client, protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionRead,
		Service: "AgentSecrets",
		Targets: []string{"k"},
	})
	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Status != "denied" {
		t.Fatalf("status = %q reason = %q, want denied", resp.Status, resp.Reason)
	}
}

func TestSignedBinaryNewPathIsDenied(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	newPath := filepath.Join(dir, "signed-new-path")
	if err := os.WriteFile(newPath, signBinary(t, priv, []byte("signed binary content for a brand new path, long enough to hold a trailer")), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		RegisteredBinaries: []config.RegisteredBinary{{
			Path:                 "/opt/somewhere-else",
			Hash:                 "sha256:deadbeef",
			AllowedReadServices:  []string{"AgentSecrets"},
			AllowedWriteServices: []string{"AgentSecrets"},
			CanSearch:            true,
		}},
		TrustedSigners: []config.TrustedSigner{{Service: "AgentSecrets", PublicKey: base64.StdEncoding.EncodeToString(pub)}},
	}
	v := &mockVerifier{binaryPath: newPath}
	kc := &mockKeychain{secrets: map[string]string{"AgentSecrets:k": "secret"}, search: map[string][]string{}}
	h := newHandlerWithConfig(t, v, kc, cfg)

	expectDenied(t, h)

	// The new path must NOT have been registered by the signature.
	reloaded, err := config.Load(config.ConfigPathOverride)
	if err != nil {
		t.Fatal(err)
	}
	for _, rb := range reloaded.RegisteredBinaries {
		if rb.Path == newPath {
			t.Fatalf("signed binary at a new path was auto-registered: %+v", rb)
		}
	}
}

func TestSignedBinaryRollbackIsDenied(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := filepath.Join(dir, "agentsecrets")
	oldBytes := signBinary(t, priv, []byte("the old, still-validly-signed binary content, long enough for a trailer"))
	if err := os.WriteFile(path, oldBytes, 0755); err != nil {
		t.Fatal(err)
	}
	oldHash := hashOf(t, oldBytes)

	cfg := &config.Config{
		RegisteredBinaries: []config.RegisteredBinary{{
			Path:                 path,
			Hash:                 "sha256:currentnewer",
			AllowedReadServices:  []string{"AgentSecrets"},
			AllowedWriteServices: []string{"AgentSecrets"},
			CanSearch:            true,
		}},
		TrustedSigners:   []config.TrustedSigner{{Service: "AgentSecrets", PublicKey: base64.StdEncoding.EncodeToString(pub)}},
		SupersededHashes: []string{oldHash},
	}
	v := &mockVerifier{binaryPath: path}
	kc := &mockKeychain{secrets: map[string]string{"AgentSecrets:k": "secret"}, search: map[string][]string{}}
	h := newHandlerWithConfig(t, v, kc, cfg)

	expectDenied(t, h)
}

func TestSignedBinaryCrossServiceIsDenied(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := filepath.Join(dir, "agentsecrets")
	if err := os.WriteFile(path, signBinary(t, priv, []byte("signed content long enough to carry a signature trailer here")), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		RegisteredBinaries: []config.RegisteredBinary{{
			Path:                 path,
			Hash:                 "sha256:oldhash",
			AllowedReadServices:  []string{"AgentSecrets"},
			AllowedWriteServices: []string{"AgentSecrets"},
			CanSearch:            true,
		}},
		// The signer is trusted for a DIFFERENT service, so it must not upgrade a
		// binary that is registered for AgentSecrets.
		TrustedSigners: []config.TrustedSigner{{Service: "SomeOtherService", PublicKey: base64.StdEncoding.EncodeToString(pub)}},
	}
	v := &mockVerifier{binaryPath: path}
	kc := &mockKeychain{secrets: map[string]string{"AgentSecrets:k": "secret"}, search: map[string][]string{}}
	h := newHandlerWithConfig(t, v, kc, cfg)

	expectDenied(t, h)
}

func TestSignedBinaryUpgradeIsAllowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := filepath.Join(dir, "agentsecrets")
	newBytes := signBinary(t, priv, []byte("the new signed binary content, long enough to carry a signature trailer"))
	if err := os.WriteFile(path, newBytes, 0755); err != nil {
		t.Fatal(err)
	}
	newHash := hashOf(t, newBytes)

	cfg := &config.Config{
		RegisteredBinaries: []config.RegisteredBinary{{
			Path:                 path,
			Hash:                 "sha256:oldhash",
			AllowedReadServices:  []string{"AgentSecrets"},
			AllowedWriteServices: []string{"AgentSecrets"},
			CanSearch:            true,
		}},
		TrustedSigners: []config.TrustedSigner{{Service: "AgentSecrets", PublicKey: base64.StdEncoding.EncodeToString(pub)}},
	}
	v := &mockVerifier{binaryPath: path}
	kc := &mockKeychain{secrets: map[string]string{"AgentSecrets:k": "secret"}, search: map[string][]string{}}
	h := newHandlerWithConfig(t, v, kc, cfg)

	client, server := socketPair(t)
	defer client.Close()
	go h.Handle(server)

	if err := sendJSON(client, protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionRead,
		Service: "AgentSecrets",
		Targets: []string{"k"},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Status != "success" {
		t.Fatalf("status = %q reason = %q, want success", resp.Status, resp.Reason)
	}

	reloaded, err := config.Load(config.ConfigPathOverride)
	if err != nil {
		t.Fatal(err)
	}
	var got *config.RegisteredBinary
	for i := range reloaded.RegisteredBinaries {
		if reloaded.RegisteredBinaries[i].Path == path {
			got = &reloaded.RegisteredBinaries[i]
		}
	}
	if got == nil || got.Hash != newHash {
		t.Fatalf("policy hash not updated to the new signed hash: %+v", got)
	}
	if !reloaded.IsSuperseded("sha256:oldhash") {
		t.Fatalf("old hash was not recorded as superseded: %+v", reloaded.SupersededHashes)
	}
}

func hashOf(t *testing.T, b []byte) string {
	t.Helper()
	// Use the same helper the daemon uses so the format matches exactly.
	return verify.HashBytes(b)
}
