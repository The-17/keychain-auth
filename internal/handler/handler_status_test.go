package handler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/The-17/keychain-auth/internal/protocol"
)

func TestStatusIsAvailableBeforeRegistration(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{}
	h, auditLog, _, _, pendingPath := newTestHandler(t, v, kc, []string{"svc-test"}, []string{"svc-test"}, false)
	defer auditLog.Close()
	h.DaemonVersion = "4.0.2-test"

	unregistered := filepath.Join(t.TempDir(), "unregistered")
	if err := os.WriteFile(unregistered, []byte("other bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	v.binaryPath = unregistered

	client, server := socketPair(t)
	defer client.Close()
	go h.Handle(server)

	if err := sendJSON(client, protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionStatus,
		Service: "svc-test",
	}); err != nil {
		t.Fatal(err)
	}
	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("status response: %v", err)
	}
	if resp.Status != "success" {
		t.Fatalf("status = %+v", resp)
	}
	if resp.Registered {
		t.Error("unregistered peer reported registered")
	}
	if resp.HashCurrent {
		t.Error("unregistered peer reported hash_current")
	}
	if resp.ProtocolVersion != protocol.Version {
		t.Errorf("protocol version = %q", resp.ProtocolVersion)
	}
	if resp.DaemonVersion != "4.0.2-test" {
		t.Errorf("daemon version = %q", resp.DaemonVersion)
	}

	data, err := os.ReadFile(pendingPath)
	if err == nil && len(data) != 0 {
		t.Errorf("a status request must not create a pending approval entry: %s", data)
	}
}

func TestStatusForRegisteredPeer(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{}
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"svc-test"}, []string{"svc-write"}, true)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()
	go h.Handle(server)

	if err := sendJSON(client, protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionStatus,
		Service: "svc-test",
	}); err != nil {
		t.Fatal(err)
	}
	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("status response: %v", err)
	}
	if !resp.Registered || !resp.HashCurrent {
		t.Errorf("registered peer status = %+v", resp)
	}
	found := false
	for _, service := range resp.AllowedServices {
		if service == "svc-test" {
			found = true
		}
	}
	if !found {
		t.Errorf("allowed services = %v, want svc-test", resp.AllowedServices)
	}
}
