package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/The-17/keychain-auth/internal/audit"
	"github.com/The-17/keychain-auth/internal/config"
	"github.com/The-17/keychain-auth/internal/handler"
	"github.com/The-17/keychain-auth/internal/pending"
	"github.com/The-17/keychain-auth/internal/protocol"
	"github.com/The-17/keychain-auth/internal/verify"
)

// --- Mock Verifier ---

type mockVerifier struct {
	binaryPath string
	resolveErr error
	alive      bool
	aliveErr   error
	peerPID    int
	peerErr    error
	cmdLine    []string
	cmdLineErr error
}

func (m *mockVerifier) ResolveBinaryPath(pid int) (string, error) {
	return m.binaryPath, m.resolveErr
}

func (m *mockVerifier) IsProcessAlive(pid int) (bool, error) {
	return m.alive, m.aliveErr
}

func (m *mockVerifier) PeerPID(conn net.Conn) (int, error) {
	return m.peerPID, m.peerErr
}

func (m *mockVerifier) ResolveCommandLine(pid int) ([]string, error) {
	return m.cmdLine, m.cmdLineErr
}

// --- Mock Keychain ---

type mockKeychain struct {
	secrets map[string]string   // service:target -> value
	search  map[string][]string // service -> targets
}

func (m *mockKeychain) Read(service, target string) (string, error) {
	val, ok := m.secrets[service+":"+target]
	if !ok {
		return "", fmt.Errorf("secret not found")
	}
	return val, nil
}

func (m *mockKeychain) Write(service, target, value string) error {
	m.secrets[service+":"+target] = value
	return nil
}

func (m *mockKeychain) Delete(service, target string) error {
	key := service + ":" + target
	if _, ok := m.secrets[key]; !ok {
		return fmt.Errorf("secret not found")
	}
	delete(m.secrets, key)
	return nil
}

func (m *mockKeychain) Search(service string) ([]string, error) {
	return m.search[service], nil
}

// --- Test Helpers ---

func newTestHandler(
	t *testing.T,
	v *mockVerifier,
	kc *mockKeychain,
	allowedRead []string,
	allowedWrite []string,
	canSearch bool,
) (*handler.Handler, *audit.Logger, *pending.PendingStore, string, string) {
	t.Helper()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	auditLog, err := audit.New(logPath)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	pendingPath := filepath.Join(dir, "pending.json")
	pendingStore := pending.NewPendingStore(pendingPath)

	// Write dummy binary content so hashing works
	dummyBin := filepath.Join(dir, "dummy_bin")
	if err := os.WriteFile(dummyBin, []byte("some binary content"), 0755); err != nil {
		t.Fatalf("Failed to write dummy binary: %v", err)
	}
	v.binaryPath = dummyBin

	hash, err := verify.HashBinary(dummyBin)
	if err != nil {
		t.Fatalf("Failed to hash binary: %v", err)
	}

	cfg := &config.Config{
		RegisteredBinaries: []config.RegisteredBinary{
			{
				Path:                 dummyBin,
				Hash:                 hash,
				AllowedReadServices:  allowedRead,
				AllowedWriteServices: allowedWrite,
				CanSearch:            canSearch,
			},
		},
		ProtocolVersion: "1",
	}

	cfgPath := filepath.Join(dir, "config.json")
	config.ConfigPathOverride = cfgPath
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	h := handler.New(v, kc, auditLog, pendingStore)
	return h, auditLog, pendingStore, logPath, pendingPath
}

func socketPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	clientDone := make(chan net.Conn, 1)
	go func() {
		c, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Errorf("Dial failed: %v", err)
			return
		}
		clientDone <- c
	}()

	srv, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	l.Close()

	return <-clientDone, srv
}

func sendJSON(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}

func readJSON(conn net.Conn, v any) error {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes.TrimSpace(buf[:n]), v)
}

// --- Tests ---

func TestHandler_UnregisteredBinary(t *testing.T) {
	v := &mockVerifier{
		peerPID: 1234,
		cmdLine: []string{"./dummy_bin", "--arg"},
	}
	kc := &mockKeychain{}

	h, auditLog, _, logPath, pendingPath := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, false)
	defer auditLog.Close()

	// Point verifier path to a different dummy file so it doesn't match config
	dir := t.TempDir()
	unregisteredBin := filepath.Join(dir, "unregistered")
	_ = os.WriteFile(unregisteredBin, []byte("unregistered content"), 0755)
	v.binaryPath = unregisteredBin

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	// Try reading response directly after connection setup
	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.Status != "denied" || resp.Reason != protocol.ReasonUnregisteredBinaryPendingApproval {
		t.Errorf("Expected registration rejection, got: %+v", resp)
	}

	// Verify attempt logged to pending.json
	data, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatalf("Failed to read pending file: %v", err)
	}
	if !strings.Contains(string(data), "unregistered") {
		t.Error("Pending file does not contain unregistered path")
	}

	// Verify audit log has connect denied
	auditLog.Close()
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read audit log: %v", err)
	}
	if !strings.Contains(string(logData), "connect") || !strings.Contains(string(logData), "DENIED") {
		t.Error("Audit log does not record connect DENIED")
	}
}

func TestHandler_PathMismatch(t *testing.T) {
	v := &mockVerifier{
		peerPID: 1234,
	}
	kc := &mockKeychain{}

	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, false)
	defer auditLog.Close()

	// Configure handler normally, but during execution return a path that mismatch
	// of the actual registered path.
	dir := t.TempDir()
	otherBin := filepath.Join(dir, "other_bin")
	_ = os.WriteFile(otherBin, []byte("some binary content"), 0755) // same content/hash but different path
	v.binaryPath = otherBin

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.Status != "denied" || resp.Reason != protocol.ReasonUnregisteredBinaryPendingApproval {
		t.Errorf("Expected path mismatch rejection, got: %+v", resp)
	}
}

func TestHandler_BatchRead_Success(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{
		secrets: map[string]string{
			"auth-service:user-db": "secret-pw-1",
			"auth-service:api-key": "secret-key-2",
		},
	}

	h, auditLog, _, logPath, _ := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	// Send Batch Read Request
	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionRead,
		Service: "auth-service",
		Targets: []string{"user-db", "api-key"},
	}
	if err := sendJSON(client, req); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	var resp protocol.Response
	if err := readJSON(client, &resp); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if resp.Status != "success" || len(resp.Results) != 2 {
		t.Fatalf("Expected success with 2 results, got: %+v", resp)
	}

	if resp.Results[0].Target != "user-db" || resp.Results[0].Value != "secret-pw-1" {
		t.Errorf("Result 0 mismatch: %+v", resp.Results[0])
	}
	if resp.Results[1].Target != "api-key" || resp.Results[1].Value != "secret-key-2" {
		t.Errorf("Result 1 mismatch: %+v", resp.Results[1])
	}

	// Verify audit log has read GRANTED
	auditLog.Close()
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "read") || !strings.Contains(string(logData), "GRANTED") {
		t.Error("Audit log does not record read GRANTED")
	}
}

func TestHandler_BatchRead_PolicyDenied(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{
		secrets: map[string]string{
			"billing-service:stripe-key": "billing-secret",
		},
	}

	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionRead,
		Service: "billing-service",
		Targets: []string{"stripe-key"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "denied" || resp.Reason != protocol.ReasonServiceNotAllowed {
		t.Errorf("Expected policy denial, got: %+v", resp)
	}
}

func TestHandler_BatchWrite_Success(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{
		secrets: map[string]string{},
	}

	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{}, []string{"auth-service"}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionWrite,
		Service: "auth-service",
		Targets: []string{"db-pass", "jwt-sig"},
		Values:  []string{"db-value", "jwt-value"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "success" {
		t.Fatalf("Expected success, got: %+v", resp)
	}

	if kc.secrets["auth-service:db-pass"] != "db-value" || kc.secrets["auth-service:jwt-sig"] != "jwt-value" {
		t.Errorf("Secrets not written to mock keychain: %+v", kc.secrets)
	}
}

func TestHandler_BatchWrite_AlignmentCheck(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{}

	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{}, []string{"auth-service"}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionWrite,
		Service: "auth-service",
		Targets: []string{"db-pass"},
		Values:  []string{}, // Mismatched length
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "error" || resp.Reason != protocol.ReasonMalformedRequest {
		t.Errorf("Expected malformed request error, got: %+v", resp)
	}
}

func TestHandler_Search_Success(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{
		search: map[string][]string{
			"auth-service": {"proj_123:production:api-key", "proj_456:development:db-pass", "proj_123:production:secret"},
		},
	}

	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, true)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	// 1. Search everything (empty Targets)
	reqAll := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionSearch,
		Service: "auth-service",
	}
	if err := sendJSON(client, reqAll); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	var respAll protocol.Response
	if err := readJSON(client, &respAll); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if respAll.Status != "success" || len(respAll.Results) != 3 {
		t.Fatalf("Expected 3 search results, got: %+v", respAll)
	}

	// 2. Search with prefix filter
	reqFilter := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionSearch,
		Service: "auth-service",
		Targets: []string{"proj_123:production:"},
	}
	if err := sendJSON(client, reqFilter); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	var respFilter protocol.Response
	if err := readJSON(client, &respFilter); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if respFilter.Status != "success" || len(respFilter.Results) != 2 {
		t.Fatalf("Expected 2 filtered search results, got: %+v", respFilter)
	}

	if respFilter.Results[0].Target != "proj_123:production:api-key" || respFilter.Results[1].Target != "proj_123:production:secret" {
		t.Errorf("Filtered results mismatch: %+v", respFilter.Results)
	}
}

func TestHandler_Search_Denied(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{}

	// CanSearch set to false
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionSearch,
		Service: "auth-service",
		Targets: []string{"dummy"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "denied" || resp.Reason != protocol.ReasonActionNotInPolicy {
		t.Errorf("Expected action denied for search, got: %+v", resp)
	}
}

func TestHandler_Delete_Success(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{
		secrets: map[string]string{
			"auth-service:user-db": "val",
		},
	}

	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{}, []string{"auth-service"}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionDelete,
		Service: "auth-service",
		Targets: []string{"user-db"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "success" {
		t.Fatalf("Expected success, got: %+v", resp)
	}

	if _, ok := kc.secrets["auth-service:user-db"]; ok {
		t.Error("Secret was not deleted")
	}
}

func TestHandler_Read_Prefix_Success(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{
		secrets: map[string]string{
			"auth-service:proj:prod:key1": "val1",
			"auth-service:proj:prod:key2": "val2",
			"auth-service:proj:dev:key3":  "val3",
		},
		search: map[string][]string{
			"auth-service": {
				"proj:prod:key1",
				"proj:prod:key2",
				"proj:dev:key3",
			},
		},
	}

	// For prefix read, CanSearch must be true
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, true)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionRead,
		Service: "auth-service",
		Match:   protocol.MatchPrefix,
		Targets: []string{"proj:prod:"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "success" {
		t.Fatalf("Expected success, got: %+v", resp)
	}

	if len(resp.Results) != 2 {
		t.Fatalf("Expected 2 results, got: %d", len(resp.Results))
	}

	resultsMap := make(map[string]string)
	for _, res := range resp.Results {
		resultsMap[res.Target] = res.Value
	}

	if resultsMap["proj:prod:key1"] != "val1" || resultsMap["proj:prod:key2"] != "val2" {
		t.Errorf("Unexpected results: %+v", resp.Results)
	}
}

func TestHandler_Read_Prefix_Denied(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{}

	// CanSearch = false, should deny prefix read
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{"auth-service"}, []string{}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionRead,
		Service: "auth-service",
		Match:   protocol.MatchPrefix,
		Targets: []string{"proj:"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "denied" || resp.Reason != protocol.ReasonActionNotInPolicy {
		t.Errorf("Expected ActionNotInPolicy (CanSearch=false denied), got: %+v", resp)
	}
}

func TestHandler_Delete_Prefix_Success(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{
		secrets: map[string]string{
			"auth-service:proj:prod:key1": "val1",
			"auth-service:proj:prod:key2": "val2",
			"auth-service:proj:dev:key3":  "val3",
		},
		search: map[string][]string{
			"auth-service": {
				"proj:prod:key1",
				"proj:prod:key2",
				"proj:dev:key3",
			},
		},
	}

	// For prefix delete, AllowedWriteServices must contain service AND CanSearch must be true
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{}, []string{"auth-service"}, true)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionDelete,
		Service: "auth-service",
		Match:   protocol.MatchPrefix,
		Targets: []string{"proj:prod:"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "success" {
		t.Fatalf("Expected success, got: %+v", resp)
	}

	if _, ok := kc.secrets["auth-service:proj:prod:key1"]; ok {
		t.Error("key1 was not deleted")
	}
	if _, ok := kc.secrets["auth-service:proj:prod:key2"]; ok {
		t.Error("key2 was not deleted")
	}
	if _, ok := kc.secrets["auth-service:proj:dev:key3"]; !ok {
		t.Error("key3 (dev) was deleted unexpectedly")
	}
}

func TestHandler_Delete_Prefix_Denied(t *testing.T) {
	v := &mockVerifier{peerPID: 1234}
	kc := &mockKeychain{}

	// CanSearch = false, should deny prefix delete
	h, auditLog, _, _, _ := newTestHandler(t, v, kc, []string{}, []string{"auth-service"}, false)
	defer auditLog.Close()

	client, server := socketPair(t)
	defer client.Close()

	go h.Handle(server)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionDelete,
		Service: "auth-service",
		Match:   protocol.MatchPrefix,
		Targets: []string{"proj:"},
	}
	sendJSON(client, req)

	var resp protocol.Response
	readJSON(client, &resp)

	if resp.Status != "denied" || resp.Reason != protocol.ReasonActionNotInPolicy {
		t.Errorf("Expected ActionNotInPolicy (CanSearch=false denied), got: %+v", resp)
	}
}

