package protocol_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/The-17/keychain-auth/internal/protocol"
)

func TestEncodeDecodeRequest(t *testing.T) {
	var buf bytes.Buffer
	enc := protocol.NewEncoder(&buf)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionRead,
		Service: "auth-service",
		Targets: []string{"db-pass", "api-key"},
	}
	if err := enc.Write(req); err != nil {
		t.Fatalf("Failed to encode request: %v", err)
	}

	dec := protocol.NewDecoder(&buf)

	raw, err := dec.ReadRaw()
	if err != nil {
		t.Fatalf("Failed to read raw: %v", err)
	}

	var parsed protocol.Request
	if err := protocol.UnmarshalRequest(raw, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if parsed.Type != protocol.TypeRequest {
		t.Errorf("Expected type %s, got %s", protocol.TypeRequest, parsed.Type)
	}
	if parsed.Action != protocol.ActionRead {
		t.Errorf("Expected action %s, got %s", protocol.ActionRead, parsed.Action)
	}
	if parsed.Service != "auth-service" {
		t.Errorf("Expected service auth-service, got %s", parsed.Service)
	}
	if len(parsed.Targets) != 2 || parsed.Targets[0] != "db-pass" || parsed.Targets[1] != "api-key" {
		t.Errorf("Targets mismatch: %+v", parsed.Targets)
	}
}

func TestEncodeDecodeResponse(t *testing.T) {
	var buf bytes.Buffer
	enc := protocol.NewEncoder(&buf)

	resp := protocol.Response{
		Type:   protocol.TypeResponse,
		Status: "success",
		Results: []protocol.ResultItem{
			{Target: "db-pass", Value: "secret-value"},
		},
	}
	if err := enc.Write(resp); err != nil {
		t.Fatalf("Failed to encode response: %v", err)
	}

	dec := protocol.NewDecoder(&buf)
	raw, err := dec.ReadRaw()
	if err != nil {
		t.Fatalf("Failed to read raw: %v", err)
	}

	var parsed protocol.Response
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if parsed.Status != "success" || len(parsed.Results) != 1 || parsed.Results[0].Value != "secret-value" {
		t.Errorf("Response mismatch: %+v", parsed)
	}
}

func TestWriteRequestAlignmentFields(t *testing.T) {
	var buf bytes.Buffer
	enc := protocol.NewEncoder(&buf)

	req := protocol.Request{
		Type:    protocol.TypeRequest,
		Action:  protocol.ActionWrite,
		Service: "billing-service",
		Targets: []string{"key1", "key2"},
		Values:  []string{"val1", "val2"},
	}
	if err := enc.Write(req); err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	dec := protocol.NewDecoder(&buf)
	raw, err := dec.ReadRaw()
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	var parsed protocol.Request
	if err := protocol.UnmarshalRequest(raw, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(parsed.Targets) != len(parsed.Values) {
		t.Errorf("Target/Value length mismatch: %d vs %d", len(parsed.Targets), len(parsed.Values))
	}
}

func TestOversizedMessage(t *testing.T) {
	longMsg := `{"type": "` + strings.Repeat("a", 65536) + `"}` + "\n"
	dec := protocol.NewDecoder(strings.NewReader(longMsg))
	_, err := dec.ReadRaw()
	if err == nil {
		t.Fatal("Expected error for oversized message, got none")
	}
	if !strings.Contains(err.Error(), "token too long") {
		t.Errorf("Expected 'token too long' error, got: %v", err)
	}
}
