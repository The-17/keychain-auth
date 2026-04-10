package protocol_test

import (
    "bytes"
    "strings"
    "testing"

    "github.com/The-17/keychain-auth/internal/protocol"
)

func TestEncodeDecodeParse(t *testing.T) {
    var buf bytes.Buffer
    enc := protocol.NewEncoder(&buf)
    
    // Test 1: SessionInit
    initMsg := protocol.SessionInit{
        Type:            protocol.TypeSessionInit,
        PID:             1234,
        BinaryPath:      "/bin/test",
        BinaryHash:      "sha256:abc",
        ProtocolVersion: "1",
    }
    if err := enc.Write(initMsg); err != nil {
        t.Fatalf("Failed to encode: %v", err)
    }

    // Test 2: SecretRequest
    reqMsg := protocol.SecretRequest{
        Type:         protocol.TypeSecretRequest,
        SessionToken: "token123",
        ProjectID:    "proj1",
        Environment:  "development",
        Key:          "test_key",
    }
    if err := enc.Write(reqMsg); err != nil {
        t.Fatalf("Failed to encode: %v", err)
    }

    dec := protocol.NewDecoder(&buf)
    
    // Read 1
    raw1, err := dec.ReadRaw()
    if err != nil {
        t.Fatalf("Failed to read raw: %v", err)
    }
    
    msgType, parsed1, err := protocol.ParseMessage(raw1)
    if err != nil {
        t.Fatalf("Failed to parse: %v", err)
    }
    if msgType != protocol.TypeSessionInit {
        t.Errorf("Expected type %s, got %s", protocol.TypeSessionInit, msgType)
    }
    p1 := parsed1.(*protocol.SessionInit)
    if p1.PID != 1234 || p1.ProtocolVersion != "1" {
        t.Errorf("Parsed message fields mismatch")
    }

    // Read 2
    raw2, err := dec.ReadRaw()
    if err != nil {
        t.Fatalf("Failed to read raw: %v", err)
    }
    
    msgType2, parsed2, err := protocol.ParseMessage(raw2)
    if err != nil {
        t.Fatalf("Failed to parse: %v", err)
    }
    if msgType2 != protocol.TypeSecretRequest {
        t.Errorf("Expected type %s, got %s", protocol.TypeSecretRequest, msgType2)
    }
    p2 := parsed2.(*protocol.SecretRequest)
    if p2.ProjectID != "proj1" || p2.Environment != "development" || p2.Key != "test_key" {
        t.Errorf("Parsed SecretRequest fields mismatch")
    }
}

func TestValidationErrors(t *testing.T) {
    tests := []struct {
        name     string
        raw      string
        wantType protocol.MessageType
        wantErr  string
    }{
        {
            name:     "Malformed JSON",
            raw:      `{"type": "`,
            wantType: "",
            wantErr:  "malformed JSON",
        },
        {
            name:     "Unknown Type",
            raw:      `{"type": "UNKNOWN_MSG"}`,
            wantType: "UNKNOWN_MSG",
            wantErr:  "unknown message type",
        },
        {
            name:     "Bad SessionInit (wrong types)",
            raw:      `{"type": "SESSION_INIT", "pid": "should-be-int"}`,
            wantType: protocol.TypeSessionInit,
            wantErr:  "invalid SESSION_INIT",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            msgType, _, err := protocol.ParseMessage([]byte(tt.raw))
            if err == nil {
                t.Fatalf("Expected error, got none")
            }
            if msgType != tt.wantType {
                t.Errorf("Expected type %q, got %q", tt.wantType, msgType)
            }
            if !strings.Contains(err.Error(), tt.wantErr) {
                t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
            }
        })
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
