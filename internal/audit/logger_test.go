package audit_test

import (
    "encoding/json"
    "os"
    "path/filepath"
    "testing"

    "github.com/The-17/keychain-auth/internal/audit"
)

func TestAuditLogger(t *testing.T) {
    dir := t.TempDir()
    logPath := filepath.Join(dir, "audit.log")

    logger, err := audit.New(logPath)
    if err != nil {
        t.Fatalf("Failed to create logger: %v", err)
    }

    // Log an event
    err = logger.Log(audit.Event{
        EventType: "SESSION_INIT",
        PID:       123,
        Result:    "ACCEPTED",
    })
    if err != nil {
        t.Fatalf("Failed to log event: %v", err)
    }

    logger.Close()

    // Read it back
    data, err := os.ReadFile(logPath)
    if err != nil {
        t.Fatalf("Failed to read log file: %v", err)
    }

    var event audit.Event
    if err := json.Unmarshal(data, &event); err != nil {
        t.Fatalf("Failed to parse log entry: %v", err)
    }

    if event.EventType != "SESSION_INIT" || event.PID != 123 || event.Result != "ACCEPTED" {
        t.Errorf("Log entry mismatch: %+v", event)
    }
    if event.Timestamp == "" {
        t.Error("Timestamp was not populated")
    }
}
