package audit

import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"
)

// Event represents a single audit log entry.
type Event struct {
    Timestamp          string `json:"timestamp"`
    EventType          string `json:"event_type"` // e.g., SESSION_INIT, SECRET_REQUEST
    PID                int    `json:"pid,omitempty"`
    BinaryPath         string `json:"binary_path,omitempty"`
    ProjectID          string `json:"project_id,omitempty"`
    Environment        string `json:"environment,omitempty"`
    Key                string `json:"key,omitempty"`                  // The requested secret key name
    Result             string `json:"result"`                         // ACCEPTED, REJECTED, GRANTED, DENIED
    Reason             string `json:"reason,omitempty"`               // Reason for rejection/denial
    SessionTokenPrefix string `json:"session_token_prefix,omitempty"` // For correlating requests to sessions
}

// Logger provides thread-safe, append-only JSON logging.
type Logger struct {
    mu   sync.Mutex
    file *os.File
}

// New Logger creates or opens the audit log file in append mode.
func New(path string) (*Logger, error) {
    if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
        return nil, fmt.Errorf("create audit log dir: %w", err)
    }

    // O_APPEND ensures writes are atomic at the OS level (POSIX)
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
    if err != nil {
        return nil, fmt.Errorf("open audit log: %w", err)
    }

    return &Logger{file: f}, nil
}

// Log writes an event as a single JSON line.
func (l *Logger) Log(e Event) error {
    e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

    data, err := json.Marshal(e)
    if err != nil {
        return err
    }
    data = append(data, '\n')

    l.mu.Lock()
    defer l.mu.Unlock()
    _, err = l.file.Write(data)
    l.file.Sync() // Ensure immediate flush
    return err
}

func (l *Logger) Close() error {
    l.mu.Lock()
    defer l.mu.Unlock()
    return l.file.Close()
}
