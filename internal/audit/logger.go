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
	Timestamp  string   `json:"timestamp"`
	Action     string   `json:"action"` // e.g. connect, read, write, delete, search
	PID        int      `json:"pid"`
	BinaryPath string   `json:"binary_path"`
	BinaryHash string   `json:"binary_hash"`
	Service    string   `json:"service,omitempty"`
	Targets    []string `json:"targets,omitempty"`
	Result     string   `json:"result"`           // GRANTED, DENIED, ERROR, ACCEPTED
	Reason     string   `json:"reason,omitempty"`
}

// Logger provides thread-safe, append-only JSON logging.
// Writes are buffered by the OS via O_APPEND. No per-write fsync —
// the audit log prioritises low latency over crash-proof durability.
// The OS will flush on its own schedule, and we flush explicitly on Close.
type Logger struct {
	mu   sync.Mutex
	file *os.File
}

// New creates or opens the audit log file in append mode.
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
// Returns an error if the write fails — callers should handle this.
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
	// No Sync() — O_APPEND provides atomic writes, OS buffers handle flush.
	// This avoids the fsync latency penalty on every secret request.
	return err
}

// Close flushes pending data and closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.file.Sync() // Final flush on shutdown only
	return l.file.Close()
}
