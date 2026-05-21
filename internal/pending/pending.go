package pending

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const pendingTTL = 24 * time.Hour

type PendingAttempt struct {
	Path        string    `json:"path"`
	Hash        string    `json:"hash"`
	CommandLine []string  `json:"command_line"`
	Timestamp   time.Time `json:"timestamp"`
}

type PendingStore struct {
	mu   sync.Mutex
	path string
}

func NewPendingStore(path string) *PendingStore {
	return &PendingStore{path: path}
}

// Load retrieves all pending attempts, pruning those older than the TTL.
func (s *PendingStore) Load() ([]PendingAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.loadUnlocked()
}

func (s *PendingStore) loadUnlocked() ([]PendingAttempt, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []PendingAttempt{}, nil
		}
		return nil, fmt.Errorf("read pending attempts: %w", err)
	}

	var attempts []PendingAttempt
	if err := json.Unmarshal(data, &attempts); err != nil {
		return nil, fmt.Errorf("parse pending attempts: %w", err)
	}

	// Prune expired
	now := time.Now()
	var active []PendingAttempt
	changed := false
	for _, a := range attempts {
		if now.Sub(a.Timestamp) < pendingTTL {
			active = append(active, a)
		} else {
			changed = true
		}
	}

	if changed {
		if err := s.saveUnlocked(active); err != nil {
			return nil, fmt.Errorf("prune pending attempts: %w", err)
		}
	}

	return active, nil
}

// Add logs a new unregistered binary verification attempt.
// If an attempt with the same hash already exists, it updates the timestamp and command line.
func (s *PendingStore) Add(path, hash string, cmdLine []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempts, err := s.loadUnlocked()
	if err != nil {
		return err
	}

	now := time.Now()
	updated := false
	for i, a := range attempts {
		if a.Hash == hash {
			attempts[i].Path = path
			attempts[i].CommandLine = cmdLine
			attempts[i].Timestamp = now
			updated = true
			break
		}
	}

	if !updated {
		attempts = append(attempts, PendingAttempt{
			Path:        path,
			Hash:        hash,
			CommandLine: cmdLine,
			Timestamp:   now,
		})
	}

	// Re-prune on add just in case
	var active []PendingAttempt
	for _, a := range attempts {
		if now.Sub(a.Timestamp) < pendingTTL {
			active = append(active, a)
		}
	}

	return s.saveUnlocked(active)
}

// Remove deletes a pending attempt by its hash.
func (s *PendingStore) Remove(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempts, err := s.loadUnlocked()
	if err != nil {
		return err
	}

	var active []PendingAttempt
	for _, a := range attempts {
		if a.Hash != hash {
			active = append(active, a)
		}
	}

	return s.saveUnlocked(active)
}


func (s *PendingStore) saveUnlocked(attempts []PendingAttempt) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("create pending dir: %w", err)
	}

	data, err := json.MarshalIndent(attempts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal pending: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write tmp pending: %w", err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename pending: %w", err)
	}
	return nil
}
