package session

import (
    "sync"
    "time"
)

// Store holds active sessions in memory.
// It is safe for concurrent use.
// Sessions are NEVER written to disk.
type Store struct {
    mu      sync.RWMutex
    byToken map[string]*Session // keyed by hex token
    byPID   map[int]string      // PID → hex token (one-session-per-PID)
}

func NewStore() *Store {
    return &Store{
        byToken: make(map[string]*Session),
        byPID:   make(map[int]string),
    }
}

// Create generates a new session for the given PID.
// If a session already exists for this PID, the old session is invalidated first.
// Returns the new session and whether an old session was replaced.
func (s *Store) Create(pid int, binaryPath, binaryHash string) (*Session, bool) {
    s.mu.Lock()
    defer s.mu.Unlock()

    replaced := false

    // Enforce one session per PID
    if oldTokenHex, exists := s.byPID[pid]; exists {
        delete(s.byToken, oldTokenHex)
        delete(s.byPID, pid)
        replaced = true
    }

    token := GenerateToken()
    session := &Session{
        Token:      token,
        PID:        pid,
        BinaryPath: binaryPath,
        BinaryHash: binaryHash,
        CreatedAt:  time.Now(),
    }

    tokenHex := session.TokenHex()
    s.byToken[tokenHex] = session
    s.byPID[pid] = tokenHex

    return session, replaced
}

// Lookup retrieves a session by its hex token string.
// Returns nil if the token is unknown.
func (s *Store) Lookup(tokenHex string) *Session {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return s.byToken[tokenHex]
}

// Invalidate removes a session by its hex token string.
func (s *Store) Invalidate(tokenHex string) {
    s.mu.Lock()
    defer s.mu.Unlock()

    session, exists := s.byToken[tokenHex]
    if !exists {
        return
    }
    delete(s.byToken, tokenHex)
    delete(s.byPID, session.PID)
}

// Count returns the number of active sessions. For diagnostics only.
func (s *Store) Count() int {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return len(s.byToken)
}
