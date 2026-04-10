package session

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "time"
)

// Session represents a verified, active session bound to a process.
type Session struct {
    Token      [32]byte  // 256-bit random token — NEVER serialise to disk
    PID        int
    BinaryPath string
    BinaryHash string    // "sha256:<hex>"
    CreatedAt  time.Time
}

// TokenHex returns the hex-encoded token string (64 characters).
func (s *Session) TokenHex() string {
    return hex.EncodeToString(s.Token[:])
}

// TokenPrefix returns the first 8 hex characters for audit logging.
func (s *Session) TokenPrefix() string {
    return s.TokenHex()[:8]
}

// GenerateToken fills a [32]byte with cryptographically random data.
// Uses crypto/rand. Panics on failure (system entropy exhaustion is unrecoverable).
func GenerateToken() [32]byte {
    var token [32]byte
    _, err := rand.Read(token[:])
    if err != nil {
        panic(fmt.Sprintf("crypto/rand failed: %v", err))
    }
    return token
}
