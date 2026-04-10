package session_test

import (
    "testing"

    "github.com/The-17/keychain-auth/internal/session"
)

func TestSessionStore(t *testing.T) {
    store := session.NewStore()

    // Test Create
    sess1, replaced := store.Create(1234, "/bin/test1", "hash1")
    if replaced {
        t.Error("Expected replaced to be false for new PID")
    }
    if store.Count() != 1 {
        t.Errorf("Expected count 1, got %d", store.Count())
    }

    // Test Lookup
    token1 := sess1.TokenHex()
    lookedUp := store.Lookup(token1)
    if lookedUp == nil || lookedUp.PID != 1234 {
        t.Error("Lookup failed to find created session")
    }

    // Test Create (Replace existing)
    sess2, replaced := store.Create(1234, "/bin/test2", "hash2")
    if !replaced {
        t.Error("Expected replaced to be true when overriding PID")
    }
    if store.Count() != 1 {
        t.Errorf("Expected count 1 after replace, got %d", store.Count())
    }
    
    // Old token should be invalid
    if store.Lookup(token1) != nil {
        t.Error("Old token should have been invalidated")
    }

    // Test TokenPrefix
    if len(sess2.TokenPrefix()) != 8 {
        t.Errorf("Expected TokenPrefix length 8, got %d", len(sess2.TokenPrefix()))
    }

    // Test Invalidate
    token2 := sess2.TokenHex()
    store.Invalidate(token2)
    if store.Lookup(token2) != nil {
        t.Error("Session should be nil after Invalidate")
    }
    if store.Count() != 0 {
        t.Errorf("Expected count 0 after invalidate, got %d", store.Count())
    }
}
