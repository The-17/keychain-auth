package keychain_test

import (
    "testing"

    "github.com/The-17/keychain-auth/internal/keychain"
)

func TestKeychainReader(t *testing.T) {
    // Note: This relies on either go-keyring or file fallback.
    // In CI environments without dbus/file, it might fail.
    // The implementation handles fallback, but we'll just test instantiation.
    reader := keychain.New()
    if reader == nil {
        t.Fatal("Expected non-nil Reader")
    }

    // Reading a non-existent key should fail cleanly
    _, err := reader.Read("non-existent-key")
    if err == nil {
        t.Fatal("Expected error when reading non-existent key, got nil")
    }
}
