//go:build linux

package verify_test

import (
    "os"
    "strings"
    "testing"

    "github.com/The-17/keychain-auth/internal/verify"
)

func TestHashBinary(t *testing.T) {
    // Hash the current test executable
    exePath, err := os.Executable()
    if err != nil {
        t.Fatalf("Failed to get executable path: %v", err)
    }

    hash, err := verify.HashBinary(exePath)
    if err != nil {
        t.Fatalf("HashBinary failed: %v", err)
    }
    if !strings.HasPrefix(hash, "sha256:") || len(hash) != 71 {
        t.Errorf("Invalid hash format: %s", hash)
    }

    // Verify it
    if err := verify.VerifyHash(exePath, hash); err != nil {
        t.Errorf("VerifyHash failed on matched hash: %v", err)
    }

    if err := verify.VerifyHash(exePath, "sha256:00000000"); err == nil {
        t.Error("VerifyHash succeeded on bad hash")
    }
}

func TestLinuxVerifier(t *testing.T) {
    v := verify.New()
    pid := os.Getpid()

    path, err := v.ResolveBinaryPath(pid)
    if err != nil {
        t.Fatalf("ResolveBinaryPath failed: %v", err)
    }
    if path == "" {
        t.Error("ResolveBinaryPath returned empty path")
    }

    alive, err := v.IsProcessAlive(pid)
    if err != nil || !alive {
        t.Errorf("IsProcessAlive failed for own PID. Alive: %v Error: %v", alive, err)
    }

    // High PID that shouldn't exist
    alive, _ = v.IsProcessAlive(999999999)
    if alive {
        t.Error("IsProcessAlive returned true for non-existent PID")
    }
}
