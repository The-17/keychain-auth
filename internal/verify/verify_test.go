//go:build linux

package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
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

func TestVerifySignature(t *testing.T) {
	// 1. Generate Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKey)

	// 2. Create dummy binary
	message := []byte("this is some dummy executable content that should be signed")
	
	// 3. Sign message
	signature := ed25519.Sign(privKey, message)
	if len(signature) != 64 {
		t.Fatalf("Expected signature size 64, got %d", len(signature))
	}

	// 4. Construct signed binary content: message + signature + magic
	signedData := append([]byte{}, message...)
	signedData = append(signedData, signature...)
	signedData = append(signedData, []byte("KCAS")...)

	// 5. Write to temp file
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "test_binary.exe")
	if err := os.WriteFile(exePath, signedData, 0755); err != nil {
		t.Fatalf("Failed to write signed binary: %v", err)
	}

	// 6. Verify signature
	ok, err := verify.VerifySignature(exePath, pubKeyBase64)
	if err != nil {
		t.Fatalf("VerifySignature error: %v", err)
	}
	if !ok {
		t.Error("Expected VerifySignature to return true, got false")
	}

	// 7. Verify invalid signature on modified message
	signedData[10] ^= 0xFF // corrupt a byte in the message
	corruptPath := filepath.Join(tmpDir, "corrupt_binary.exe")
	if err := os.WriteFile(corruptPath, signedData, 0755); err != nil {
		t.Fatalf("Failed to write corrupt binary: %v", err)
	}
	ok, err = verify.VerifySignature(corruptPath, pubKeyBase64)
	if err != nil {
		t.Fatalf("VerifySignature error on corrupt: %v", err)
	}
	if ok {
		t.Error("Expected VerifySignature to fail on modified message, but it succeeded")
	}

	// 8. Verify missing magic bytes
	noMagicData := append([]byte{}, message...)
	noMagicData = append(noMagicData, signature...)
	noMagicData = append(noMagicData, []byte("BAD!")...)
	noMagicPath := filepath.Join(tmpDir, "nomagic_binary.exe")
	if err := os.WriteFile(noMagicPath, noMagicData, 0755); err != nil {
		t.Fatalf("Failed to write no magic binary: %v", err)
	}
	ok, err = verify.VerifySignature(noMagicPath, pubKeyBase64)
	if err != nil {
		t.Fatalf("VerifySignature error on no magic: %v", err)
	}
	if ok {
		t.Error("Expected VerifySignature to fail on missing magic bytes, but it succeeded")
	}
}

