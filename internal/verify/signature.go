package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

// VerifySignature checks if the binary at exePath is signed by the trusted public key (base64-encoded).
func VerifySignature(exePath string, trustedPublicKeyBase64 string) (bool, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(trustedPublicKeyBase64)
	if err != nil {
		return false, fmt.Errorf("decode trusted public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	data, err := os.ReadFile(exePath)
	if err != nil {
		return false, fmt.Errorf("read executable: %w", err)
	}

	n := len(data)
	if n < 68 {
		return false, nil // Too small to contain signature
	}

	// Last 4 bytes is magic "KCAS"
	magic := string(data[n-4:])
	if magic != "KCAS" {
		return false, nil // No signature magic
	}

	signature := data[n-68 : n-4]
	message := data[:n-68]

	return ed25519.Verify(pubKey, message, signature), nil
}
