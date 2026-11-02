package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

// VerifySignature checks if the binary at exePath is signed by the trusted public key (base64-encoded).
func VerifySignature(exePath string, trustedPublicKeyBase64 string) (bool, error) {
	data, err := os.ReadFile(exePath)
	if err != nil {
		return false, fmt.Errorf("read executable: %w", err)
	}
	return VerifySignatureBytes(data, trustedPublicKeyBase64)
}

// VerifySignatureBytes verifies an embedded Ed25519 signature over an in-memory
// byte slice. The trailer is 64 bytes of signature followed by the 4-byte magic
// "KCAS"; the signed message is everything before the trailer.
//
// Callers that also hash the binary must hash the same slice, so the hash and the
// signature are taken over identical content and a file swapped between two reads
// cannot make them disagree.
func VerifySignatureBytes(data []byte, trustedPublicKeyBase64 string) (bool, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(trustedPublicKeyBase64)
	if err != nil {
		return false, fmt.Errorf("decode trusted public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)

	n := len(data)
	if n < 68 {
		return false, nil // Too small to contain a signature
	}

	// Last 4 bytes is magic "KCAS"
	if string(data[n-4:]) != "KCAS" {
		return false, nil // No signature magic
	}

	signature := data[n-68 : n-4]
	message := data[:n-68]

	return ed25519.Verify(pubKey, message, signature), nil
}
