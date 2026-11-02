package verify

import (
    "crypto/sha256"
    "fmt"
    "io"
    "os"
)

// HashBinary computes the SHA-256 hash of the file at the given path.
// Returns the hash in "sha256:<hex>" format.
func HashBinary(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil {
        return "", fmt.Errorf("open binary: %w", err)
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return "", fmt.Errorf("read binary: %w", err)
    }

    return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// HashBytes computes the SHA-256 of an in-memory byte slice, in the same
// "sha256:<hex>" format as HashBinary. Callers use it when the bytes have
// already been read once, so the hash and any signature verification are taken
// over the exact same content (no second read, no TOCTOU window).
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

// VerifyHash computes SHA-256 of the file at path and compares against expectedHash.
func VerifyHash(path, expectedHash string) error {
    actual, err := HashBinary(path)
    if err != nil {
        return err
    }
    if actual != expectedHash {
        return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actual)
    }
    return nil
}
