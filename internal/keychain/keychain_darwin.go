//go:build darwin

package keychain

import (
	"fmt"

	gokeyring "github.com/zalando/go-keyring"

	"github.com/The-17/keychain-auth/internal/namespace"
)

type DarwinReader struct{}

func New() *DarwinReader {
	return &DarwinReader{}
}

func (r *DarwinReader) Read(keychainKey string) (string, error) {
	val, err := gokeyring.Get(namespace.ServiceName, keychainKey)
	if err != nil {
		return "", fmt.Errorf("secret not found: %s: %w", keychainKey, err)
	}
	return val, nil
}
