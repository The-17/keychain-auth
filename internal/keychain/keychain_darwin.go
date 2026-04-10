//go:build darwin

package keychain

import (
    "fmt"

    gokeyring "github.com/zalando/go-keyring"
)

const serviceName = "AgentSecrets"

type DarwinReader struct{}

func New() *DarwinReader {
    return &DarwinReader{}
}

func (r *DarwinReader) Read(keychainKey string) (string, error) {
    val, err := gokeyring.Get(serviceName, keychainKey)
    if err != nil {
        return "", fmt.Errorf("secret not found: %s", keychainKey)
    }
    return val, nil
}
