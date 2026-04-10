//go:build linux

package keychain

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "runtime"

    gokeyring "github.com/zalando/go-keyring"
)

const serviceName = "AgentSecrets"

// LinuxReader reads secrets from the same backend AgentSecrets uses.
// On systems with D-Bus Secret Service: uses go-keyring.
// On WSL / headless Linux: falls back to ~/.agentsecrets/keyring.json.
type LinuxReader struct {
    useFileBackend bool
}

func New() *LinuxReader {
    r := &LinuxReader{}

    // Mirror AgentSecrets' detection logic exactly
    if runtime.GOOS == "linux" {
        if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("DISPLAY") == "" {
            r.useFileBackend = true
            return r
        }

        // Test if keyring actually works
        testKey := "__keychain_auth_keyring_test__"
        if err := gokeyring.Set(serviceName, testKey, "test"); err != nil {
            r.useFileBackend = true
        } else {
            _ = gokeyring.Delete(serviceName, testKey)
        }
    }

    return r
}

func (r *LinuxReader) Read(keychainKey string) (string, error) {
    if r.useFileBackend {
        return r.fileRead(keychainKey)
    }

    val, err := gokeyring.Get(serviceName, keychainKey)
    if err != nil {
        return "", fmt.Errorf("secret not found: %s", keychainKey)
    }
    return val, nil
}

// fileRead reads from ~/.agentsecrets/keyring.json — the same file AgentSecrets uses.
// AgentSecrets stores secrets as { "key": { "private": "base64(value)", "public": "" } }
func (r *LinuxReader) fileRead(keychainKey string) (string, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return "", fmt.Errorf("get home dir: %w", err)
    }

    path := filepath.Join(home, ".agentsecrets", "keyring.json")
    data, err := os.ReadFile(path)
    if err != nil {
        return "", fmt.Errorf("read keyring file: %w", err)
    }

    // AgentSecrets' file format: { "key": { "private": "b64", "public": "b64" } }
    var entries map[string]struct {
        Private string `json:"private"`
        Public  string `json:"public"`
    }

    if err := json.Unmarshal(data, &entries); err != nil {
        return "", fmt.Errorf("parse keyring file: %w", err)
    }

    entry, ok := entries[keychainKey]
    if !ok {
        return "", fmt.Errorf("secret not found in keyring file: %s", keychainKey)
    }

    if entry.Private == "" {
        return "", fmt.Errorf("secret has empty value: %s", keychainKey)
    }

    // AgentSecrets base64-encodes values before storing in the file backend
    decoded, err := base64.StdEncoding.DecodeString(entry.Private)
    if err != nil {
        return "", fmt.Errorf("decode secret value: %w", err)
    }

    return string(decoded), nil
}
