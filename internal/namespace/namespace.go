package namespace

import (
    "fmt"
    "strings"
)

const (
    // ServiceName is the go-keyring service name used by AgentSecrets.
    // keychain-auth MUST use the same service name to read the same entries.
    ServiceName = "AgentSecrets"
)

// ValidEnvironments are the only environment values keychain-auth will accept.
var ValidEnvironments = map[string]bool{
    "development": true,
    "staging":     true,
    "production":  true,
}

// ValidateKey checks that a bare key name is safe.
// It rejects keys containing:
//   - Forward slashes (/)
//   - Backslashes (\)
//   - Dot-dot sequences (..)
//   - Colons (:) — because the storage format uses colons as delimiters
//   - The namespace prefix itself (double-prefixing)
//   - Empty strings
//   - Strings longer than 256 characters
//
// Returns nil if valid, or an error describing the rejection reason.
func ValidateKey(key string) error {
    if key == "" {
        return fmt.Errorf("key is empty")
    }
    if len(key) > 256 {
        return fmt.Errorf("key exceeds maximum length of 256 characters")
    }
    if strings.Contains(key, "/") {
        return fmt.Errorf("key contains forward slash")
    }
    if strings.Contains(key, "\\") {
        return fmt.Errorf("key contains backslash")
    }
    if strings.Contains(key, "..") {
        return fmt.Errorf("key contains dot-dot sequence")
    }
    if strings.Contains(key, ":") {
        return fmt.Errorf("key contains colon")
    }
    if strings.HasPrefix(key, "agentsecrets") {
        return fmt.Errorf("key contains namespace prefix")
    }
    return nil
}

// ValidateProjectID checks that a project ID is non-empty and safe.
func ValidateProjectID(projectID string) error {
    if projectID == "" {
        return fmt.Errorf("project_id is empty")
    }
    if strings.Contains(projectID, ":") {
        return fmt.Errorf("project_id contains colon")
    }
    if len(projectID) > 128 {
        return fmt.Errorf("project_id is not a valid uuid")
    }
    return nil
}

// ValidateEnvironment checks that the environment is one of the three valid values.
func ValidateEnvironment(env string) error {
    if !ValidEnvironments[env] {
        return fmt.Errorf("invalid environment %q: must be development, staging, or production", env)
    }
    return nil
}

// KeychainKey constructs the OS keychain key name in AgentSecrets' format.
// Format: "{projectID}:{environment}:{key}"
//
// This matches AgentSecrets' secretKeyName() function in pkg/keyring/keyring.go:
//     func secretKeyName(projectID, environment, key string) string {
//         return fmt.Sprintf("%s:%s:%s", projectID, environment, key)
//     }
//
// MUST only be called after all three inputs have been validated.
func KeychainKey(projectID, environment, key string) string {
    return fmt.Sprintf("%s:%s:%s", projectID, environment, key)
}

// LegacyKeychainKey constructs the older AgentSecrets format for migration compatibility.
// Format: "Secret_{projectID}_{key}"
// MUST only be called after inputs have been validated.
func LegacyKeychainKey(projectID, key string) string {
    return fmt.Sprintf("Secret_%s_%s", projectID, key)
}

// IsAllowedKeychainKey checks whether a constructed key follows the
// {projectID}:{environment}:{key} pattern. This is the namespace boundary —
// keychain-auth must NEVER read a key that doesn't match this pattern.
func IsAllowedKeychainKey(keychainKey string) bool {
    parts := strings.SplitN(keychainKey, ":", 3)
    if len(parts) != 3 {
        return false
    }
    if parts[0] == "" || parts[1] == "" || parts[2] == "" {
        return false
    }
    return ValidEnvironments[parts[1]]
}
