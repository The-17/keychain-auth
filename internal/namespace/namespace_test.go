package namespace_test

import (
    "strings"
    "testing"

    "github.com/The-17/keychain-auth/internal/namespace"
)

func TestValidateKey(t *testing.T) {
    tests := []struct {
        name    string
        key     string
        wantErr bool
    }{
        {"Valid key", "OPENAI_API_KEY", false},
        {"Valid lowercase key", "stripe_secret", false},
        {"Empty key", "", true},
        {"Slash", "foo/bar", true},
        {"Backslash", `foo\bar`, true},
        {"Dot dot", "../passwd", true},
        {"Colon", "foo:bar", true},
        {"Namespace prefix", "agentsecrets.io/secret", true},
        {"Too long", strings.Repeat("A", 257), true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := namespace.ValidateKey(tt.key)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
            }
        })
    }
}

func TestValidateEnvironment(t *testing.T) {
    valid := []string{"development", "staging", "production"}
    for _, env := range valid {
        if err := namespace.ValidateEnvironment(env); err != nil {
            t.Errorf("ValidateEnvironment(%q) unexpectedly failed: %v", env, err)
        }
    }

    invalid := []string{"", "test", "prod"}
    for _, env := range invalid {
        if err := namespace.ValidateEnvironment(env); err == nil {
            t.Errorf("ValidateEnvironment(%q) unexpectedly succeeded", env)
        }
    }
}

func TestValidateProjectID(t *testing.T) {
    if err := namespace.ValidateProjectID("proj123"); err != nil {
        t.Errorf("Valid project ID failed: %v", err)
    }
    if err := namespace.ValidateProjectID(""); err == nil {
        t.Error("Empty project ID succeeded")
    }
    if err := namespace.ValidateProjectID("proj:123"); err == nil {
        t.Error("Project ID with colon succeeded")
    }
}

func TestKeychainKeyConstruction(t *testing.T) {
    got := namespace.KeychainKey("proj123", "development", "API_KEY")
    want := "proj123:development:API_KEY"
    if got != want {
        t.Errorf("KeychainKey() = %v, want %v", got, want)
    }

    gotLegacy := namespace.LegacyKeychainKey("proj123", "API_KEY")
    wantLegacy := "Secret_proj123_API_KEY"
    if gotLegacy != wantLegacy {
        t.Errorf("LegacyKeychainKey() = %v, want %v", gotLegacy, wantLegacy)
    }
}

func TestIsAllowedKeychainKey(t *testing.T) {
    tests := []struct {
        key  string
        want bool
    }{
        {"proj:development:KEY", true},
        {"proj:staging:KEY", true},
        {"proj:production:KEY", true},
        {"proj:test:KEY", false},           // Invalid environment
        {":development:KEY", false},        // Empty project ID
        {"proj:development:", false},       // Empty key
        {"email_private_key", false},       // Keypair, no colons
        {"agentsecrets:allowlist:123", false}, // Invalid environment (allowlist)
        {"ProjectKeys_proj_dev", false},    // Index, no colons
    }

    for _, tt := range tests {
        t.Run(tt.key, func(t *testing.T) {
            got := namespace.IsAllowedKeychainKey(tt.key)
            if got != tt.want {
                t.Errorf("IsAllowedKeychainKey(%q) = %v, want %v", tt.key, got, tt.want)
            }
        })
    }
}
