package keychain

// Reader is the interface for reading secrets from the OS keychain.
// keychain-auth ONLY reads. Writing and deleting are AgentSecrets' responsibility.
type Reader interface {
    // Read retrieves a secret value by its keychain key name.
    // The keychainKey is already in the format "{projectID}:{environment}:{key}" 
    // or the legacy "Secret_{projectID}_{key}".
    // Returns the plaintext value or an error if the key is not found.
    Read(keychainKey string) (string, error)
}
