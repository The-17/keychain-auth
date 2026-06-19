package keychain

import "errors"

// ErrNotFound is returned by Read when the requested key does not exist in the keychain.
// The handler treats this as an empty result (not an internal error).
var ErrNotFound = errors.New("keychain: secret not found")

// Keychain is the interface for interacting with the OS keychain.
type Keychain interface {
	// Read retrieves a secret value by its service name and target key/account.
	// Returns ErrNotFound if the key does not exist.
	Read(service, target string) (string, error)

	// Write creates or updates a secret value for a service and target.
	Write(service, target, value string) error

	// Delete removes a secret for a service and target.
	Delete(service, target string) error

	// Search returns a list of target keys/accounts registered under the given service.
	// It does NOT return secret values.
	Search(service string) ([]string, error)
}
