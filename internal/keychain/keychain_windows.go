//go:build windows

package keychain

import (
	"fmt"
	"strings"

	"github.com/danieljoos/wincred"
	gokeyring "github.com/zalando/go-keyring"
)

type WindowsKeychain struct{}

// New creates a new WindowsKeychain instance.
func New() *WindowsKeychain {
	return &WindowsKeychain{}
}

// Read retrieves a secret value by its service name and target key/account.
// Returns ErrNotFound if the key does not exist in Windows Credential Manager.
func (wk *WindowsKeychain) Read(service, target string) (string, error) {
	val, err := gokeyring.Get(service, target)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return "", ErrNotFound
		}
		return "", err
	}
	return val, nil
}


// Write creates or updates a secret value for a service and target.
func (wk *WindowsKeychain) Write(service, target, value string) error {
	return gokeyring.Set(service, target, value)
}

// Delete removes a secret for a service and target.
func (wk *WindowsKeychain) Delete(service, target string) error {
	return gokeyring.Delete(service, target)
}

// Search returns a list of target keys registered under the given service on Windows.
func (wk *WindowsKeychain) Search(service string) ([]string, error) {
	creds, err := wincred.List()
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}

	var targets []string
	prefix := service + ":"
	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, prefix) {
			targets = append(targets, strings.TrimPrefix(cred.TargetName, prefix))
		}
	}
	return targets, nil
}
