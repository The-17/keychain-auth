//go:build darwin && !cgo

package keychain

import "errors"

type DarwinKeychain struct{}

func New() *DarwinKeychain {
	return &DarwinKeychain{}
}

func (dk *DarwinKeychain) Read(service, target string) (string, error) {
	return "", errors.New("not implemented without cgo")
}

func (dk *DarwinKeychain) Write(service, target, value string) error {
	return errors.New("not implemented without cgo")
}

func (dk *DarwinKeychain) Delete(service, target string) error {
	return errors.New("not implemented without cgo")
}

func (dk *DarwinKeychain) Search(service string) ([]string, error) {
	return nil, errors.New("not implemented without cgo")
}
