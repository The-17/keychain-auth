//go:build windows

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/danieljoos/wincred"
)

const credentialTargetName = "AgentSecretsMasterKey"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: keychain-helper.exe [get|set] [args]")
		os.Exit(1)
	}

	action := os.Args[1]
	switch action {
	case "get":
		key, err := getOrCreateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(key)
	case "set":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: keychain-helper.exe set <base64_key>")
			os.Exit(1)
		}
		keyBase64 := os.Args[2]
		// Verify it's valid base64
		keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
		if err != nil || len(keyBytes) != 32 {
			fmt.Fprintf(os.Stderr, "Error: invalid 32-byte base64 key: %v\n", err)
			os.Exit(1)
		}
		err = setKey(keyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Key updated successfully")
	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", action)
		os.Exit(1)
	}
}

func getOrCreateKey() (string, error) {
	cred, err := wincred.GetGenericCredential(credentialTargetName)
	if err == nil && cred != nil && len(cred.CredentialBlob) == 32 {
		return base64.StdEncoding.EncodeToString(cred.CredentialBlob), nil
	}

	// Not found or invalid size, let's create a new one
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generate random key: %w", err)
	}

	err = setKey(key)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(key), nil
}

func setKey(keyBytes []byte) error {
	cred := wincred.NewGenericCredential(credentialTargetName)
	cred.UserName = "agentsecrets"
	cred.CredentialBlob = keyBytes
	cred.Persist = wincred.PersistEnterprise
	return cred.Write()
}
