//go:build linux

package keychain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	gokeyring "github.com/zalando/go-keyring"
	"github.com/godbus/dbus/v5"
)

type LinuxKeychain struct {
	useFileBackend bool
	storePath      string // path to encrypted data file
	keyPath        string // path to encryption key file
	mu             sync.Mutex
	cache          map[string]string // in-memory cache of file store for fast reads
}

func New() *LinuxKeychain {
	lk := &LinuxKeychain{}

	if runtime.GOOS == "linux" {
		needsFileBackend := false

		// Test if keyring actually works
		testKey := "__keychain_auth_keyring_test__"
		if err := gokeyring.Set("keychain-auth-test", testKey, "test"); err != nil {
			needsFileBackend = true
		} else {
			_ = gokeyring.Delete("keychain-auth-test", testKey)
		}

		if needsFileBackend {
			lk.useFileBackend = true
			storeDir := fileStoreDir()
			lk.storePath = filepath.Join(storeDir, "keychain.enc")
			lk.keyPath = filepath.Join(storeDir, "keychain.key")

			// Ensure store directory exists with strict permissions
			_ = os.MkdirAll(storeDir, 0700)

			// Load existing data from disk
			lk.cache = lk.loadFromDisk()
		}
	}

	return lk
}

// fileStoreDir returns the directory for the encrypted file store.
// Uses XDG_DATA_HOME if set, otherwise ~/.local/share/keychain-auth.
func fileStoreDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "keychain-auth")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "keychain-auth")
}

func (lk *LinuxKeychain) Read(service, target string) (string, error) {
	if lk.useFileBackend {
		lk.mu.Lock()
		defer lk.mu.Unlock()

		key := service + ":" + target
		if val, ok := lk.cache[key]; ok {
			return val, nil
		}
		return "", ErrNotFound
	}

	val, err := gokeyring.Get(service, target)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return "", ErrNotFound
		}
		return "", err
	}
	return val, nil
}

func (lk *LinuxKeychain) Write(service, target, value string) error {
	if lk.useFileBackend {
		lk.mu.Lock()
		defer lk.mu.Unlock()

		key := service + ":" + target
		lk.cache[key] = value
		return lk.persistToDisk()
	}
	return gokeyring.Set(service, target, value)
}

func (lk *LinuxKeychain) Delete(service, target string) error {
	if lk.useFileBackend {
		lk.mu.Lock()
		defer lk.mu.Unlock()

		key := service + ":" + target
		if _, ok := lk.cache[key]; !ok {
			return fmt.Errorf("secret not found: %s:%s", service, target)
		}
		delete(lk.cache, key)
		return lk.persistToDisk()
	}
	return gokeyring.Delete(service, target)
}

func (lk *LinuxKeychain) Search(service string) ([]string, error) {
	if lk.useFileBackend {
		lk.mu.Lock()
		defer lk.mu.Unlock()

		prefix := service + ":"
		var targets []string
		for k := range lk.cache {
			if strings.HasPrefix(k, prefix) {
				targets = append(targets, strings.TrimPrefix(k, prefix))
			}
		}
		return targets, nil
	}
	return lk.dbusSearch(service)
}

// --- Encrypted File Store ---

// getOrCreateKey loads the AES-256 key from disk, or generates one on first use.
func (lk *LinuxKeychain) getOrCreateKey() ([]byte, error) {
	data, err := os.ReadFile(lk.keyPath)
	if err == nil && len(data) == 32 {
		return data, nil
	}

	// Generate a new 256-bit key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}

	if err := os.WriteFile(lk.keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("write encryption key: %w", err)
	}
	return key, nil
}

// persistToDisk encrypts the cache map and writes it to disk atomically.
// Caller must hold lk.mu.
func (lk *LinuxKeychain) persistToDisk() error {
	key, err := lk.getOrCreateKey()
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal(lk.cache)
	if err != nil {
		return fmt.Errorf("marshal keychain data: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Atomic write: write to temp file, then rename
	tmpPath := lk.storePath + ".tmp"
	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write temp store: %w", err)
	}
	if err := os.Rename(tmpPath, lk.storePath); err != nil {
		return fmt.Errorf("rename temp store: %w", err)
	}

	return nil
}

// loadFromDisk decrypts the store file and returns the data map.
// Returns an empty map if the file doesn't exist or can't be read.
func (lk *LinuxKeychain) loadFromDisk() map[string]string {
	result := make(map[string]string)

	ciphertext, err := os.ReadFile(lk.storePath)
	if err != nil {
		return result // No store yet — clean start
	}

	key, err := os.ReadFile(lk.keyPath)
	if err != nil || len(key) != 32 {
		return result // No key — can't decrypt, clean start
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return result
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return result
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return result
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return result // Decryption failed — corrupted or key mismatch, clean start
	}

	if err := json.Unmarshal(plaintext, &result); err != nil {
		return make(map[string]string)
	}

	return result
}

// --- D-Bus search logic ---

func (lk *LinuxKeychain) dbusSearch(service string) ([]string, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("session bus connection: %w", err)
	}

	obj := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")

	attrs := map[string]string{
		"service": service,
	}

	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath
	err = obj.Call("org.freedesktop.Secret.Service.SearchItems", 0, attrs).Store(&unlocked, &locked)
	if err != nil {
		return nil, fmt.Errorf("D-Bus SearchItems call failed: %w", err)
	}

	allPaths := append(unlocked, locked...)
	var targets []string

	for _, path := range allPaths {
		itemObj := conn.Object("org.freedesktop.secrets", path)
		variant, err := itemObj.GetProperty("org.freedesktop.Secret.Item.Attributes")
		if err != nil {
			continue
		}
		itemAttrs, ok := variant.Value().(map[string]string)
		if !ok {
			continue
		}
		if user, exists := itemAttrs["username"]; exists {
			targets = append(targets, user)
		} else if user, exists := itemAttrs["account"]; exists {
			targets = append(targets, user)
		}
	}

	return targets, nil
}
