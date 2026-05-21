//go:build linux

package keychain

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	gokeyring "github.com/zalando/go-keyring"
	"github.com/godbus/dbus/v5"
)

type fileEntry struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

type LinuxKeychain struct {
	useFileBackend bool
	fileMu         sync.Mutex
	filePath       string
}

func New() *LinuxKeychain {
	home, err := os.UserHomeDir()
	var path string
	if err == nil {
		path = filepath.Join(home, ".keychain-auth", "keyring.json")
	}

	lk := &LinuxKeychain{
		filePath: path,
	}

	if runtime.GOOS == "linux" {
		if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("DISPLAY") == "" {
			lk.useFileBackend = true
		} else {
			// Test if keyring actually works
			testKey := "__keychain_auth_keyring_test__"
			if err := gokeyring.Set("keychain-auth-test", testKey, "test"); err != nil {
				lk.useFileBackend = true
			} else {
				_ = gokeyring.Delete("keychain-auth-test", testKey)
			}
		}
	}

	if lk.useFileBackend {
		lk.migrateWSLKeyring()
	}

	return lk
}

func (lk *LinuxKeychain) migrateWSLKeyring() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	oldPath := filepath.Join(home, ".agentsecrets", "keyring.json")
	if _, err := os.Stat(oldPath); err != nil {
		return // Old path does not exist
	}
	if _, err := os.Stat(lk.filePath); err == nil {
		return // New path already exists
	}

	_ = os.MkdirAll(filepath.Dir(lk.filePath), 0700)

	data, err := os.ReadFile(oldPath)
	if err != nil {
		return
	}

	var oldEntries map[string]fileEntry
	if err := json.Unmarshal(data, &oldEntries); err != nil {
		return
	}

	newEntries := make(map[string]fileEntry)
	for k, v := range oldEntries {
		// Migrate by prefixing with AgentSecrets:
		newEntries["AgentSecrets:"+k] = v
	}

	newData, err := json.MarshalIndent(newEntries, "", "  ")
	if err == nil {
		_ = os.WriteFile(lk.filePath, newData, 0600)
	}
}

func (lk *LinuxKeychain) Read(service, target string) (string, error) {
	if lk.useFileBackend {
		return lk.fileRead(service, target)
	}
	return gokeyring.Get(service, target)
}

func (lk *LinuxKeychain) Write(service, target, value string) error {
	if lk.useFileBackend {
		return lk.fileWrite(service, target, value)
	}
	return gokeyring.Set(service, target, value)
}

func (lk *LinuxKeychain) Delete(service, target string) error {
	if lk.useFileBackend {
		return lk.fileDelete(service, target)
	}
	return gokeyring.Delete(service, target)
}

func (lk *LinuxKeychain) Search(service string) ([]string, error) {
	if lk.useFileBackend {
		return lk.fileSearch(service)
	}
	return lk.dbusSearch(service)
}

// --- File backend helper methods ---

func (lk *LinuxKeychain) fileRead(service, target string) (string, error) {
	lk.fileMu.Lock()
	defer lk.fileMu.Unlock()

	entries, err := lk.loadEntries()
	if err != nil {
		return "", err
	}

	key := service + ":" + target
	entry, ok := entries[key]
	if !ok {
		return "", fmt.Errorf("secret not found in file: %s", key)
	}

	decoded, err := base64.StdEncoding.DecodeString(entry.Private)
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}

	return string(decoded), nil
}

func (lk *LinuxKeychain) fileWrite(service, target, value string) error {
	lk.fileMu.Lock()
	defer lk.fileMu.Unlock()

	entries, err := lk.loadEntries()
	if err != nil {
		return err
	}

	key := service + ":" + target
	entries[key] = fileEntry{
		Private: base64.StdEncoding.EncodeToString([]byte(value)),
	}

	return lk.saveEntries(entries)
}

func (lk *LinuxKeychain) fileDelete(service, target string) error {
	lk.fileMu.Lock()
	defer lk.fileMu.Unlock()

	entries, err := lk.loadEntries()
	if err != nil {
		return err
	}

	key := service + ":" + target
	if _, ok := entries[key]; !ok {
		return fmt.Errorf("secret not found: %s", key)
	}

	delete(entries, key)
	return lk.saveEntries(entries)
}

func (lk *LinuxKeychain) fileSearch(service string) ([]string, error) {
	lk.fileMu.Lock()
	defer lk.fileMu.Unlock()

	entries, err := lk.loadEntries()
	if err != nil {
		return nil, err
	}

	var targets []string
	prefix := service + ":"
	for k := range entries {
		if strings.HasPrefix(k, prefix) {
			targets = append(targets, strings.TrimPrefix(k, prefix))
		}
	}
	return targets, nil
}

func (lk *LinuxKeychain) loadEntries() (map[string]fileEntry, error) {
	if lk.filePath == "" {
		return nil, fmt.Errorf("keyring file path not initialized")
	}

	data, err := os.ReadFile(lk.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]fileEntry), nil
		}
		return nil, err
	}

	var entries map[string]fileEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (lk *LinuxKeychain) saveEntries(entries map[string]fileEntry) error {
	if err := os.MkdirAll(filepath.Dir(lk.filePath), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	tmp := lk.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmp, lk.filePath)
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
