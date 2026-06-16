//go:build linux

package keychain

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	gokeyring "github.com/zalando/go-keyring"
	"github.com/godbus/dbus/v5"
)

type LinuxKeychain struct {
	useInMemoryBackend bool
	dbMu               sync.Mutex
	db                 map[string]string // maps "service:target" -> value
}

func New() *LinuxKeychain {
	lk := &LinuxKeychain{
		db: make(map[string]string),
	}

	if runtime.GOOS == "linux" {
		if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("DISPLAY") == "" {
			lk.useInMemoryBackend = true
		} else {
			// Test if keyring actually works
			testKey := "__keychain_auth_keyring_test__"
			if err := gokeyring.Set("keychain-auth-test", testKey, "test"); err != nil {
				lk.useInMemoryBackend = true
			} else {
				_ = gokeyring.Delete("keychain-auth-test", testKey)
			}
		}
	}

	return lk
}

func (lk *LinuxKeychain) Read(service, target string) (string, error) {
	if lk.useInMemoryBackend {
		key := service + ":" + target
		if val, ok := lk.memRead(key); ok {
			return val, nil
		}
		return "", fmt.Errorf("secret not found in memory: %s", key)
	}
	return gokeyring.Get(service, target)
}

func (lk *LinuxKeychain) Write(service, target, value string) error {
	if lk.useInMemoryBackend {
		lk.memWrite(service+":"+target, value)
		return nil
	}
	return gokeyring.Set(service, target, value)
}

func (lk *LinuxKeychain) Delete(service, target string) error {
	if lk.useInMemoryBackend {
		if ok := lk.memDelete(service + ":" + target); !ok {
			return fmt.Errorf("secret not found: %s:%s", service, target)
		}
		return nil
	}
	return gokeyring.Delete(service, target)
}

func (lk *LinuxKeychain) Search(service string) ([]string, error) {
	if lk.useInMemoryBackend {
		return lk.memSearch(service + ":"), nil
	}
	return lk.dbusSearch(service)
}

// --- In-Memory Helper Methods ---

func (lk *LinuxKeychain) memRead(key string) (string, bool) {
	lk.dbMu.Lock()
	defer lk.dbMu.Unlock()
	val, ok := lk.db[key]
	return val, ok
}

func (lk *LinuxKeychain) memWrite(key, value string) {
	lk.dbMu.Lock()
	defer lk.dbMu.Unlock()
	lk.db[key] = value
}

func (lk *LinuxKeychain) memDelete(key string) bool {
	lk.dbMu.Lock()
	defer lk.dbMu.Unlock()
	if _, ok := lk.db[key]; !ok {
		return false
	}
	delete(lk.db, key)
	return true
}

func (lk *LinuxKeychain) memSearch(prefix string) []string {
	lk.dbMu.Lock()
	defer lk.dbMu.Unlock()
	var targets []string
	for k := range lk.db {
		if strings.HasPrefix(k, prefix) {
			targets = append(targets, strings.TrimPrefix(k, prefix))
		}
	}
	return targets
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
