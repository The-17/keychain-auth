//go:build linux

package keychain

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
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

	// Always initialize keyPath so it is available for encryption/decryption
	storeDir := fileStoreDir()
	lk.keyPath = filepath.Join(storeDir, "keychain.key")
	_ = os.MkdirAll(storeDir, 0700)

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
			lk.storePath = filepath.Join(storeDir, "keychain.enc")

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

	encryptedVal, err := gokeyring.Get(service, target)
	if err != nil {
		if err == gokeyring.ErrNotFound {
			return "", ErrNotFound
		}
		return "", err
	}

	decryptedVal, err := lk.decrypt(encryptedVal)
	if err != nil {
		return "", fmt.Errorf("decrypt value from keyring: %w", err)
	}
	return decryptedVal, nil
}

func (lk *LinuxKeychain) Write(service, target, value string) error {
	if lk.useFileBackend {
		lk.mu.Lock()
		defer lk.mu.Unlock()

		key := service + ":" + target
		lk.cache[key] = value
		return lk.persistToDisk()
	}

	encryptedVal, err := lk.encrypt(value)
	if err != nil {
		return fmt.Errorf("encrypt value for keyring: %w", err)
	}
	return gokeyring.Set(service, target, encryptedVal)
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

// --- Encrypt / Decrypt helpers for Keyring payloads ---

func (lk *LinuxKeychain) encrypt(plaintext string) (string, error) {
	key, err := lk.getOrCreateKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (lk *LinuxKeychain) decrypt(encodedCiphertext string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", fmt.Errorf("decode base64 ciphertext: %w", err)
	}

	key, err := lk.getOrCreateKey()
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt GCM open: %w", err)
	}

	return string(plaintext), nil
}

// --- WSL / TPM2 / File Key Storage Detection & Logic ---

func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "microsoft") || strings.Contains(content, "wsl") {
			return true
		}
	}
	return false
}

func getWindowsUserProfile() string {
	cmdPath := "cmd.exe"
	if _, err := exec.LookPath("cmd.exe"); err != nil {
		for _, p := range []string{"/mnt/c/Windows/System32/cmd.exe", "/mnt/c/Windows/system32/cmd.exe"} {
			if _, statErr := os.Stat(p); statErr == nil {
				cmdPath = p
				break
			}
		}
	}

	cmd := exec.Command(cmdPath, "/c", "echo %USERPROFILE%")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	winPath := strings.TrimSpace(string(out))
	if winPath == "" {
		return ""
	}

	wslpathCmd := exec.Command("wslpath", "-u", winPath)
	wslPathBytes, err := wslpathCmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(wslPathBytes))
}

//go:embed keychain-helper.exe
var helperBytes []byte

func ensureHelperExists() error {
	userProfile := getWindowsUserProfile()
	if userProfile == "" {
		return fmt.Errorf("cannot resolve Windows user profile")
	}

	targetDir := filepath.Join(userProfile, ".config", "keychain-auth")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", targetDir, err)
	}

	targetPath := filepath.Join(targetDir, "keychain-helper.exe")

	// Check if already exists and matches the size
	if info, err := os.Stat(targetPath); err == nil {
		if info.Size() == int64(len(helperBytes)) {
			return nil
		}
	}

	// Write the embedded bytes
	if err := os.WriteFile(targetPath, helperBytes, 0755); err != nil {
		return fmt.Errorf("failed to write helper to %s: %w", targetPath, err)
	}

	return nil
}

func runKeychainHelper(args ...string) (string, error) {
	_ = ensureHelperExists() // Try to ensure the helper is extracted to the user's config folder

	paths := []string{"keychain-helper.exe"}
	if userProfile := getWindowsUserProfile(); userProfile != "" {
		paths = append(paths, filepath.Join(userProfile, ".config", "keychain-auth", "keychain-helper.exe"))
		paths = append(paths, filepath.Join(userProfile, "AppData", "Local", "keychain-auth", "keychain-helper.exe"))
	}

	var lastErr error
	for _, p := range paths {
		cmd := exec.Command(p, args...)
		out, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("failed to execute keychain-helper.exe: %w", lastErr)
}

func hasTPM2() bool {
	if _, err := os.Stat("/dev/tpm0"); os.IsNotExist(err) {
		return false
	}
	_, err := exec.LookPath("tpm2_unseal")
	return err == nil
}

func tpm2Seal(key []byte, pubPath, privPath string) error {
	tmpDir, err := os.MkdirTemp("", "keychain-tpm-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	primaryCtx := filepath.Join(tmpDir, "primary.ctx")
	keyRaw := filepath.Join(tmpDir, "key.raw")

	if err := os.WriteFile(keyRaw, key, 0600); err != nil {
		return fmt.Errorf("write raw key: %w", err)
	}

	cmd := exec.Command("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa", "-c", primaryCtx)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tpm2_createprimary failed: %s: %w", string(out), err)
	}

	cmd = exec.Command("tpm2_create", "-C", primaryCtx, "-u", pubPath, "-r", privPath, "-i", keyRaw)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tpm2_create failed: %s: %w", string(out), err)
	}

	return nil
}

func tpm2Unseal(pubPath, privPath string) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "keychain-tpm-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	primaryCtx := filepath.Join(tmpDir, "primary.ctx")
	keyCtx := filepath.Join(tmpDir, "key.ctx")

	cmd := exec.Command("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa", "-c", primaryCtx)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("tpm2_createprimary failed: %s: %w", string(out), err)
	}

	cmd = exec.Command("tpm2_load", "-C", primaryCtx, "-u", pubPath, "-r", privPath, "-c", keyCtx)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("tpm2_load failed: %s: %w", string(out), err)
	}

	cmd = exec.Command("tpm2_unseal", "-c", keyCtx)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("tpm2_unseal failed: %w", err)
	}

	return out, nil
}

// getOrCreateKey loads the AES-256 key, using WSL host interop, TPM2, or local file fallback.
func (lk *LinuxKeychain) getOrCreateKey() ([]byte, error) {
	if isWSL() {
		base64Key, err := runKeychainHelper("get")
		if err != nil {
			return nil, fmt.Errorf("WSL key interop: %w", err)
		}
		key, err := base64.StdEncoding.DecodeString(base64Key)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid key returned from Windows host helper: %w", err)
		}
		return key, nil
	}

	if hasTPM2() {
		pubPath := lk.keyPath + ".pub"
		privPath := lk.keyPath + ".priv"
		if _, err := os.Stat(pubPath); err == nil {
			key, err := tpm2Unseal(pubPath, privPath)
			if err == nil && len(key) == 32 {
				return key, nil
			}
		}

		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("generate random key: %w", err)
		}
		if err := tpm2Seal(key, pubPath, privPath); err != nil {
			return nil, fmt.Errorf("seal key to TPM2: %w", err)
		}
		return key, nil
	}

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

	key, err := lk.getOrCreateKey()
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

	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
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
