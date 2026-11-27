package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	selfUpdateBaseURL = "https://github.com/The-17/keychain-auth/releases/download"
	latestReleaseAPI  = "https://api.github.com/repos/The-17/keychain-auth/releases/latest"
	maxReleaseAsset   = 64 << 20
)

// SelfUpdateResult is the machine-readable result of self-update.
type SelfUpdateResult struct {
	PreviousVersion string `json:"previous_version"`
	Version         string `json:"version"`
	Path            string `json:"path"`
	Restarted       bool   `json:"restarted"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

func selectAssetName(version, goos, goarch string) string {
	return fmt.Sprintf("keychain-auth_%s_%s_%s.tar.gz", version, goos, goarch)
}

// checksumFor looks up one asset digest in a GoReleaser checksums.txt.
func checksumFor(checksums, asset string) (string, error) {
	for _, line := range strings.Split(checksums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("asset %s is not in checksums.txt", asset)
}

func downloadRelease(client *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func extractBinary(archive []byte, binaryName string) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if filepath.Base(header.Name) != binaryName {
			continue
		}
		return io.ReadAll(tr)
	}
	return nil, fmt.Errorf("binary %s not found in archive", binaryName)
}

func resolveLatestVersion(client *http.Client) (string, error) {
	body, err := downloadRelease(client, latestReleaseAPI, 1<<20)
	if err != nil {
		return "", err
	}
	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", fmt.Errorf("parse latest release: %w", err)
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
}

func installBinary(self string, data []byte) (string, error) {
	if runtime.GOOS == "windows" {
		pending := self + ".new"
		if err := os.WriteFile(pending, data, 0755); err != nil {
			return "", fmt.Errorf("write pending binary: %w", err)
		}
		return pending, nil
	}
	tmp := self + ".update"
	if err := os.WriteFile(tmp, data, 0755); err != nil {
		return "", fmt.Errorf("write update: %w", err)
	}
	if err := os.Rename(tmp, self); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("replace binary: %w", err)
	}
	return self, nil
}

var selfUpdateVersion string

var selfUpdateCmd = &cobra.Command{
	Use:   "self-update",
	Short: "Download, verify, and install a keychain-auth release",
	RunE: func(cmd *cobra.Command, args []string) error {
		client := &http.Client{Timeout: 60 * time.Second}
		version := strings.TrimPrefix(selfUpdateVersion, "v")
		if version == "" {
			var err error
			version, err = resolveLatestVersion(client)
			if err != nil {
				return fmt.Errorf("resolve latest version: %w", err)
			}
		}
		if version == "" {
			return fmt.Errorf("no version resolved")
		}

		base := fmt.Sprintf("%s/v%s", selfUpdateBaseURL, version)
		checksums, err := downloadRelease(client, base+"/checksums.txt", 1<<20)
		if err != nil {
			return fmt.Errorf("download checksums: %w", err)
		}
		asset := selectAssetName(version, runtime.GOOS, runtime.GOARCH)
		want, err := checksumFor(string(checksums), asset)
		if err != nil {
			return err
		}
		archive, err := downloadRelease(client, base+"/"+asset, maxReleaseAsset)
		if err != nil {
			return fmt.Errorf("download %s: %w", asset, err)
		}
		sum := sha256.Sum256(archive)
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, want) {
			return fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset, got, want)
		}

		binaryName := "keychain-auth"
		if runtime.GOOS == "windows" {
			binaryName += ".exe"
		}
		payload, err := extractBinary(archive, binaryName)
		if err != nil {
			return err
		}
		self, err := os.Executable()
		if err != nil {
			return err
		}
		self, err = filepath.EvalSymlinks(self)
		if err != nil {
			return err
		}
		installed, err := installBinary(self, payload)
		if err != nil {
			return err
		}

		result := &SelfUpdateResult{
			PreviousVersion: daemonVersion,
			Version:         version,
			Path:            installed,
			Restarted:       installed == self && runtime.GOOS != "windows",
		}
		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			encoded, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(encoded))
			return nil
		}
		fmt.Printf("Updated keychain-auth %s -> %s\n", result.PreviousVersion, result.Version)
		fmt.Printf("Binary: %s\n", result.Path)
		return nil
	},
}

func init() {
	selfUpdateCmd.Flags().Bool("json", false, "Output in JSON format")
	selfUpdateCmd.Flags().StringVar(&selfUpdateVersion, "version", "", "Version to install, without the v prefix")
	rootCmd.AddCommand(selfUpdateCmd)
}
