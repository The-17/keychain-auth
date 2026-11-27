package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

func TestChecksumFor(t *testing.T) {
	checksums := "abc  keychain-auth_4.0.2_linux_amd64.tar.gz\ndef  keychain-auth_4.0.2_darwin_arm64.tar.gz\n"
	got, err := checksumFor(checksums, "keychain-auth_4.0.2_linux_amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Errorf("digest = %q", got)
	}
	if _, err := checksumFor(checksums, "missing.tar.gz"); err == nil {
		t.Error("a missing asset must fail")
	}
}

func TestExtractBinaryFindsOnlyTheBinary(t *testing.T) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct{ name, body string }{
		{"README.md", "docs"},
		{"keychain-auth", "binary-bytes"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0755, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := extractBinary(raw.Bytes(), "keychain-auth")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary-bytes" {
		t.Errorf("binary = %q", got)
	}
	if _, err := extractBinary(raw.Bytes(), "missing"); err == nil {
		t.Error("a missing binary must fail")
	}
}

func TestSelectAssetName(t *testing.T) {
	want := "keychain-auth_4.0.2_windows_arm64.tar.gz"
	if got := selectAssetName("4.0.2", "windows", "arm64"); got != want {
		t.Errorf("asset = %q, want %q", got, want)
	}
}
