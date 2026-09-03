package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"x-ui/config"
)

func TestIsPanelUpdateAvailable(t *testing.T) {
	tests := []struct {
		current   string
		latest    string
		available bool
	}{
		{current: "0.4.5", latest: "0.4.6", available: true},
		{current: "0.4.9", latest: "0.5.0", available: true},
		{current: "1.0.0", latest: "1.0.0", available: false},
		{current: "1.2.0", latest: "1.1.99", available: false},
	}
	for _, test := range tests {
		got, err := isPanelUpdateAvailable(test.current, test.latest)
		if err != nil {
			t.Fatalf("compare %s and %s: %v", test.current, test.latest, err)
		}
		if got != test.available {
			t.Fatalf("compare %s and %s: got %v, want %v", test.current, test.latest, got, test.available)
		}
	}
	if _, err := isPanelUpdateAvailable("dev", "0.4.6"); err == nil {
		t.Fatal("invalid current version was accepted")
	}
}

func TestGetPanelUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"999.0.0","html_url":"https://example.invalid/release","draft":false,"prerelease":false}`))
	}))
	defer server.Close()
	previousURL := panelReleaseAPIURL
	previousClient := releaseHTTPClient
	panelReleaseAPIURL = server.URL
	releaseHTTPClient = server.Client()
	defer func() {
		panelReleaseAPIURL = previousURL
		releaseHTTPClient = previousClient
	}()

	info, err := (&ServerService{}).GetPanelUpdate()
	if err != nil {
		t.Fatal(err)
	}
	if !info.UpdateAvailable || info.LatestVersion != "999.0.0" || info.CurrentVersion != config.GetVersion() {
		t.Fatalf("unexpected update info: %+v", info)
	}
}

func TestVerifyPanelChecksum(t *testing.T) {
	content := []byte("verified panel archive")
	fileName := filepath.Join(t.TempDir(), "panel.tar.gz")
	if err := os.WriteFile(fileName, content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	checksum := []byte(fmt.Sprintf("%x  x-ui-linux-amd64.tar.gz\n", digest))
	if err := verifyPanelChecksum(fileName, checksum); err != nil {
		t.Fatal(err)
	}
	if err := verifyPanelChecksum(fileName, []byte("invalid")); err == nil {
		t.Fatal("invalid checksum was accepted")
	}
}

func TestExtractPanelExecutable(t *testing.T) {
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	content := []byte("panel executable")
	if err := tarWriter.WriteHeader(&tar.Header{
		Name: "x-ui/x-ui",
		Mode: 0755,
		Size: int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	archiveName := filepath.Join(t.TempDir(), "panel.tar.gz")
	if err := os.WriteFile(archiveName, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	targetDir := t.TempDir()
	extracted, err := extractPanelExecutable(archiveName, targetDir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(extracted)
	got, err := os.ReadFile(extracted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("unexpected extracted content: %q", got)
	}
	stat, err := os.Stat(extracted)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0755 {
		t.Fatalf("unexpected mode: %o", stat.Mode().Perm())
	}
}
