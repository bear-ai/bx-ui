package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"x-ui/database"
)

func testCertificateMaterial(t *testing.T, domain string, notBefore, notAfter time.Time) *certificateMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(notAfter.UnixNano()),
		Subject:               pkix.Name{CommonName: domain},
		Issuer:                pkix.Name{CommonName: "bx-ui test CA"},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &certificateMaterial{
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		privateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func TestNormalizeCertificateDomain(t *testing.T) {
	valid := map[string]string{
		"Panel.Example.COM.": "panel.example.com",
		"xn--fsq.example":    "xn--fsq.example",
	}
	for input, expected := range valid {
		actual, err := normalizeCertificateDomain(input)
		if err != nil || actual != expected {
			t.Fatalf("normalize %q = %q, %v; want %q", input, actual, err, expected)
		}
	}
	for _, input := range []string{"", "localhost", "127.0.0.1", "*.example.com", "-bad.example", "bad..example"} {
		if _, err := normalizeCertificateDomain(input); err == nil {
			t.Fatalf("invalid domain %q was accepted", input)
		}
	}
}

func TestPublicAddressValidation(t *testing.T) {
	for _, input := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1"} {
		if isPublicAddress(net.ParseIP(input)) {
			t.Fatalf("private address %s was accepted", input)
		}
	}
	for _, input := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !isPublicAddress(net.ParseIP(input)) {
			t.Fatalf("public address %s was rejected", input)
		}
	}
}

func TestHTTPChallengeHandler(t *testing.T) {
	service := NewCertificateService()
	path := challengePrefix + "test-token"
	cleanup := service.setChallenge(path, "test-response")
	defer cleanup()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := service.HTTPChallengeHandler(fallback)

	known := httptest.NewRecorder()
	handler.ServeHTTP(known, httptest.NewRequest(http.MethodGet, path, nil))
	if known.Code != http.StatusOK || known.Body.String() != "test-response" {
		t.Fatalf("unexpected challenge response: %d %q", known.Code, known.Body.String())
	}
	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, challengePrefix+"missing", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown challenge returned %d", unknown.Code)
	}
	normal := httptest.NewRecorder()
	handler.ServeHTTP(normal, httptest.NewRequest(http.MethodGet, "/", nil))
	if normal.Code != http.StatusTeapot {
		t.Fatalf("fallback returned %d", normal.Code)
	}
}

func TestActivateCertificateIsAtomicAndPreservesOldCertificate(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	service := NewCertificateService()
	service.storageDir = t.TempDir()
	service.now = func() time.Time { return now }
	domain := "panel.example.com"
	first := testCertificateMaterial(t, domain, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if err := service.activateCertificate(domain, first); err != nil {
		t.Fatal(err)
	}
	status, err := service.statusFor(domain, 443)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "valid" || status.RenewalDue || status.DaysRemaining != 90 {
		t.Fatalf("unexpected status: %+v", status)
	}
	certPath, keyPath := service.certificatePaths()
	for _, path := range []string{certPath, keyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
	oldTarget, err := os.Readlink(filepath.Join(service.storageDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	wrongDomain := testCertificateMaterial(t, "other.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if err := service.activateCertificate(domain, wrongDomain); err == nil {
		t.Fatal("mismatched certificate was accepted")
	}
	currentTarget, err := os.Readlink(filepath.Join(service.storageDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if currentTarget != oldTarget {
		t.Fatalf("failed activation changed current certificate from %q to %q", oldTarget, currentTarget)
	}
}

func TestRenewIfNeededAtFifteenDayBoundary(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	settings := &SettingService{}
	for key, value := range map[string]string{
		"webDomain":    "panel.example.com",
		"webPort":      "80",
		"webHTTPSPort": "443",
	} {
		if err := settings.saveSetting(key, value); err != nil {
			t.Fatal(err)
		}
	}
	service := NewCertificateService()
	service.storageDir = t.TempDir()
	service.now = func() time.Time { return now }
	service.lookupIP = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	initial := testCertificateMaterial(t, "panel.example.com", now.Add(-75*24*time.Hour), now.Add(certificateRenewBefore))
	if err := service.activateCertificate("panel.example.com", initial); err != nil {
		t.Fatal(err)
	}
	service.issueFunc = func(context.Context, string) (*certificateMaterial, error) {
		return testCertificateMaterial(t, "panel.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour)), nil
	}
	renewed, err := service.RenewIfNeeded(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !renewed {
		t.Fatal("certificate inside the 15-day renewal window was not renewed")
	}
	status, err := service.statusFor("panel.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if status.RenewalDue || status.State != "valid" {
		t.Fatalf("renewed certificate status is unexpected: %+v", status)
	}
}
