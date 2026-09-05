package xray

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"x-ui/util/json_util"
)

func testExecutable(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray-test")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateConfigUsesInstalledBinaryAndRemovesTemporaryFile(t *testing.T) {
	binary := testExecutable(t, `test "$1" = run && test "$2" = -test && test "$3" = -c || exit 80
test -f "$4" || exit 81
exit 0
`)
	dir := t.TempDir()
	if err := validateConfig(&Config{}, binary, dir, nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatalf("temporary configuration was not removed: %v, %v", files, err)
	}
}

func TestPreflightIgnoresInheritedConfigDirectories(t *testing.T) {
	t.Setenv("XRAY_LOCATION_CONFDIR", "/must-not-merge")
	t.Setenv("xray.location.confdir", "/must-not-merge-alias")
	t.Setenv("XRAY_LOCATION_ASSET", "/keep-assets")
	binary := testExecutable(t, `if env | grep -E '^(XRAY_LOCATION_CONFDIR|xray\.location\.confdir)='; then exit 90; fi
test "$XRAY_LOCATION_ASSET" = /keep-assets || exit 91
exit 0
`)
	if err := validateConfig(&Config{}, binary, t.TempDir(), nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, entry := range coreEnvironment() {
		if strings.HasPrefix(entry, "XRAY_LOCATION_CONFDIR=") || strings.HasPrefix(entry, "xray.location.confdir=") {
			t.Fatal("configuration directory alias remained in child environment")
		}
	}
}

func TestValidateConfigDoesNotExposeSecrets(t *testing.T) {
	binary := testExecutable(t, "echo 'secret-private-key secret-password' >&2\nexit 23\n")
	err := validateConfig(&Config{}, binary, t.TempDir(), nil, 5*time.Second)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unexpected or sensitive error: %v", err)
	}
}

func TestValidateConfigTimesOut(t *testing.T) {
	binary := testExecutable(t, "exec sleep 2\n")
	start := time.Now()
	err := validateConfig(&Config{}, binary, t.TempDir(), nil, 30*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "超时") || time.Since(start) > time.Second {
		t.Fatalf("validation did not time out promptly: %v", err)
	}
}

func TestConfigTestOutputIsBounded(t *testing.T) {
	output := &cappedOutput{}
	data := []byte(strings.Repeat("x", configTestOutputLimit*2))
	n, err := output.Write(data)
	if err != nil || n != len(data) || output.Len() != configTestOutputLimit {
		t.Fatalf("unexpected write count or limit: %d, %d, %v", n, output.Len(), err)
	}
}

func TestValidateTUNNeverStartsRealDeviceDuringPreflight(t *testing.T) {
	binary := testExecutable(t, `if grep -q bx-ui-tun-support-probe "$4"; then
  echo 'cannot unmarshal string into Go struct field TunConfig.MTU of type uint32'
  exit 23
fi
if grep -q '"protocol":"tun"' "$4"; then exit 90; fi
exit 0
`)
	config := &Config{InboundConfigs: []InboundConfig{{Protocol: "tun", Tag: "tun-entry", Settings: json_util.RawMessage(`{"name":"xray-test0","MTU":1500}`)}}}
	checked := false
	err := validateConfig(config, binary, t.TempDir(), func() error { checked = true; return nil }, 5*time.Second)
	if err != nil || !checked {
		t.Fatalf("TUN preflight failed: %v, permission checked: %v", err, checked)
	}
	if config.InboundConfigs[0].Protocol != "tun" || config.InboundConfigs[0].Tag != "tun-entry" {
		t.Fatal("validation modified the candidate configuration")
	}
}

func TestValidateTUNRejectsUnsupportedCoreAndPermissions(t *testing.T) {
	config := &Config{InboundConfigs: []InboundConfig{{Protocol: "tun", Settings: json_util.RawMessage(`{}`)}}}
	binary := testExecutable(t, "echo 'unknown config id: tun'\nexit 23\n")
	permissionErr := errors.New("administrator must enable TUN")
	if err := validateConfig(config, binary, t.TempDir(), func() error { return permissionErr }, 5*time.Second); !errors.Is(err, permissionErr) {
		t.Fatalf("permission guidance lost: %v", err)
	}
	if err := validateConfig(config, binary, t.TempDir(), func() error { return nil }, 5*time.Second); err == nil || !strings.Contains(err.Error(), "TUN 支持检查") {
		t.Fatalf("unsupported core accepted: %v", err)
	}
}

func TestValidateTUNRejectsInvalidSettingsAndDuplicateNames(t *testing.T) {
	for _, settings := range []string{`{"name":"too-long-interface-name"}`, `{"name":"bad/name"}`, `{"name":"bad name"}`, `{"MTU":-1}`, `{"MTU":100}`, `{"MTU":"1500"}`} {
		if _, err := validateTUNSettings([]byte(settings)); err == nil {
			t.Fatalf("invalid TUN settings accepted: %s", settings)
		}
	}
	config := &Config{InboundConfigs: []InboundConfig{
		{Protocol: "tun", Settings: json_util.RawMessage(`{}`)},
		{Protocol: "tun", Settings: json_util.RawMessage(`{"name":"xray0"}`)},
	}}
	if err := validateConfig(config, "unused", t.TempDir(), nil, time.Second); err == nil || !strings.Contains(err.Error(), "相同") {
		t.Fatalf("duplicate TUN interface accepted: %v", err)
	}
}

// XRAY_TEST_BINARY enables an integration check against a separately verified
// official core without bundling a host executable in the repository.
func TestInstalledXrayPreflight(t *testing.T) {
	binary := os.Getenv("XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set XRAY_TEST_BINARY to an official host Xray executable")
	}
	// If either inherited confdir alias reaches the core, this otherwise-valid
	// test configuration gains an unsupported inbound and must fail. Use an
	// invalid protocol here, never a real TUN, so a regression is safe to test.
	confDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(confDir, "unexpected.json"), []byte(`{"inbounds":[{"protocol":"bx-ui-unexpected-env-config","port":10999}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_CONFDIR", confDir)
	t.Setenv("xray.location.confdir", confDir)
	for _, test := range []struct {
		name     string
		protocol string
		settings string
		wantErr  bool
	}{
		{name: "http", protocol: "http", settings: `{}`},
		{name: "vmess", protocol: "vmess", settings: `{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}`},
		{name: "tun-safe-probe", protocol: "tun", settings: `{"name":"bxuitest0","MTU":1500}`},
		{name: "unsupported-protocol", protocol: "bx-ui-invalid-protocol", settings: `{}`, wantErr: true},
		{name: "invalid-vmess", protocol: "vmess", settings: `{"clients":[{"id":"not-a-valid-uuid-password-secret"}]}`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{
				InboundConfigs: []InboundConfig{{Protocol: test.protocol, Port: 10877,
					Listen: json_util.RawMessage(`"127.0.0.1"`), Settings: json_util.RawMessage(test.settings)}},
				OutboundConfigs: json_util.RawMessage(`[{"protocol":"freedom"}]`),
			}
			err := validateConfig(config, binary, t.TempDir(), func() error { return nil }, configTestTimeout)
			if (err != nil) != test.wantErr {
				t.Fatalf("unexpected installed-core validation result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "password-secret") {
				t.Fatal("installed core error exposed credentials")
			}
		})
	}
}
