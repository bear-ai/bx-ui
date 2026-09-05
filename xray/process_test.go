package xray

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessDetectsImmediateStartupFailure(t *testing.T) {
	binary := testExecutable(t, `if test "$1" = -version; then echo 'Xray 26.3.27'; exit 0; fi
echo 'failed to bind'
exit 23
`)
	p := newProcess(&Config{})
	if err := p.start(binary, filepath.Join(t.TempDir(), "config.json")); err == nil {
		t.Fatal("immediate startup failure reported as success")
	}
	if p.IsRunning() {
		t.Fatal("failed process still marked running")
	}
}

func TestProcessStopWaitsForExit(t *testing.T) {
	t.Setenv("XRAY_LOCATION_CONFDIR", "/must-not-merge")
	t.Setenv("xray.location.confdir", "/must-not-merge-alias")
	binary := testExecutable(t, `if test "$1" = -version; then echo 'Xray 26.3.27'; exit 0; fi
if env | grep -E '^(XRAY_LOCATION_CONFDIR|xray\.location\.confdir)='; then exit 90; fi
exec sleep 60
`)
	p := newProcess(&Config{})
	path := filepath.Join(t.TempDir(), "config.json")
	if err := p.start(binary, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop() })
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected config permissions: %v, %v", info, err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if p.IsRunning() {
		t.Fatal("Stop returned before process exit")
	}
}
