package tunsetup

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEnableDisable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x-ui.service.d")
	var calls []string
	run := func(action string) error { calls = append(calls, action); return nil }
	for _, enable := range []bool{true, true, false, false} {
		calls = nil
		if err := configureAt(dir, enable, run); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(calls, []string{"daemon-reload", "restart"}) {
			t.Fatalf("calls: %v", calls)
		}
		data, err := os.ReadFile(filepath.Join(dir, dropInName))
		if enable && (err != nil || string(data) != dropIn) {
			t.Fatalf("missing drop-in: %v", err)
		}
		if !enable && !os.IsNotExist(err) {
			t.Fatalf("drop-in remains: %v", err)
		}
	}
	for _, required := range []string{"DevicePolicy=closed", "DeviceAllow=/dev/net/tun rw", "CAP_NET_ADMIN"} {
		if !strings.Contains(dropIn, required) {
			t.Fatalf("missing %s", required)
		}
	}
	if strings.Contains(dropIn, "User=root") || strings.Contains(dropIn, "CAP_SYS_ADMIN") {
		t.Fatal("excess permissions")
	}
}

func TestRefusesUnmanagedFilesAndSymlinks(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		dir := t.TempDir()
		target := filepath.Join(dir, dropInName)
		if symlink {
			if err := os.Symlink("elsewhere", target); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(target, []byte("custom configuration"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, enable := range []bool{true, false} {
			if err := configureAt(dir, enable, func(string) error { t.Fatal("must not reload"); return nil }); err == nil {
				t.Fatal("accepted unmanaged file")
			}
		}
	}
}

func TestReloadFailureDoesNotRestart(t *testing.T) {
	want := errors.New("reload failed")
	err := configureAt(t.TempDir(), true, func(action string) error {
		if action != "daemon-reload" {
			t.Fatal("restart after failed reload")
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
}
