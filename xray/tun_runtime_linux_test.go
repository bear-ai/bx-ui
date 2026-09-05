//go:build linux

package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"x-ui/util/json_util"
	"x-ui/util/tunsetup"
)

// TestTUNRuntimeSystemd is deliberately opt-in. It needs root only to create two
// transient systemd units. Both workers and the real core run as nobody inside
// their own network namespace; host interfaces and production services are never
// touched. A missing prerequisite is a failure when CI enables the test.
func TestTUNRuntimeSystemd(t *testing.T) {
	if os.Getenv("BX_UI_TUN_RUNTIME") != "1" {
		t.Skip("requires explicit BX_UI_TUN_RUNTIME=1, root and systemd; executed by Linux CI")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the isolated systemd test launcher must be root")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("BX_UI_SOURCE_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("BX_UI_SOURCE_ROOT must be an absolute source checkout path")
	}
	binary := os.Getenv("XRAY_TEST_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("XRAY_TEST_BINARY must be an absolute path accessible to nobody")
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base, tun := tunRuntimeServiceProperties(t, root)
	for _, enabled := range []bool{false, true} {
		mode := "denied"
		if enabled {
			mode = "enabled"
		}
		t.Run(mode, func(t *testing.T) {
			properties := make(map[string]string, len(base)+len(tun))
			for key, value := range base {
				properties[key] = value
			}
			if enabled {
				for key, value := range tun {
					properties[key] = value
				}
			}
			// These differences relocate the same sandbox to a disposable worker.
			// Its writable temporary directory is supplied by PrivateTmp=true.
			properties["User"] = "nobody"
			properties["Group"] = "nogroup"
			properties["WorkingDirectory"] = "/tmp"
			properties["ReadWritePaths"] = "/tmp"
			properties["PrivateNetwork"] = "true"
			properties["RuntimeMaxSec"] = "45s"
			properties["TimeoutStopSec"] = "5s"
			args := []string{"--quiet", "--wait", "--pipe", "--collect",
				"--unit=" + fmt.Sprintf("bx-ui-tun-test-%d-%s", os.Getpid(), mode),
				"--setenv=BX_UI_TUN_RUNTIME_WORKER=" + mode,
				"--setenv=XRAY_TEST_BINARY=" + binary}
			keys := make([]string, 0, len(properties))
			for key := range properties {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				args = append(args, "--property="+key+"="+properties[key])
			}
			args = append(args, testBinary, "-test.run=^TestTUNRuntimeSandboxWorker$", "-test.v", "-test.timeout=40s")
			ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("%s production sandbox: %v\n%s", mode, err, output)
			}
			t.Logf("%s", output)
		})
	}
}

func TestTUNRuntimeSandboxWorker(t *testing.T) {
	mode := os.Getenv("BX_UI_TUN_RUNTIME_WORKER")
	if mode == "" {
		t.Skip("launched only by TestTUNRuntimeSystemd")
	}
	if os.Geteuid() == 0 {
		t.Fatal("TUN workers and Xray must run without root")
	}
	before := tunRuntimeInterfaces(t)
	if len(before) != 1 || before[0].Name != "lo" {
		t.Fatalf("expected a private network namespace with only loopback, got %+v", before)
	}
	// A panel account must not be able to opt itself into system-wide privileges.
	if err := tunsetup.Configure(true); err == nil || !strings.Contains(err.Error(), "Linux root") {
		t.Fatalf("unprivileged TUN authorization was not rejected: %v", err)
	}
	if mode == "denied" {
		if err := CheckTUNSupport(); err == nil {
			t.Fatal("default service sandbox unexpectedly permits TUN")
		} else {
			t.Logf("default sandbox rejects TUN before core startup: %v", err)
		}
		if after := tunRuntimeInterfaces(t); !reflect.DeepEqual(after, before) {
			t.Fatalf("denied preflight changed interfaces: before=%+v after=%+v", before, after)
		}
		return
	}
	if mode != "enabled" {
		t.Fatalf("unknown worker mode %q", mode)
	}
	if err := CheckTUNSupport(); err != nil {
		t.Fatalf("TUN opt-in does not work under the production sandbox: %v", err)
	}
	if after := tunRuntimeInterfaces(t); !reflect.DeepEqual(after, before) {
		t.Fatalf("permission check created or changed interfaces: before=%+v after=%+v", before, after)
	}

	binary := os.Getenv("XRAY_TEST_BINARY")
	dir := t.TempDir()
	config := &Config{
		LogConfig: json_util.RawMessage(`{"loglevel":"info"}`),
		InboundConfigs: []InboundConfig{{
			Protocol: "tun", Tag: "tun-runtime", Port: 12345,
			Settings: json_util.RawMessage(`{"name":"bxuici0","MTU":1400,"userLevel":0}`),
		}},
		OutboundConfigs: json_util.RawMessage(`[{"protocol":"freedom"}]`),
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "xray.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(binary, "run", "-c", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			output, _ := os.ReadFile(logPath)
			t.Logf("real Xray output:\n%s", output)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		iface, err := net.InterfaceByName("bxuici0")
		if err == nil && iface.MTU == 1400 && iface.Flags&net.FlagUp != 0 {
			break
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("real Xray exited before creating its TUN interface: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("real Xray did not create and enable bxuici0 with MTU 1400")
		}
		time.Sleep(20 * time.Millisecond)
	}
	running := tunRuntimeInterfaces(t)
	if len(running) != 2 {
		t.Fatalf("unexpected interfaces while Xray is running: %+v", running)
	}
	// Validate a changed MTU while the old core owns the same name. A dangerous
	// real `xray -test` preflight would attach/mutate the device or fail as busy.
	config.InboundConfigs[0].Settings = json_util.RawMessage(`{"name":"bxuici0","MTU":1500,"userLevel":0}`)
	for i := 0; i < 3; i++ {
		if err := CheckTUNSupport(); err != nil {
			t.Fatalf("non-mutating permission check %d failed: %v", i, err)
		}
		if err := validateConfig(config, binary, dir, CheckTUNSupport, 10*time.Second); err != nil {
			t.Fatalf("non-mutating configuration preflight %d failed: %v", i, err)
		}
		if after := tunRuntimeInterfaces(t); !reflect.DeepEqual(after, running) {
			t.Fatalf("preflight modified the running interface: before=%+v after=%+v", running, after)
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("preflight stopped the running Xray core: %v", err)
		default:
		}
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("Xray did not shut down cleanly: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Xray did not shut down after SIGTERM")
	}
	if after := tunRuntimeInterfaces(t); !reflect.DeepEqual(after, before) {
		t.Fatalf("Xray shutdown left or changed interfaces: before=%+v after=%+v", before, after)
	}
	t.Log("non-root Xray created and removed a real TUN; repeated preflight preserved its name, index, MTU and flags")
}

func tunRuntimeInterfaces(t *testing.T) []net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })
	return interfaces
}

// Read the checked-in unit and the actual administrator-managed drop-in, so the
// runtime test cannot silently drift to a more permissive hand-written sandbox.
func tunRuntimeServiceProperties(t *testing.T, root string) (map[string]string, map[string]string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "x-ui.service"))
	if err != nil {
		t.Fatal(err)
	}
	parse := func(text string) map[string]string {
		result := map[string]string{}
		service := false
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				service = line == "[Service]"
				continue
			}
			if !service || line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("invalid service property %q", line)
			}
			if strings.HasPrefix(key, "Exec") || key == "Type" || key == "Restart" || key == "RestartSec" {
				continue
			}
			if _, exists := result[key]; exists {
				t.Fatalf("duplicate %s requires explicit runtime-test support", key)
			}
			result[key] = value
		}
		return result
	}
	base := parse(string(data))
	source, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "util/tunsetup/setup.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var dropIn string
	ast.Inspect(source, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "dropIn" || len(spec.Values) != 1 {
			return true
		}
		literal, ok := spec.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatal("TUN dropIn must be a string constant")
		}
		dropIn, err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		return false
	})
	if dropIn == "" || base["PrivateDevices"] != "true" {
		t.Fatal("could not locate production TUN opt-in and default device sandbox")
	}
	return base, parse(dropIn)
}
