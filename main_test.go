package main

import (
	"bytes"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	passwordutil "x-ui/util/password"
)

// Run the real command entry point in a child process so exit statuses and
// stdin handling are covered without accessing the host's installed database.
func TestSettingCommandHelper(t *testing.T) {
	if os.Getenv("BX_UI_SETTING_TEST_HELPER") != "1" {
		return
	}
	for i, argument := range os.Args {
		if argument == "--" {
			os.Args = append([]string{"bx-ui", "setting"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(99)
}

func runSettingCommand(t *testing.T, dbPath, input string, arguments ...string) (int, string) {
	t.Helper()
	command := exec.Command(os.Args[0], append([]string{"-test.run=^TestSettingCommandHelper$", "--"}, arguments...)...)
	command.Env = append(os.Environ(), "BX_UI_SETTING_TEST_HELPER=1", "XUI_DB_PATH="+dbPath)
	command.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), output.String()
		}
		t.Fatal(err)
	}
	return 0, output.String()
}

func TestSettingPasswordValidationHasNoSideEffects(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		valid bool
		hint  string
	}{
		{"empty", "\n", false, "至少需要 8 个字符"},
		{"seven characters", "1234567\n", false, "至少需要 8 个字符"},
		{"eight characters", "eight-pw\n", true, ""},
		{"CRLF input", "eight-pw\r\n", true, ""},
		{"seven Unicode characters", strings.Repeat("密", 7) + "\n", false, "至少需要 8 个字符"},
		{"eight Unicode characters", strings.Repeat("密", 8) + "\n", true, ""},
		{"72 bytes", strings.Repeat("a", 72) + "\n", true, ""},
		{"73 bytes", strings.Repeat("a", 73) + "\n", false, "不能超过 72 字节"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "untouched", "x-ui.db")
			status, output := runSettingCommand(t, dbPath, tt.input,
				"-validate-password", "-password-stdin", "-port", "12345", "-username", "admin", "-show", "-reset")
			if (status == 0) != tt.valid {
				t.Fatalf("unexpected status %d: %s", status, output)
			}
			if !strings.Contains(output, tt.hint) {
				t.Fatalf("missing validation explanation: %s", output)
			}
			if plain := strings.TrimRight(tt.input, "\r\n"); plain != "" && strings.Contains(output, plain) {
				t.Fatal("command exposed the password")
			}
			if _, err := os.Stat(filepath.Dir(dbPath)); !os.IsNotExist(err) {
				t.Fatalf("validation touched database directory: %v", err)
			}
		})
	}
}

func TestSettingRejectsInvalidCredentialsBeforeWriting(t *testing.T) {
	for _, tt := range []struct {
		name      string
		input     string
		arguments []string
	}{
		{"short password", "1234567\n", []string{"-username", "admin", "-password-stdin", "-port", "12345"}},
		{"empty password", "\n", []string{"-password-stdin"}},
		{"missing password", "", []string{"-username", "admin"}},
		{"invalid username", "eight-pw\n", []string{"-username", "ab", "-password-stdin", "-port", "12345"}},
		{"missing stdin flag", "eight-pw\n", []string{"-validate-password"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "untouched", "x-ui.db")
			status, output := runSettingCommand(t, dbPath, tt.input, tt.arguments...)
			if status == 0 || strings.Contains(output, "success") {
				t.Fatalf("invalid credentials reported success: %d %s", status, output)
			}
			if _, err := os.Stat(filepath.Dir(dbPath)); !os.IsNotExist(err) {
				t.Fatalf("invalid credentials touched the database: %v", err)
			}
		})
	}
}

func TestSettingSavesEightCharacterPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	// Spaces and shell metacharacters must be preserved, not evaluated or trimmed.
	plain := " p$!\\w? "
	status, output := runSettingCommand(t, dbPath, plain+"\n", "-username", "admin", "-password-stdin")
	if status != 0 || !strings.Contains(output, "set username and password success") {
		t.Fatalf("valid credentials failed: %d %s", status, output)
	}
	if strings.Contains(output, plain) {
		t.Fatal("command exposed the password")
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hash string
	if err := db.QueryRow("SELECT password FROM users WHERE username = ?", "admin").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !passwordutil.IsHash(hash) || !passwordutil.Compare(hash, plain) {
		t.Fatal("password was not saved correctly as a hash")
	}
	status, output = runSettingCommand(t, dbPath, "", "-port", "12345")
	if status != 0 || !strings.Contains(output, "set port 12345 success") {
		t.Fatalf("port-only update failed: %d %s", status, output)
	}
}

func TestSettingDatabaseFailureReturnsNonzero(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	status, output := runSettingCommand(t, filepath.Join(blocker, "x-ui.db"), "eight-pw\n", "-username", "admin", "-password-stdin")
	if status == 0 || strings.Contains(output, "success") {
		t.Fatalf("database failure reported success: %d %s", status, output)
	}
}
