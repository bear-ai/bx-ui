package service

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"x-ui/database"
	"x-ui/util/password"
)

func TestLegacyPasswordMigrationAndRevocation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	legacyDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacyDB.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT);
		INSERT INTO users(username, password) VALUES ('legacy-admin', 'short-old');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatal(err)
	}

	if err := database.InitDB(dbPath); err != nil {
		t.Fatal(err)
	}
	users := UserService{}
	if err := users.MigratePasswordHashes(); err != nil {
		t.Fatal(err)
	}
	user := users.CheckUser("legacy-admin", "short-old")
	if user == nil || !password.IsHash(user.PasswordHash) {
		t.Fatal("legacy password was not upgraded")
	}
	oldVersion := user.SessionVersion
	updated, err := users.UpdateUser(user.Id, "legacy-admin", "replacement-password-456")
	if err != nil {
		t.Fatal(err)
	}
	if updated.SessionVersion <= oldVersion {
		t.Fatal("password change did not revoke prior sessions")
	}
	if users.CheckUser("legacy-admin", "short-old") != nil {
		t.Fatal("old password remains valid")
	}
	if users.CheckUser("legacy-admin", "replacement-password-456") == nil {
		t.Fatal("new password is not valid")
	}
}
