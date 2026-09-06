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
		INSERT INTO users(username, password) VALUES ('legacy-admin', 'old-pw');`)
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
	user := users.CheckUser("legacy-admin", "old-pw")
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
	if users.CheckUser("legacy-admin", "old-pw") != nil {
		t.Fatal("old password remains valid")
	}
	if users.CheckUser("legacy-admin", "replacement-password-456") == nil {
		t.Fatal("new password is not valid")
	}
}

func TestUserPasswordMinimumAndRejectedUpdate(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	users := UserService{}
	if err := users.UpdateFirstUser("admin", "eight-pw"); err != nil {
		t.Fatal(err)
	}
	user := users.CheckUser("admin", "eight-pw")
	if user == nil {
		t.Fatal("eight-character password cannot log in")
	}
	if err := users.UpdateFirstUser("changed-admin", "shortpw"); err == nil {
		t.Fatal("CLI account update accepted seven-character password")
	}
	if _, err := users.UpdateUser(user.Id, "changed-admin", "shortpw"); err == nil {
		t.Fatal("panel account update accepted seven-character password")
	}
	unchanged, err := users.GetUser(user.Id)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Username != user.Username || unchanged.PasswordHash != user.PasswordHash || unchanged.SessionVersion != user.SessionVersion {
		t.Fatal("rejected password update changed account or sessions")
	}
	updated, err := users.UpdateUser(user.Id, "admin", "new-pass")
	if err != nil {
		t.Fatal(err)
	}
	if updated.SessionVersion <= user.SessionVersion || users.CheckUser("admin", "new-pass") == nil {
		t.Fatal("eight-character panel update did not change password and revoke old sessions")
	}
}
