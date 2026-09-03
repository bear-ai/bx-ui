package password

import "testing"

func TestHashAndCompare(t *testing.T) {
	plain := "correct horse battery staple"
	hash, err := Hash(plain)
	if err != nil {
		t.Fatal(err)
	}
	if hash == plain || !IsHash(hash) {
		t.Fatal("password was not stored as a bcrypt hash")
	}
	if !Compare(hash, plain) || Compare(hash, "wrong password") {
		t.Fatal("password comparison returned an invalid result")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if ValidatePassword("too-short") == nil {
		t.Fatal("short password was accepted")
	}
	if ValidateUsername("ab") == nil {
		t.Fatal("short username was accepted")
	}
}
