package password

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

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
	if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost != 12 {
		t.Fatal("bcrypt cost must remain 12")
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
		valid bool
	}{
		{"empty", "", false},
		{"seven characters", "1234567", false},
		{"eight characters", "12345678", true},
		{"eleven characters", "12345678901", true},
		{"twelve characters", "123456789012", true},
		{"72 bytes", strings.Repeat("a", 72), true},
		{"73 bytes", strings.Repeat("a", 73), false},
		{"seven Unicode characters", strings.Repeat("密", 7), false},
		{"eight Unicode characters", strings.Repeat("密", 8), true},
		{"Unicode 72 bytes", strings.Repeat("密", 24), true},
		{"Unicode over 72 bytes", strings.Repeat("密", 25), false},
		{"eight emoji", strings.Repeat("🔑", 8), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.value)
			if (err == nil) != tt.valid {
				t.Fatalf("valid = %v, error = %v", tt.valid, err)
			}
		})
	}
	if ValidateUsername("ab") == nil {
		t.Fatal("short username was accepted")
	}
}

func TestHashLegacyPreservesShortExistingPassword(t *testing.T) {
	plain := "old-pw"
	hash, err := HashLegacy(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !Compare(hash, plain) {
		t.Fatal("legacy password was not preserved during hashing")
	}
	if _, err := Hash(plain); err == nil {
		t.Fatal("new password policy accepted a short password")
	}
}

func TestHashAcceptsEightCharacterPassword(t *testing.T) {
	hash, err := Hash("eight-pw")
	if err != nil {
		t.Fatal(err)
	}
	if !Compare(hash, "eight-pw") {
		t.Fatal("eight-character password cannot be verified")
	}
}
