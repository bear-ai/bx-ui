package password

import (
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// DummyHash makes unknown-user and wrong-password checks take comparable time.
var DummyHash = []byte("$2a$12$j8IqShQ1J8qOZC8V.WkDpu8AuRhukr0EGhIbwxmv21KNp0dMYQ1le")

func Hash(value string) (string, error) {
	if err := ValidatePassword(value); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(value), bcryptCost)
	return string(hash), err
}

func Compare(hash, value string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(value)) == nil
}

func IsHash(value string) bool {
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}

func ValidateUsername(value string) error {
	n := utf8.RuneCountInString(value)
	if n < 3 || n > 64 {
		return errors.New("用户名长度必须为 3 至 64 个字符")
	}
	return nil
}

func ValidatePassword(value string) error {
	n := utf8.RuneCountInString(value)
	if n < 12 || len([]byte(value)) > 72 {
		return errors.New("密码至少需要 12 个字符，且 UTF-8 编码后不能超过 72 字节")
	}
	return nil
}
