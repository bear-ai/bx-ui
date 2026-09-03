package service

import (
	"errors"
	"os"
	"x-ui/database"
	"x-ui/database/model"
	"x-ui/util/password"
	"x-ui/util/random"

	"gorm.io/gorm"
)

type UserService struct{}

func (s *UserService) GetFirstUser() (*model.User, error) {
	user := &model.User{}
	err := database.GetDB().Model(model.User{}).First(user).Error
	return user, err
}

func (s *UserService) GetUser(id int) (*model.User, error) {
	user := &model.User{}
	err := database.GetDB().Model(model.User{}).First(user, id).Error
	return user, err
}

func (s *UserService) CheckUser(username, plainPassword string) *model.User {
	user := &model.User{}
	err := database.GetDB().Model(model.User{}).Where("username = ?", username).First(user).Error
	if err != nil {
		_ = password.Compare(string(password.DummyHash), plainPassword)
		return nil
	}
	if !password.Compare(user.PasswordHash, plainPassword) {
		return nil
	}
	return user
}

func (s *UserService) VerifyPassword(user *model.User, plainPassword string) bool {
	return user != nil && password.Compare(user.PasswordHash, plainPassword)
}

func (s *UserService) UpdateUser(id int, username, plainPassword string) (*model.User, error) {
	if err := password.ValidateUsername(username); err != nil {
		return nil, err
	}
	hash, err := password.Hash(plainPassword)
	if err != nil {
		return nil, err
	}
	user, err := s.GetUser(id)
	if err != nil {
		return nil, err
	}
	user.Username = username
	user.PasswordHash = hash
	user.SessionVersion++
	err = database.GetDB().Save(user).Error
	return user, err
}

func (s *UserService) UpdateFirstUser(username, plainPassword string) error {
	if err := password.ValidateUsername(username); err != nil {
		return err
	}
	hash, err := password.Hash(plainPassword)
	if err != nil {
		return err
	}
	user, err := s.GetFirstUser()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return database.GetDB().Create(&model.User{Username: username, PasswordHash: hash, SessionVersion: 1}).Error
	}
	if err != nil {
		return err
	}
	user.Username = username
	user.PasswordHash = hash
	user.SessionVersion++
	return database.GetDB().Save(user).Error
}

// MigratePasswordHashes transparently upgrades legacy plaintext passwords.
func (s *UserService) MigratePasswordHashes() error {
	var users []*model.User
	if err := database.GetDB().Find(&users).Error; err != nil {
		return err
	}
	for _, user := range users {
		changed := false
		if !password.IsHash(user.PasswordHash) {
			hash, err := password.HashLegacy(user.PasswordHash)
			if err != nil {
				return errors.New("旧账号密码无法安全迁移，请先通过命令行重置密码")
			}
			user.PasswordHash = hash
			changed = true
		}
		if user.SessionVersion == 0 {
			user.SessionVersion = 1
			changed = true
		}
		if changed {
			if err := database.GetDB().Save(user).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// EnsureInitialUser creates a strong one-time account instead of admin/admin.
func (s *UserService) EnsureInitialUser() (string, string, bool, error) {
	var count int64
	if err := database.GetDB().Model(&model.User{}).Count(&count).Error; err != nil {
		return "", "", false, err
	}
	if count != 0 {
		return "", "", false, nil
	}
	username := os.Getenv("XUI_USERNAME")
	if username == "" {
		username = "admin"
	}
	plainPassword := os.Getenv("XUI_PASSWORD")
	if plainPassword == "" {
		plainPassword = random.Seq(24)
	}
	if err := s.UpdateFirstUser(username, plainPassword); err != nil {
		return "", "", false, err
	}
	return username, plainPassword, true, nil
}
