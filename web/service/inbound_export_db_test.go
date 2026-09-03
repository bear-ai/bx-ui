package service

import (
	"errors"
	"path/filepath"
	"testing"

	"gorm.io/gorm"
	"x-ui/database"
	"x-ui/database/model"
)

func TestExportClientConfigIsScopedToOwner(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	db := database.GetDB()
	owner := &model.User{Username: "owner", PasswordHash: "unused", SessionVersion: 1}
	other := &model.User{Username: "other", PasswordHash: "unused", SessionVersion: 1}
	if err := db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	inbound := exportInbound(model.VMess,
		`{"clients":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}`,
		`{"network":"tcp","security":"none"}`)
	inbound.UserId = owner.Id
	inbound.Tag = "inbound-443"
	if err := db.Create(inbound).Error; err != nil {
		t.Fatal(err)
	}

	service := InboundService{}
	if _, err := service.ExportClientConfig(inbound.Id, other.Id, "example.com"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("another user could access the exported config: %v", err)
	}
	if _, err := service.ExportClientConfig(inbound.Id, owner.Id, "example.com"); err != nil {
		t.Fatalf("owner could not export config: %v", err)
	}
}
