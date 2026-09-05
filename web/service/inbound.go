package service

import (
	"fmt"
	"time"
	"x-ui/database"
	"x-ui/database/model"
	"x-ui/util/common"
	"x-ui/xray"

	"gorm.io/gorm"
)

type InboundService struct {
	validateConfig func(*xray.Config) error
	applyConfig    func(*xray.Config) error
}

// validateCandidates builds the exact proposed active configuration without
// touching the database. Callers hold lock until the corresponding DB commit.
func (s *InboundService) validateCandidates(candidates []*model.Inbound) (*xray.Config, error) {
	all, err := s.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		found := false
		for index, existing := range all {
			if candidate.Id != 0 && candidate.Id == existing.Id {
				all[index] = candidate
				found = true
				break
			}
		}
		if !found {
			all = append(all, candidate)
		}
	}
	service := &XrayService{}
	config, err := service.configWithInbounds(all)
	if err != nil {
		return nil, err
	}
	validate := s.validateConfig
	if validate == nil {
		validate = xray.ValidateConfig
	}
	if err := validate(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (s *InboundService) applyPreparedConfig(config *xray.Config) error {
	if p != nil && p.IsRunning() && p.GetConfig().Equals(config) {
		return nil
	}
	if s.applyConfig != nil {
		return s.applyConfig(config)
	}
	return (&XrayService{}).replaceProcess(config)
}

// saveAndApply keeps the database and runtime in agreement for interactive
// changes. The caller holds lock, so another mutation/restart cannot interleave.
func (s *InboundService) saveAndApply(config *xray.Config, save func(*gorm.DB) error) error {
	var previous *xray.Config
	if p != nil && p.IsRunning() {
		previous = p.GetConfig()
	}
	applied := false
	err := database.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := save(tx); err != nil {
			return err
		}
		if err := s.applyPreparedConfig(config); err != nil {
			// replaceProcess restores the old running instance on startup error;
			// returning an error here also rolls back the candidate DB record.
			return err
		}
		applied = true
		return nil
	})
	if err == nil || !applied {
		return err
	}
	// A successful process switch is not a successful save if COMMIT failed.
	// Restore the exact pre-transaction running state as well as rolling back DB.
	var restoreErr error
	if previous != nil {
		restoreErr = s.applyPreparedConfig(previous)
	} else if p != nil && p.IsRunning() {
		restoreErr = p.Stop()
		if restoreErr == nil {
			p = nil
		}
	}
	if restoreErr != nil {
		return common.NewError("保存入站失败，恢复原运行状态也失败，请检查内核运行日志")
	}
	return err
}

func (s *InboundService) GetInbounds(userId int) ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("user_id = ?", userId).Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return inbounds, nil
}

func (s *InboundService) GetAllInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Find(&inbounds).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return inbounds, nil
}

func (s *InboundService) checkPortExist(port int, ignoreId int) (bool, error) {
	db := database.GetDB()
	db = db.Model(model.Inbound{}).Where("port = ?", port)
	if ignoreId > 0 {
		db = db.Where("id != ?", ignoreId)
	}
	var count int64
	err := db.Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *InboundService) AddInbound(inbound *model.Inbound) error {
	lock.Lock()
	defer lock.Unlock()
	// Creation must never turn a submitted primary key into an update.
	inbound.Id = 0
	exist, err := s.checkPortExist(inbound.Port, 0)
	if err != nil {
		return err
	}
	if exist {
		return common.NewError("端口已存在:", inbound.Port)
	}
	config, err := s.validateCandidates([]*model.Inbound{inbound})
	if err != nil {
		return err
	}
	return s.saveAndApply(config, func(tx *gorm.DB) error { return tx.Create(inbound).Error })
}

func (s *InboundService) AddInbounds(inbounds []*model.Inbound) error {
	lock.Lock()
	defer lock.Unlock()
	for _, inbound := range inbounds {
		exist, err := s.checkPortExist(inbound.Port, 0)
		if err != nil {
			return err
		}
		if exist {
			return common.NewError("端口已存在:", inbound.Port)
		}
	}
	if _, err := s.validateCandidates(inbounds); err != nil {
		return err
	}

	db := database.GetDB()
	return db.Transaction(func(tx *gorm.DB) error {
		for _, inbound := range inbounds {
			if err := tx.Save(inbound).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *InboundService) DelInbound(id, userID int) error {
	lock.Lock()
	defer lock.Unlock()
	db := database.GetDB()
	result := db.Where("id = ? AND user_id = ?", id, userID).Delete(&model.Inbound{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (s *InboundService) GetInbound(id int) (*model.Inbound, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}
	err := db.Model(model.Inbound{}).First(inbound, id).Error
	if err != nil {
		return nil, err
	}
	return inbound, nil
}

func (s *InboundService) GetInboundForUser(id, userID int) (*model.Inbound, error) {
	db := database.GetDB()
	inbound := &model.Inbound{}
	err := db.Model(model.Inbound{}).
		Where("id = ? AND user_id = ?", id, userID).
		First(inbound).Error
	if err != nil {
		return nil, err
	}
	return inbound, nil
}

func (s *InboundService) UpdateInbound(userID int, inbound *model.Inbound) error {
	lock.Lock()
	defer lock.Unlock()
	exist, err := s.checkPortExist(inbound.Port, inbound.Id)
	if err != nil {
		return err
	}
	if exist {
		return common.NewError("端口已存在:", inbound.Port)
	}

	oldInbound, err := s.GetInbound(inbound.Id)
	if err != nil {
		return err
	}
	if oldInbound.UserId != userID {
		return gorm.ErrRecordNotFound
	}
	oldInbound.Up = inbound.Up
	oldInbound.Down = inbound.Down
	oldInbound.Total = inbound.Total
	oldInbound.Remark = inbound.Remark
	oldInbound.Enable = inbound.Enable
	oldInbound.ExpiryTime = inbound.ExpiryTime
	oldInbound.Listen = inbound.Listen
	oldInbound.Port = inbound.Port
	oldInbound.Protocol = inbound.Protocol
	oldInbound.Settings = inbound.Settings
	oldInbound.StreamSettings = inbound.StreamSettings
	oldInbound.Sniffing = inbound.Sniffing
	oldInbound.Tag = fmt.Sprintf("inbound-%v", inbound.Port)
	config, err := s.validateCandidates([]*model.Inbound{oldInbound})
	if err != nil {
		return err
	}
	return s.saveAndApply(config, func(tx *gorm.DB) error { return tx.Save(oldInbound).Error })
}

func (s *InboundService) AddTraffic(traffics []*xray.Traffic) (err error) {
	if len(traffics) == 0 {
		return nil
	}
	db := database.GetDB()
	db = db.Model(model.Inbound{})
	tx := db.Begin()
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()
	for _, traffic := range traffics {
		if traffic.IsInbound {
			err = tx.Where("tag = ?", traffic.Tag).
				UpdateColumn("up", gorm.Expr("up + ?", traffic.Up)).
				UpdateColumn("down", gorm.Expr("down + ?", traffic.Down)).
				Error
			if err != nil {
				return
			}
		}
	}
	return
}

func (s *InboundService) DisableInvalidInbounds() (int64, error) {
	lock.Lock()
	defer lock.Unlock()
	db := database.GetDB()
	now := time.Now().Unix() * 1000
	result := db.Model(model.Inbound{}).
		Where("((total > 0 and up + down >= total) or (expiry_time > 0 and expiry_time <= ?)) and enable = ?", now, true).
		Update("enable", false)
	err := result.Error
	count := result.RowsAffected
	return count, err
}
