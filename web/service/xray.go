package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/xray"

	"go.uber.org/atomic"
)

type xrayProcess interface {
	IsRunning() bool
	GetErr() error
	GetResult() string
	GetVersion() string
	GetConfig() *xray.Config
	GetTraffic(bool) ([]*xray.Traffic, error)
	Start() error
	Stop() error
}

var p xrayProcess
var lock sync.RWMutex
var isNeedXrayRestart atomic.Bool
var result string

type XrayService struct {
	inboundService InboundService
	settingService SettingService
	validateConfig func(*xray.Config) error
	newProcess     func(*xray.Config) xrayProcess
}

func (s *XrayService) IsXrayRunning() bool {
	lock.RLock()
	defer lock.RUnlock()
	return p != nil && p.IsRunning()
}

func (s *XrayService) GetXrayErr() error {
	lock.RLock()
	defer lock.RUnlock()
	if p == nil {
		return nil
	}
	return p.GetErr()
}

func (s *XrayService) GetXrayResult() string {
	lock.Lock()
	defer lock.Unlock()
	if result != "" {
		return result
	}
	if p != nil && p.IsRunning() {
		return ""
	}
	if p == nil {
		return ""
	}
	result = p.GetResult()
	return result
}

func (s *XrayService) GetXrayVersion() string {
	lock.RLock()
	defer lock.RUnlock()
	if p == nil {
		return "Unknown"
	}
	return p.GetVersion()
}

func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	return s.configWithInbounds(inbounds)
}

func (s *XrayService) configWithInbounds(inbounds []*model.Inbound) (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		inboundConfig := inbound.GenXrayInboundConfig()
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
	}
	return xrayConfig, nil
}

func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, error) {
	lock.RLock()
	defer lock.RUnlock()
	if p == nil || !p.IsRunning() {
		return nil, errors.New("xray is not running")
	}
	return p.GetTraffic(true)
}

func (s *XrayService) RestartXray(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("restart xray, force:", isForce)

	xrayConfig, err := s.GetXrayConfig()
	if err != nil {
		return err
	}

	if p != nil && p.IsRunning() && !isForce && p.GetConfig().Equals(xrayConfig) {
		logger.Debug("not need to restart xray")
		return nil
	}
	validate := s.validateConfig
	if validate == nil {
		validate = xray.ValidateConfig
	}
	if err := validate(xrayConfig); err != nil {
		return err
	}
	return s.replaceProcess(xrayConfig)
}

func (s *XrayService) replaceProcess(config *xray.Config) error {
	create := s.newProcess
	if create == nil {
		create = func(config *xray.Config) xrayProcess { return xray.NewProcess(config) }
	}
	var previous *xray.Config
	if p != nil && p.IsRunning() {
		previous = p.GetConfig()
		if err := p.Stop(); err != nil {
			return fmt.Errorf("停止旧 Xray 实例失败，已取消配置切换: %w", err)
		}
	}
	p = create(config)
	result = ""
	if err := p.Start(); err != nil {
		if previous == nil {
			return err
		}
		p = create(previous)
		if restoreErr := p.Start(); restoreErr != nil {
			return errors.New("新 Xray 配置启动失败，恢复旧配置也失败，请检查内核运行日志")
		}
		return errors.New("新 Xray 配置启动失败，已恢复运行中的旧配置，请检查端口占用和系统权限")
	}
	return nil
}

func (s *XrayService) StopXray() error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("stop xray")
	if p != nil && p.IsRunning() {
		return p.Stop()
	}
	return errors.New("xray is not running")
}

func (s *XrayService) SetToNeedRestart() {
	isNeedXrayRestart.Store(true)
}

func (s *XrayService) IsNeedRestartAndSetFalse() bool {
	return isNeedXrayRestart.CAS(true, false)
}
