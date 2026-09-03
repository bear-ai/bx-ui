package service

import (
	"encoding/json"
	"errors"
	"sync"
	"x-ui/logger"
	"x-ui/xray"

	"go.uber.org/atomic"
)

var p *xray.Process
var lock sync.RWMutex
var isNeedXrayRestart atomic.Bool
var result string

type XrayService struct {
	inboundService InboundService
	settingService SettingService
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
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}

	inbounds, err := s.inboundService.GetAllInbounds()
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

	if p != nil && p.IsRunning() {
		if !isForce && p.GetConfig().Equals(xrayConfig) {
			logger.Debug("not need to restart xray")
			return nil
		}
		if err := p.Stop(); err != nil {
			logger.Warning("stop old xray process failed:", err)
		}
	}

	p = xray.NewProcess(xrayConfig)
	result = ""
	return p.Start()
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
