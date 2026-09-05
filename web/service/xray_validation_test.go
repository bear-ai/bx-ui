package service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"x-ui/database"
	"x-ui/database/model"
	"x-ui/xray"

	"gorm.io/gorm"
)

func initInboundValidationDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "panel.db")); err != nil {
		t.Fatal(err)
	}
}

func validationInbound(port int) *model.Inbound {
	return &model.Inbound{UserId: 1, Enable: true, Port: port, Tag: "inbound-test", Protocol: model.Http, Settings: `{}`}
}

func TestAddInboundValidationFailureDoesNotPersist(t *testing.T) {
	initInboundValidationDB(t)
	wantErr := errors.New("invalid candidate")
	service := &InboundService{validateConfig: func(config *xray.Config) error {
		if len(config.InboundConfigs) != 2 || config.InboundConfigs[1].Port != 8080 {
			t.Fatalf("candidate not included with template: %+v", config.InboundConfigs)
		}
		return wantErr
	}}
	if err := service.AddInbound(validationInbound(8080)); !errors.Is(err, wantErr) {
		t.Fatalf("unexpected validation result: %v", err)
	}
	var count int64
	if err := database.GetDB().Model(&model.Inbound{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rejected inbound persisted: %d, %v", count, err)
	}
}

func TestUpdateInboundValidationFailureKeepsOriginal(t *testing.T) {
	initInboundValidationDB(t)
	original := validationInbound(8080)
	if err := database.GetDB().Create(original).Error; err != nil {
		t.Fatal(err)
	}
	changed := *original
	changed.Port = 8443
	changed.Settings = `{"invalid":"candidate"}`
	service := &InboundService{validateConfig: func(config *xray.Config) error {
		if len(config.InboundConfigs) != 2 || config.InboundConfigs[1].Port != 8443 {
			t.Fatalf("update did not replace original candidate: %+v", config.InboundConfigs)
		}
		return errors.New("invalid")
	}}
	if err := service.UpdateInbound(1, &changed); err == nil {
		t.Fatal("invalid update was accepted")
	}
	saved, err := service.GetInbound(original.Id)
	if err != nil || saved.Port != 8080 || saved.Settings != `{}` {
		t.Fatalf("original record changed: %+v, %v", saved, err)
	}
}

func TestAddInboundCannotOverwriteSubmittedID(t *testing.T) {
	initInboundValidationDB(t)
	original := validationInbound(8080)
	if err := database.GetDB().Create(original).Error; err != nil {
		t.Fatal(err)
	}
	service := &InboundService{
		validateConfig: func(*xray.Config) error { return nil },
		applyConfig:    func(*xray.Config) error { return nil },
	}
	other := validationInbound(8081)
	other.Id, other.UserId, other.Tag = original.Id, 2, "inbound-other"
	if err := service.AddInbound(other); err != nil {
		t.Fatal(err)
	}
	saved, err := service.GetInbound(original.Id)
	if err != nil || saved.Port != 8080 || saved.UserId != 1 || other.Id == original.Id {
		t.Fatalf("creation overwrote another inbound: %+v, %v", saved, err)
	}
}

func TestAddInboundsRollsBackEntireBatch(t *testing.T) {
	initInboundValidationDB(t)
	service := &InboundService{validateConfig: func(*xray.Config) error { return nil }}
	// Duplicate tags cause the second insert to fail after the first succeeds.
	if err := service.AddInbounds([]*model.Inbound{validationInbound(8080), validationInbound(8081)}); err == nil {
		t.Fatal("duplicate-tag batch accepted")
	}
	var count int64
	if err := database.GetDB().Model(&model.Inbound{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("partial batch persisted: %d, %v", count, err)
	}
}

type fakeXrayProcess struct {
	config   *xray.Config
	running  bool
	startErr error
	stopErr  error
	starts   int
	stops    int
}

func (p *fakeXrayProcess) IsRunning() bool                          { return p.running }
func (p *fakeXrayProcess) GetErr() error                            { return p.startErr }
func (p *fakeXrayProcess) GetResult() string                        { return "" }
func (p *fakeXrayProcess) GetVersion() string                       { return "test" }
func (p *fakeXrayProcess) GetConfig() *xray.Config                  { return p.config }
func (p *fakeXrayProcess) GetTraffic(bool) ([]*xray.Traffic, error) { return nil, nil }
func (p *fakeXrayProcess) Start() error {
	p.starts++
	p.running = p.startErr == nil
	return p.startErr
}
func (p *fakeXrayProcess) Stop() error {
	p.stops++
	if p.stopErr == nil {
		p.running = false
	}
	return p.stopErr
}

func preserveXrayProcess(t *testing.T) {
	t.Helper()
	old, oldResult := p, result
	t.Cleanup(func() { p, result = old, oldResult })
}

func TestRestartValidationFailureKeepsRunningCore(t *testing.T) {
	initInboundValidationDB(t)
	preserveXrayProcess(t)
	old := &fakeXrayProcess{config: &xray.Config{}, running: true}
	p = old
	service := &XrayService{validateConfig: func(*xray.Config) error { return errors.New("invalid") }}
	if err := service.RestartXray(true); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if p != old || old.stops != 0 || !old.running {
		t.Fatal("validation failure interrupted the running core")
	}
}

func TestRestartStartupFailureRestoresOldConfig(t *testing.T) {
	initInboundValidationDB(t)
	preserveXrayProcess(t)
	previous := &xray.Config{}
	old := &fakeXrayProcess{config: previous, running: true}
	p = old
	var created []*fakeXrayProcess
	service := &XrayService{
		validateConfig: func(*xray.Config) error { return nil },
		newProcess: func(config *xray.Config) xrayProcess {
			process := &fakeXrayProcess{config: config}
			if len(created) == 0 {
				process.startErr = errors.New("startup failed")
			}
			created = append(created, process)
			return process
		},
	}
	if err := service.RestartXray(true); err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatalf("startup failure not reported: %v", err)
	}
	if old.stops != 1 || len(created) != 2 || p != created[1] || !created[1].running || created[1].config != previous {
		t.Fatal("failed replacement did not restore original running config")
	}
}

func TestRestartStopFailureDoesNotStartReplacement(t *testing.T) {
	initInboundValidationDB(t)
	preserveXrayProcess(t)
	old := &fakeXrayProcess{config: &xray.Config{}, running: true, stopErr: errors.New("cannot stop")}
	p = old
	service := &XrayService{
		validateConfig: func(*xray.Config) error { return nil },
		newProcess:     func(*xray.Config) xrayProcess { t.Fatal("replacement created while old instance remains"); return nil },
	}
	if err := service.RestartXray(true); err == nil || p != old || !old.running {
		t.Fatalf("unexpected stop-failure handling: %v", err)
	}
}

func TestInteractiveStartupFailureRollsBackDatabaseAndSurvivesRestart(t *testing.T) {
	for _, operation := range []string{"add", "update"} {
		t.Run(operation, func(t *testing.T) {
			initInboundValidationDB(t)
			preserveXrayProcess(t)
			original := validationInbound(8080)
			if operation == "update" {
				if err := database.GetDB().Create(original).Error; err != nil {
					t.Fatal(err)
				}
			}
			runtimeService := &XrayService{
				validateConfig: func(*xray.Config) error { return nil },
				newProcess: func(config *xray.Config) xrayProcess {
					process := &fakeXrayProcess{config: config}
					for _, inbound := range config.InboundConfigs {
						if inbound.Port == 8081 {
							process.startErr = errors.New("simulated bind failure")
						}
					}
					return process
				},
			}
			previous, err := runtimeService.GetXrayConfig()
			if err != nil {
				t.Fatal(err)
			}
			p = &fakeXrayProcess{config: previous, running: true}
			service := &InboundService{
				validateConfig: func(*xray.Config) error { return nil },
				applyConfig:    runtimeService.replaceProcess,
			}
			candidate := validationInbound(8081)
			if operation == "add" {
				err = service.AddInbound(candidate)
			} else {
				candidate.Id = original.Id
				err = service.UpdateInbound(1, candidate)
			}
			if err == nil || !strings.Contains(err.Error(), "已恢复") {
				t.Fatalf("interactive failure not returned: %v", err)
			}
			if p == nil || !p.IsRunning() || !p.GetConfig().Equals(previous) {
				t.Fatal("previous running configuration was not restored")
			}
			inbounds, err := service.GetAllInbounds()
			if err != nil {
				t.Fatal(err)
			}
			if operation == "add" && len(inbounds) != 0 {
				t.Fatal("failed addition remained in the database")
			}
			if operation == "update" && (len(inbounds) != 1 || inbounds[0].Port != 8080) {
				t.Fatal("failed update changed the database")
			}
			// Simulate a fresh panel start: it must read only the old, good DB
			// configuration instead of retrying the rejected candidate.
			p = nil
			if err := runtimeService.RestartXray(true); err != nil || p == nil || !p.IsRunning() || !p.GetConfig().Equals(previous) {
				t.Fatalf("subsequent panel restart retried a bad candidate: %v", err)
			}
		})
	}
}

func TestCommitFailureRestoresPreviousRunningState(t *testing.T) {
	for _, wasRunning := range []bool{false, true} {
		t.Run(map[bool]string{false: "previously-stopped", true: "previously-running"}[wasRunning], func(t *testing.T) {
			initInboundValidationDB(t)
			preserveXrayProcess(t)
			previous := &xray.Config{}
			p = nil
			if wasRunning {
				p = &fakeXrayProcess{config: previous, running: true}
			}
			var created []*fakeXrayProcess
			runtimeService := &XrayService{newProcess: func(config *xray.Config) xrayProcess {
				process := &fakeXrayProcess{config: config}
				created = append(created, process)
				return process
			}}
			service := &InboundService{applyConfig: runtimeService.replaceProcess}
			candidate := validationInbound(8081)
			config := &xray.Config{InboundConfigs: []xray.InboundConfig{*candidate.GenXrayInboundConfig()}}
			err := service.saveAndApply(config, func(tx *gorm.DB) error {
				if err := tx.Create(candidate).Error; err != nil {
					return err
				}
				// Invalidate the transaction after its writes; the outer COMMIT
				// must now fail after the runtime application has succeeded.
				return tx.Rollback().Error
			})
			if err == nil || len(created) == 0 || created[0].running {
				t.Fatalf("commit failure left candidate running: %v", err)
			}
			if wasRunning && (p == nil || !p.IsRunning() || p.GetConfig() != previous) {
				t.Fatal("commit failure did not restore old running configuration")
			}
			if !wasRunning && p != nil {
				t.Fatal("commit failure started a core when none was previously running")
			}
			var count int64
			if err := database.GetDB().Model(&model.Inbound{}).Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("failed transaction persisted candidate: %d, %v", count, err)
			}
		})
	}
}
