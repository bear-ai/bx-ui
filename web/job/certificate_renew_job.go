package job

import (
	"context"
	"time"
	"x-ui/logger"
	"x-ui/web/service"
)

type CertificateRenewJob struct {
	certificateService *service.CertificateService
	panelService       service.PanelService
}

func NewCertificateRenewJob(certificateService *service.CertificateService) *CertificateRenewJob {
	return &CertificateRenewJob{certificateService: certificateService}
}

func (j *CertificateRenewJob) Run() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	renewed, err := j.certificateService.RenewIfNeeded(ctx)
	if err != nil {
		logger.Errorf("automatic certificate renewal failed: %v", err)
		return
	}
	if renewed {
		if err := j.panelService.RestartPanel(5 * time.Second); err != nil {
			logger.Errorf("restart panel after certificate renewal failed: %v", err)
		}
	}
}
