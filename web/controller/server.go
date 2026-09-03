package controller

import (
	"github.com/gin-gonic/gin"
	"sync"
	"time"
	"x-ui/logger"
	"x-ui/web/global"
	"x-ui/web/service"
)

type ServerController struct {
	BaseController

	serverService service.ServerService
	mu            sync.RWMutex
	panelUpdateMu sync.Mutex

	lastStatus        *service.Status
	lastGetStatusTime time.Time

	lastVersions        []string
	lastGetVersionsTime time.Time
}

func NewServerController(g *gin.RouterGroup) *ServerController {
	a := &ServerController{
		lastGetStatusTime: time.Now(),
	}
	a.initRouter(g)
	a.startTask()
	return a
}

func (a *ServerController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/server")

	g.Use(a.checkLogin)
	g.Use(a.checkCSRF)
	g.POST("/status", a.status)
	g.POST("/getXrayVersion", a.getXrayVersion)
	g.POST("/installXray/:version", a.installXray)
	g.POST("/checkPanelUpdate", a.checkPanelUpdate)
	g.POST("/updatePanel", a.updatePanel)
}

func (a *ServerController) refreshStatus() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastStatus = a.serverService.GetStatus(a.lastStatus)
}

func (a *ServerController) startTask() {
	webServer := global.GetWebServer()
	c := webServer.GetCron()
	_, err := c.AddFunc("@every 2s", func() {
		a.mu.RLock()
		lastGet := a.lastGetStatusTime
		a.mu.RUnlock()
		now := time.Now()
		if now.Sub(lastGet) > time.Minute*3 {
			return
		}
		a.refreshStatus()
	})
	if err != nil {
		logger.Error("schedule server status job failed:", err)
	}
}

func (a *ServerController) status(c *gin.Context) {
	a.mu.Lock()
	a.lastGetStatusTime = time.Now()
	status := a.lastStatus
	a.mu.Unlock()

	jsonObj(c, status, nil)
}

func (a *ServerController) getXrayVersion(c *gin.Context) {
	now := time.Now()
	a.mu.RLock()
	lastGet := a.lastGetVersionsTime
	versionsCache := append([]string(nil), a.lastVersions...)
	a.mu.RUnlock()
	if now.Sub(lastGet) <= time.Minute {
		jsonObj(c, versionsCache, nil)
		return
	}

	versions, err := a.serverService.GetXrayVersions()
	if err != nil {
		jsonMsg(c, "获取版本", err)
		return
	}

	a.mu.Lock()
	a.lastVersions = append([]string(nil), versions...)
	a.lastGetVersionsTime = time.Now()
	a.mu.Unlock()

	jsonObj(c, versions, nil)
}

func (a *ServerController) installXray(c *gin.Context) {
	version := c.Param("version")
	err := a.serverService.UpdateXray(version)
	jsonMsg(c, "安装 xray", err)
}

func (a *ServerController) checkPanelUpdate(c *gin.Context) {
	info, err := a.serverService.GetPanelUpdate()
	jsonObj(c, info, err)
}

func (a *ServerController) updatePanel(c *gin.Context) {
	a.panelUpdateMu.Lock()
	defer a.panelUpdateMu.Unlock()

	info, err := a.serverService.UpdatePanel()
	jsonMsgObj(c, "更新面板", info, err)
	if err == nil {
		a.serverService.SchedulePanelRestart()
	}
}
