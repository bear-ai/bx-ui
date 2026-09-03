package controller

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"x-ui/database/model"
	"x-ui/logger"
	"x-ui/web/global"
	"x-ui/web/service"
	"x-ui/web/session"
	"x-ui/xray"
)

type InboundController struct {
	inboundService service.InboundService
	xrayService    service.XrayService
}

func NewInboundController(g *gin.RouterGroup) *InboundController {
	a := &InboundController{}
	a.initRouter(g)
	a.startTask()
	return a
}

func (a *InboundController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/inbound")

	g.POST("/list", a.getInbounds)
	g.POST("/add", a.addInbound)
	g.POST("/del/:id", a.delInbound)
	g.POST("/update/:id", a.updateInbound)
	g.POST("/export/:id", a.exportClientConfig)
	g.POST("/generateX25519", a.generateX25519)
	g.POST("/generateVlessEnc", a.generateVlessEnc)
}

func (a *InboundController) exportClientConfig(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"success": false, "msg": "入站 ID 无效"})
		return
	}
	request := struct {
		Address string `form:"address"`
	}{}
	if err := c.ShouldBind(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"success": false, "msg": "服务器地址无效"})
		return
	}
	user := session.GetLoginUser(c)
	config, err := a.inboundService.ExportClientConfig(id, user.Id, request.Address)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"success": false, "msg": "入站不存在"})
		return
	}
	if errors.Is(err, service.ErrClientExportUnsupported) || errors.Is(err, service.ErrClientExportInvalid) {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"success": false, "msg": err.Error()})
		return
	}
	if err != nil {
		logger.Error("export inbound client config failed:", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"success": false, "msg": "导出失败"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="bx-inbound-%d.json"`, id))
	c.Data(http.StatusOK, "application/json; charset=utf-8", config)
}

func (a *InboundController) generateX25519(c *gin.Context) {
	pair, err := xray.GenerateX25519KeyPair()
	jsonObj(c, pair, err)
}

func (a *InboundController) generateVlessEnc(c *gin.Context) {
	pairs, err := xray.GenerateVlessEncryptionPairs()
	jsonObj(c, pairs, err)
}

func (a *InboundController) startTask() {
	webServer := global.GetWebServer()
	c := webServer.GetCron()
	_, err := c.AddFunc("@every 10s", func() {
		if a.xrayService.IsNeedRestartAndSetFalse() {
			err := a.xrayService.RestartXray(false)
			if err != nil {
				logger.Error("restart xray failed:", err)
			}
		}
	})
	if err != nil {
		logger.Error("schedule Xray restart job failed:", err)
	}
}

func (a *InboundController) getInbounds(c *gin.Context) {
	user := session.GetLoginUser(c)
	inbounds, err := a.inboundService.GetInbounds(user.Id)
	if err != nil {
		jsonMsg(c, "获取", err)
		return
	}
	jsonObj(c, inbounds, nil)
}

func (a *InboundController) addInbound(c *gin.Context) {
	inbound := &model.Inbound{}
	err := c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, "添加", err)
		return
	}
	user := session.GetLoginUser(c)
	inbound.UserId = user.Id
	inbound.Enable = true
	inbound.Tag = fmt.Sprintf("inbound-%v", inbound.Port)
	err = a.inboundService.AddInbound(inbound)
	jsonMsg(c, "添加", err)
	if err == nil {
		a.xrayService.SetToNeedRestart()
	}
}

func (a *InboundController) delInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "删除", err)
		return
	}
	user := session.GetLoginUser(c)
	err = a.inboundService.DelInbound(id, user.Id)
	jsonMsg(c, "删除", err)
	if err == nil {
		a.xrayService.SetToNeedRestart()
	}
}

func (a *InboundController) updateInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "修改", err)
		return
	}
	inbound := &model.Inbound{
		Id: id,
	}
	err = c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, "修改", err)
		return
	}
	user := session.GetLoginUser(c)
	err = a.inboundService.UpdateInbound(user.Id, inbound)
	jsonMsg(c, "修改", err)
	if err == nil {
		a.xrayService.SetToNeedRestart()
	}
}
