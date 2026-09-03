package controller

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"time"
	"x-ui/web/entity"
	"x-ui/web/service"
	"x-ui/web/session"
)

type updateUserForm struct {
	OldUsername string `json:"oldUsername" form:"oldUsername"`
	OldPassword string `json:"oldPassword" form:"oldPassword"`
	NewUsername string `json:"newUsername" form:"newUsername"`
	NewPassword string `json:"newPassword" form:"newPassword"`
}

type SettingController struct {
	settingService     service.SettingService
	userService        service.UserService
	panelService       service.PanelService
	certificateService *service.CertificateService
}

func NewSettingController(g *gin.RouterGroup, certificateService *service.CertificateService) *SettingController {
	a := &SettingController{certificateService: certificateService}
	a.initRouter(g)
	return a
}

func (a *SettingController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/setting")

	g.POST("/all", a.getAllSetting)
	g.POST("/update", a.updateSetting)
	g.POST("/updateUser", a.updateUser)
	g.POST("/restartPanel", a.restartPanel)
	g.POST("/certificate/status", a.certificateStatus)
	g.POST("/certificate/checkDomain", a.checkCertificateDomain)
	g.POST("/certificate/apply", a.applyCertificate)
}

func (a *SettingController) getAllSetting(c *gin.Context) {
	allSetting, err := a.settingService.GetAllSetting()
	if err != nil {
		jsonMsg(c, "获取设置", err)
		return
	}
	jsonObj(c, allSetting, nil)
}

func (a *SettingController) updateSetting(c *gin.Context) {
	allSetting := &entity.AllSetting{}
	err := c.ShouldBind(allSetting)
	if err != nil {
		jsonMsg(c, "修改设置", err)
		return
	}
	err = a.settingService.UpdateAllSetting(allSetting)
	jsonMsg(c, "修改设置", err)
}

func (a *SettingController) updateUser(c *gin.Context) {
	form := &updateUserForm{}
	err := c.ShouldBind(form)
	if err != nil {
		jsonMsg(c, "修改用户", err)
		return
	}
	user := session.GetLoginUser(c)
	if user == nil || user.Username != form.OldUsername || !a.userService.VerifyPassword(user, form.OldPassword) {
		jsonMsg(c, "修改用户", errors.New("原用户名或原密码错误"))
		return
	}
	if form.NewUsername == "" || form.NewPassword == "" {
		jsonMsg(c, "修改用户", errors.New("新用户名和新密码不能为空"))
		return
	}
	user, err = a.userService.UpdateUser(user.Id, form.NewUsername, form.NewPassword)
	if err == nil {
		err = session.SetLoginUser(c, user)
	}
	jsonMsg(c, "修改用户", err)
}

func (a *SettingController) restartPanel(c *gin.Context) {
	err := a.panelService.RestartPanel(time.Second * 3)
	jsonMsg(c, "重启面板", err)
}

func (a *SettingController) certificateStatus(c *gin.Context) {
	status, err := a.certificateService.GetStatus()
	jsonObj(c, status, err)
}

func (a *SettingController) checkCertificateDomain(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	status, err := a.certificateService.CheckDomain(ctx)
	jsonObj(c, status, err)
}

func (a *SettingController) applyCertificate(c *gin.Context) {
	result, err := a.certificateService.ApplyCertificate(c.Request.Context())
	if err == nil && result != nil && result.RestartRequired {
		err = a.panelService.RestartPanel(3 * time.Second)
	}
	jsonObj(c, result, err)
}
