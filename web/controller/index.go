package controller

import (
	"net/http"
	"time"
	"x-ui/logger"
	"x-ui/web/job"
	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
)

type LoginForm struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

type IndexController struct {
	BaseController

	userService service.UserService
	limiter     *loginLimiter
}

func NewIndexController(g *gin.RouterGroup) *IndexController {
	a := &IndexController{limiter: newLoginLimiter()}
	a.initRouter(g)
	return a
}

func (a *IndexController) initRouter(g *gin.RouterGroup) {
	g.GET("/", a.index)
	g.POST("/login", a.login)
	g.GET("/logout", a.logout)
}

func (a *IndexController) index(c *gin.Context) {
	if resolveLogin(c) != nil {
		c.Redirect(http.StatusTemporaryRedirect, "xui/")
		return
	}
	html(c, "login.html", "登录", nil)
}

func (a *IndexController) login(c *gin.Context) {
	remoteIP := getRemoteIp(c)
	now := time.Now()
	if !a.limiter.allow(remoteIP, now) {
		c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "msg": "登录失败次数过多，请稍后再试"})
		return
	}
	var form LoginForm
	err := c.ShouldBind(&form)
	if err != nil {
		pureJsonMsg(c, false, "数据格式错误")
		return
	}
	if form.Username == "" {
		pureJsonMsg(c, false, "请输入用户名")
		return
	}
	if form.Password == "" {
		pureJsonMsg(c, false, "请输入密码")
		return
	}
	user := a.userService.CheckUser(form.Username, form.Password)
	timeStr := now.Format("2006-01-02 15:04:05")
	if user == nil {
		a.limiter.failure(remoteIP, now)
		job.NewStatsNotifyJob().UserLoginNotify(form.Username, remoteIP, timeStr, 0)
		logger.Infof("failed login for username %q from %s", form.Username, remoteIP)
		pureJsonMsg(c, false, "用户名或密码错误")
		return
	} else {
		a.limiter.success(remoteIP)
		logger.Infof("%s login success,Ip Address:%s\n", form.Username, remoteIP)
		job.NewStatsNotifyJob().UserLoginNotify(form.Username, remoteIP, timeStr, 1)
	}

	err = session.SetLoginUser(c, user)
	logger.Info("user", user.Id, "login success")
	jsonMsg(c, "登录", err)
}

func (a *IndexController) logout(c *gin.Context) {
	user := resolveLogin(c)
	if user != nil {
		logger.Info("user", user.Id, "logout")
	}
	session.ClearSession(c)
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
}
