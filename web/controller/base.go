package controller

import (
	"crypto/subtle"
	"github.com/gin-gonic/gin"
	"net/http"
	"x-ui/database/model"
	"x-ui/web/service"
	"x-ui/web/session"
)

type BaseController struct {
}

func resolveLogin(c *gin.Context) *model.User {
	claims := session.GetLoginClaims(c)
	if claims == nil {
		return nil
	}
	user, err := (&service.UserService{}).GetUser(claims.UserID)
	if err != nil || user.SessionVersion != claims.SessionVersion {
		session.ClearSession(c)
		return nil
	}
	session.SetCurrentUser(c, user)
	return user
}

func (a *BaseController) checkLogin(c *gin.Context) {
	if resolveLogin(c) == nil {
		if isAjax(c) {
			pureJsonMsg(c, false, "登录时效已过，请重新登录")
		} else {
			c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
		}
		c.Abort()
	} else {
		c.Next()
	}
}

func (a *BaseController) checkCSRF(c *gin.Context) {
	if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
		c.Next()
		return
	}
	expected := session.GetCSRFToken(c)
	provided := c.GetHeader("X-CSRF-Token")
	if expected == "" || provided == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "msg": "CSRF 校验失败，请刷新页面后重试"})
		return
	}
	c.Next()
}
