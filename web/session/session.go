package session

import (
	"encoding/gob"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"x-ui/database/model"
	"x-ui/util/random"
)

const (
	loginClaims = "LOGIN_CLAIMS"
	antiForgery = "ANTI_FORGERY"
	currentUser = "CURRENT_USER"
)

type Claims struct {
	UserID         int
	SessionVersion uint64
}

func init() {
	gob.Register(Claims{})
}

func SetLoginUser(c *gin.Context, user *model.User) error {
	s := sessions.Default(c)
	s.Set(loginClaims, Claims{UserID: user.Id, SessionVersion: user.SessionVersion})
	if s.Get(antiForgery) == nil {
		s.Set(antiForgery, random.Seq(48))
	}
	return s.Save()
}

func GetLoginClaims(c *gin.Context) *Claims {
	value := sessions.Default(c).Get(loginClaims)
	claims, ok := value.(Claims)
	if !ok {
		return nil
	}
	return &claims
}

func SetCurrentUser(c *gin.Context, user *model.User) {
	c.Set(currentUser, user)
}

func GetLoginUser(c *gin.Context) *model.User {
	value, ok := c.Get(currentUser)
	if !ok {
		return nil
	}
	user, _ := value.(*model.User)
	return user
}

func GetCSRFToken(c *gin.Context) string {
	value, _ := sessions.Default(c).Get(antiForgery).(string)
	return value
}

func ClearSession(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	s.Options(sessions.Options{
		Path:     c.GetString("base_path"),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: 2,
	})
	_ = s.Save()
}
