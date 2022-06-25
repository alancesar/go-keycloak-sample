package handler

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

type (
	RandomStringFn func() string
)

func Login(fn RandomStringFn, config oauth2.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		state := fn()
		nonce := fn()
		setCookie(c.Writer, c.Request, "state", state)
		setCookie(c.Writer, c.Request, "nonce", nonce)

		c.Redirect(http.StatusFound, config.AuthCodeURL(state, oidc.Nonce(nonce)))
	}
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}
