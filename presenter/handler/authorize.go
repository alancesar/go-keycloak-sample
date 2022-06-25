package handler

import (
	"github.com/alancesar/go-keycloak-sample/presenter"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
)

const (
	stateKey   = "state"
	codeKey    = "code"
	nonceKey   = "nonce"
	idTokenKey = "id_token"
)

func Authorize(config oauth2.Config, handler presenter.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		state := c.Query(stateKey)
		if !cookieMatches(c.Request, stateKey, state) {
			c.Status(http.StatusUnauthorized)
			return
		}

		oauth2Token, err := config.Exchange(ctx, c.Query(codeKey))
		if err != nil {
			c.Status(http.StatusUnauthorized)
			return
		}

		rawIDToken, ok := oauth2Token.Extra(idTokenKey).(string)
		if !ok {
			c.Status(http.StatusUnauthorized)
			return
		}

		token, err := handler.Verify(ctx, rawIDToken)
		if err != nil {
			c.Status(http.StatusUnauthorized)
			return
		}

		if !cookieMatches(c.Request, nonceKey, token.Nonce) {
			c.Status(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, oauth2Token)
	}
}

func cookieMatches(r *http.Request, name, target string) bool {
	cookie, err := r.Cookie(name)
	if err != nil {
		return false
	}

	return cookie.Value == target
}
