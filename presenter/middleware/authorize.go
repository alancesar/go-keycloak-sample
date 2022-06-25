package middleware

import (
	"context"
	"github.com/alancesar/go-keycloak-sample/pkg"
	"github.com/alancesar/go-keycloak-sample/presenter"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

const (
	authorizationKey = "Authorization"
	bearerPrefix     = "Bearer"
)

func Authorize(verifier presenter.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		rawAccessToken := extractAuthorization(c.Request)
		token, err := verifier.Verify(ctx, rawAccessToken)
		if err != nil {
			_ = c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		ctx = context.WithValue(ctx, pkg.Claims, token.Claims)
		c.Request = c.Request.WithContext(ctx)
	}
}

func extractAuthorization(r *http.Request) string {
	raw := r.Header.Get(authorizationKey)
	_, after, found := strings.Cut(raw, bearerPrefix)
	if !found {
		return ""
	}

	return strings.TrimSpace(after)
}
