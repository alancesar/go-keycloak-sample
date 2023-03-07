package middleware

import (
	"context"
	"github.com/alancesar/go-keycloak-sample/pkg"
	"github.com/alancesar/go-keycloak-sample/pkg/jwt"
	"net/http"
	"strings"
)

const (
	authorizationKey = "Authorization"
	bearerPrefix     = "Bearer"
)

func Authorize(verifier jwt.TokenParser) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			rawAccessToken := extractAuthorization(r)
			token, err := verifier.Parse(r.Context(), rawAccessToken)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), pkg.Claims, token.Claims)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
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
