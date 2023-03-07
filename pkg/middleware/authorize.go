package middleware

import (
	"context"
	"github.com/alancesar/go-keycloak-sample/pkg/jwt"
	"github.com/coreos/go-oidc/v3/oidc"
	"net/http"
	"strings"
)

const (
	authorizationKey = "Authorization"
	bearerPrefix     = "Bearer"
)

func Authorize(verifier *oidc.IDTokenVerifier) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			rawAccessToken := extractAuthorization(r)
			idToken, err := verifier.Verify(ctx, rawAccessToken)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			ctx = context.WithValue(ctx, jwt.TokenKey, idToken)
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
