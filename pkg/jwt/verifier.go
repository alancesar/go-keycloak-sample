package jwt

import (
	"context"
	"github.com/alancesar/go-keycloak-sample/internal/jwt"
)

type (
	TokenParser interface {
		Parse(ctx context.Context, rawToken string) (jwt.Token, error)
	}
)
