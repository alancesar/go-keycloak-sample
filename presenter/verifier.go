package presenter

import (
	"context"
	"github.com/alancesar/go-keycloak-sample/internal/jwt"
)

type (
	Verifier interface {
		Verify(ctx context.Context, rawToken string) (jwt.Token, error)
	}
)
