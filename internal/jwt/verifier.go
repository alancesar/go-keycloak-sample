package jwt

import (
	"context"
	"fmt"
	"github.com/alancesar/go-keycloak-sample/pkg"
	"github.com/coreos/go-oidc/v3/oidc"
	"time"
)

type (
	Token struct {
		Issuer          string
		Audience        []string
		Subject         string
		Expiry          time.Time
		IssuedAt        time.Time
		Nonce           string
		AccessTokenHash string
		Claims          Claims
	}

	Claims struct {
		Sub            string            `json:"sub"`
		Email          string            `json:"email"`
		ResourceAccess map[string]Access `json:"resource_access"`
	}

	Access struct {
		Roles []string `json:"roles"`
	}

	Verifier struct {
		Verifier *oidc.IDTokenVerifier
	}
)

func NewVerifier(verifier *oidc.IDTokenVerifier) *Verifier {
	return &Verifier{
		Verifier: verifier,
	}
}

func (v Verifier) Parse(ctx context.Context, rawToken string) (Token, error) {
	idToken, err := v.Verifier.Verify(ctx, rawToken)
	if err != nil {
		return Token{}, fmt.Errorf("[%w] invalid token", pkg.ErrInvalidCredentials)
	}

	var claims Claims
	err = idToken.Claims(&claims)

	return Token{
		Issuer:          idToken.Issuer,
		Audience:        idToken.Audience,
		Subject:         idToken.Subject,
		Expiry:          idToken.Expiry,
		IssuedAt:        idToken.IssuedAt,
		Nonce:           idToken.Nonce,
		AccessTokenHash: idToken.AccessTokenHash,
		Claims:          claims,
	}, err
}
