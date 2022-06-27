package main

import (
	"context"
	"fmt"
	"github.com/alancesar/go-keycloak-sample/internal/jwt"
	"github.com/alancesar/go-keycloak-sample/internal/nonce"
	"github.com/alancesar/go-keycloak-sample/pkg"
	"github.com/alancesar/go-keycloak-sample/presenter/handler"
	"github.com/alancesar/go-keycloak-sample/presenter/middleware"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
)

const (
	callbackPath = "/auth/callback"
	nonceLength  = 16
)

var (
	clientID          = os.Getenv("CLIENT_ID")
	issuer            = os.Getenv("ISSUER")
	nonceDefaultValue = os.Getenv("DEFAULT_NONCE")
	serverAddr        = os.Getenv("SERVER_ADDRESS")
)

func main() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalln(err)
	}

	config := oauth2.Config{
		ClientID:    clientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: fmt.Sprintf("http://localhost%s%s", serverAddr, callbackPath),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	verifier := jwt.NewVerifier(provider.Verifier(oidcConfig))

	randomStringFn := func() string {
		return nonce.New(nonceLength, nonceDefaultValue)
	}

	engine := gin.Default()
	engine.Handle(http.MethodGet, "/", handler.Login(randomStringFn, config))
	engine.Handle(http.MethodGet, callbackPath, handler.Authorize(config, verifier))
	engine.Handle(http.MethodGet, "/details", middleware.Authorize(verifier), func(c *gin.Context) {
		claims := c.Request.Context().Value(pkg.Claims).(jwt.Claims)
		c.JSON(http.StatusOK, claims)
	})

	server := &http.Server{
		Handler: engine,
		Addr:    serverAddr,
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	}
}
