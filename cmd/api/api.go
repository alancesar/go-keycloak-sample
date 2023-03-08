package main

import (
	"context"
	"github.com/alancesar/go-keycloak-sample/pkg/handler"
	"github.com/alancesar/go-keycloak-sample/pkg/middleware"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

const (
	clientID = "my-client"
	issuer   = "http://localhost:8080/realms/playground"
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
		RedirectURL: "http://localhost:9090/auth/callback",
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:          clientID,
		SkipClientIDCheck: true,
	})

	mux := chi.NewMux()
	mux.Get("/", handler.Login(config))
	mux.Get("/auth/callback", handler.Callback(config, verifier))
	mux.Route("/details", func(r chi.Router) {
		r.Use(middleware.Authorize(verifier))
		r.Get("/", handler.Details)
	})

	server := &http.Server{
		Handler: mux,
		Addr:    ":9090",
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	}
}
