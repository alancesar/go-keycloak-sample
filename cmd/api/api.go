package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/alancesar/go-keycloak-sample/internal/jwt"
	"github.com/alancesar/go-keycloak-sample/pkg"
	handler2 "github.com/alancesar/go-keycloak-sample/pkg/handler"
	"github.com/alancesar/go-keycloak-sample/pkg/middleware"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
)

const (
	callbackPath = "/auth/callback"
)

var (
	clientID   = os.Getenv("CLIENT_ID")
	issuer     = os.Getenv("ISSUER")
	serverAddr = os.Getenv("SERVER_ADDRESS")
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

	mux := chi.NewMux()
	mux.Get("/", handler2.Login(config))
	mux.Get(callbackPath, handler2.Authorize(config, verifier))
	mux.Route("/details", func(r chi.Router) {
		r.Use(middleware.Authorize(verifier))
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			claims := r.Context().Value(pkg.Claims).(jwt.Claims)
			bytes, err := json.Marshal(claims)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(bytes)
		})
	})

	server := &http.Server{
		Handler: mux,
		Addr:    serverAddr,
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalln(err)
	}
}
