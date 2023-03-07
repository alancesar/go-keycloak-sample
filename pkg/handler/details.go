package handler

import (
	"encoding/json"
	"github.com/alancesar/go-keycloak-sample/pkg/jwt"
	"github.com/coreos/go-oidc/v3/oidc"
	"net/http"
)

func Details(w http.ResponseWriter, r *http.Request) {
	idToken := r.Context().Value(jwt.TokenKey).(*oidc.IDToken)
	claims := struct {
		Sub            string `json:"sub"`
		Email          string `json:"email"`
		ResourceAccess map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}{}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	bytes, err := json.Marshal(&claims)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bytes)
}
