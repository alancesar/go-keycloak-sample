package handler

import (
	"encoding/json"
	"github.com/alancesar/go-keycloak-sample/presenter"
	"golang.org/x/oauth2"
	"net/http"
)

const (
	stateKey   = "state"
	codeKey    = "code"
	nonceKey   = "nonce"
	idTokenKey = "id_token"
)

func Authorize(config oauth2.Config, handler presenter.TokenParser) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get(stateKey)
		if !cookieMatches(r, stateKey, state) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		oauth2Token, err := config.Exchange(r.Context(), r.URL.Query().Get(codeKey))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		rawIDToken, ok := oauth2Token.Extra(idTokenKey).(string)
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		token, err := handler.Parse(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if !cookieMatches(r, nonceKey, token.Nonce) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		bytes, err := json.Marshal(oauth2Token)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes)
	}
}

func cookieMatches(r *http.Request, name, target string) bool {
	cookie, err := r.Cookie(name)
	if err != nil {
		return false
	}

	return cookie.Value == target
}
