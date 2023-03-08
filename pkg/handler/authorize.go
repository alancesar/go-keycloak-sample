package handler

import (
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
)

func Callback(config oauth2.Config, verifier *oidc.IDTokenVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if err := validateState(r); err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		code := r.URL.Query().Get(codeKey)
		token, err := config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if err := validateToken(r, token, verifier); err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		bytes, err := json.Marshal(token)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes)
	}
}

func validateState(r *http.Request) error {
	state := r.URL.Query().Get(stateKey)
	if cookie, err := r.Cookie(stateKey); err != nil || cookie.Value != state {
		return errors.New("state does not matche")
	}

	return nil
}

func validateToken(r *http.Request, token *oauth2.Token, verifier *oidc.IDTokenVerifier) error {
	rawIDToken, ok := token.Extra(idTokenKey).(string)
	if !ok {
		return errors.New("invalid token")
	}

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return err
	}

	if cookie, err := r.Cookie(nonceKey); err != nil || cookie.Value != idToken.Nonce {
		return errors.New("nounce does not match")
	}

	return nil
}
