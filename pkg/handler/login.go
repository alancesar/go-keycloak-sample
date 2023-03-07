package handler

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

type (
	RandomStringFn func() string
)

func Login(fn RandomStringFn, config oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := fn()
		nonce := fn()
		setCookie(w, r, "state", state)
		setCookie(w, r, "nonce", nonce)

		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	}
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}
