package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"time"
)

func Login(config oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := createRandomString()
		http.SetCookie(w, &http.Cookie{
			Name:     stateKey,
			Value:    state,
			MaxAge:   int(time.Hour.Seconds()),
			Secure:   r.TLS != nil,
			HttpOnly: true,
		})

		nonce := createRandomString()
		http.SetCookie(w, &http.Cookie{
			Name:     nonceKey,
			Value:    nonce,
			MaxAge:   int(time.Hour.Seconds()),
			Secure:   r.TLS != nil,
			HttpOnly: true,
		})

		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	}
}

func createRandomString() string {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
