package oidclogin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"time"
)

type loginCookie struct {
	Expires  int64  `json:"exp"`
	State    string `json:"state,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Verifier string `json:"verifier,omitempty"`
	Email    string `json:"email,omitempty"`
	Subject  string `json:"sub,omitempty"`
	SID      string `json:"sid,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	IDToken  string `json:"id_token,omitempty"`
}

func (h *Handler) cookieCipher() (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(h.config.CookieKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (h *Handler) setCookie(w http.ResponseWriter, name string, value loginCookie, lifetime time.Duration, sameSite http.SameSite) error {
	aead, err := h.cookieCipher()
	if err != nil {
		return err
	}
	value.Expires = time.Now().Add(lifetime).Unix()
	plain, err := json.Marshal(value)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nonce, nonce, plain, h.cookieAudience(name))
	encoded := base64.RawURLEncoding.EncodeToString(sealed)
	if len(encoded) > 3500 {
		return fmt.Errorf("OIDC cookie exceeds size limit")
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: encoded, Path: h.cookiePathFor(name), MaxAge: int(lifetime.Seconds()), HttpOnly: true, Secure: h.external.Scheme == "https", SameSite: sameSite})
	return nil
}

func (h *Handler) readCookie(r *http.Request, name string) (loginCookie, error) {
	var value loginCookie
	cookie, err := r.Cookie(name)
	if err != nil {
		return value, err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return value, err
	}
	aead, err := h.cookieCipher()
	if err != nil {
		return value, err
	}
	if len(sealed) < aead.NonceSize() {
		return value, fmt.Errorf("invalid OIDC cookie")
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], h.cookieAudience(name))
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(plain, &value); err != nil {
		return value, err
	}
	if value.Expires <= time.Now().Unix() {
		return value, fmt.Errorf("expired OIDC cookie")
	}
	return value, nil
}

func (h *Handler) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: h.cookiePathFor(name), MaxAge: -1, HttpOnly: true, Secure: h.external.Scheme == "https", SameSite: http.SameSiteLaxMode})
}

func (h *Handler) cookiePathFor(name string) string {
	if name == logoutCookie {
		return path.Join(h.external.Path, "/api/v2/sessions")
	}
	return h.cookiePath()
}

func (h *Handler) cookieAudience(name string) []byte {
	return []byte(name + "\x00" + h.config.Issuer + "\x00" + h.config.ClientID + "\x00" + h.config.OrgID.String() + "\x00" + h.external.String())
}
