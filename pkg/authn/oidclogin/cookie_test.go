package oidclogin

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func TestEncryptedCookieAuthentication(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	w := httptest.NewRecorder()
	require.NoError(t, h.setCookie(w, transactionCookie, loginCookie{State: "state", Nonce: "nonce", Verifier: "private-verifier"}, time.Minute, http.SameSiteLaxMode))
	cookie := responseCookie(t, w, transactionCookie)
	require.NotContains(t, cookie.Value, "private-verifier")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	value, err := h.readCookie(r, transactionCookie)
	require.NoError(t, err)
	require.Equal(t, "private-verifier", value.Verifier)
	cookie.Name = identityCookie
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	_, err = h.readCookie(r, identityCookie)
	require.Error(t, err, "encrypted transaction must not become an authenticated identity")
	cookie.Name = transactionCookie
	sealed, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	require.NoError(t, err)
	sealed[len(sealed)-1] ^= 1
	cookie.Value = base64.RawURLEncoding.EncodeToString(sealed)
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	_, err = h.readCookie(r, transactionCookie)
	require.Error(t, err)
}

func TestIdentityCookieExpiry(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	w := httptest.NewRecorder()
	require.NoError(t, h.setCookie(w, identityCookie, loginCookie{Email: "alice@example.com"}, -time.Minute, http.SameSiteStrictMode))
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Origin", "https://signoz.example.com")
	r.AddCookie(w.Result().Cookies()[0])
	w = httptest.NewRecorder()
	h.Complete(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestCookieConfigurationBinding(t *testing.T) {
	p := newTestProvider(t)
	for _, test := range []struct {
		name   string
		change func(*Handler)
	}{
		{"issuer", func(h *Handler) { h.config.Issuer = "https://other.example.com" }},
		{"client", func(h *Handler) { h.config.ClientID = "other-client" }},
		{"organization", func(h *Handler) { h.config.OrgID = valuer.GenerateUUID() }},
		{"external host", func(h *Handler) { h.external.Host = "other.example.com" }},
		{"external path", func(h *Handler) { h.external.Path = "/other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := testHandler(t, p)
			w := httptest.NewRecorder()
			require.NoError(t, h.setCookie(w, identityCookie, loginCookie{Email: "alice@example.com"}, time.Minute, http.SameSiteStrictMode))
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.AddCookie(responseCookie(t, w, identityCookie))
			test.change(h)
			_, err := h.readCookie(r, identityCookie)
			require.Error(t, err)
		})
	}
}
