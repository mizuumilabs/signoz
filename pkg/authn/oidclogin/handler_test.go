package oidclogin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func testHandler(t *testing.T, p *testProvider) *Handler {
	t.Helper()
	config := validConfig()
	config.Issuer = p.server.URL
	external, err := url.Parse("https://signoz.example.com/observe")
	require.NoError(t, err)
	return New(config, global.Config{ExternalURL: external}, func(_ context.Context, email valuer.Email) (*authtypes.GettableToken, error) {
		require.Equal(t, "alice@example.com", email.String())
		return &authtypes.GettableToken{AccessToken: "signoz-access", RefreshToken: "signoz-refresh", TokenType: "bearer", ExpiresIn: 300}, nil
	})
}

func TestOIDCLogin(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	cookie, authorization := startLogin(t, h, p)
	require.True(t, cookie.Secure)
	require.True(t, cookie.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	require.Equal(t, "/observe"+Route, cookie.Path)
	w := callbackLogin(h, cookie, url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}})
	require.Equal(t, "/observe/login?oidcComplete=true", w.Header().Get("Location"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	require.NotContains(t, w.Header().Get("Location"), "Token")
	identity := responseCookie(t, w, identityCookie)
	require.True(t, identity.HttpOnly)
	require.True(t, identity.Secure)
	require.Equal(t, http.SameSiteStrictMode, identity.SameSite)
	r := httptest.NewRequest(http.MethodPost, "https://signoz.example.com/observe"+Route+"/session", nil)
	r.Header.Set("Origin", "https://signoz.example.com")
	r.AddCookie(identity)
	w = httptest.NewRecorder()
	h.Complete(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"accessToken":"signoz-access"`)
	require.Contains(t, w.Body.String(), `"refreshToken":"signoz-refresh"`)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, 1, p.exchanges)
	for _, c := range w.Result().Cookies() {
		if c.Name == identityCookie {
			require.Equal(t, -1, c.MaxAge)
		}
	}
}

func TestRejectCallbackBeforeTokenExchange(t *testing.T) {
	for _, test := range []string{"missing cookie", "wrong state", "missing state", "tampered cookie", "expired cookie", "provider error", "missing code"} {
		t.Run(test, func(t *testing.T) {
			p := newTestProvider(t)
			h := testHandler(t, p)
			cookie, authorization := startLogin(t, h, p)
			query := url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}}
			switch test {
			case "missing cookie":
				cookie = nil
			case "wrong state":
				query.Set("state", "attacker-state")
			case "missing state":
				query.Del("state")
			case "tampered cookie":
				cookie.Value = "AAAA" + cookie.Value[4:]
			case "expired cookie":
				w := httptest.NewRecorder()
				require.NoError(t, h.setCookie(w, transactionCookie, loginCookie{State: authorization.Get("state"), Nonce: "nonce", Verifier: "verifier"}, -time.Minute, http.SameSiteLaxMode))
				cookie = w.Result().Cookies()[0]
			case "provider error":
				query.Set("error", "access_denied")
				query.Set("error_description", "secret upstream details")
			case "missing code":
				query.Del("code")
			}
			w := callbackLogin(h, cookie, query)
			require.Equal(t, "/observe/login?oidcError=authentication_failed", w.Header().Get("Location"))
			require.NotContains(t, w.Body.String(), "secret upstream details")
			require.Zero(t, p.exchanges)
		})
	}
}

func TestRejectInvalidIDToken(t *testing.T) {
	for _, test := range []string{"nonce", "issuer", "audience", "signature", "expired", "unverified email", "missing email verification", "invalid email", "subject"} {
		t.Run(test, func(t *testing.T) {
			p := newTestProvider(t)
			h := testHandler(t, p)
			cookie, authorization := startLogin(t, h, p)
			switch test {
			case "nonce":
				p.claims["nonce"] = "wrong"
			case "issuer":
				p.claims["iss"] = "https://attacker.example.com"
			case "audience":
				p.claims["aud"] = "other-app"
			case "signature":
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				p.key = key
			case "expired":
				p.claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "unverified email":
				p.claims["email_verified"] = false
			case "missing email verification":
				delete(p.claims, "email_verified")
			case "invalid email":
				p.claims["email"] = "invalid"
			case "subject":
				p.claims["sub"] = ""
			}
			w := callbackLogin(h, cookie, url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}})
			require.Equal(t, "/observe/login?oidcError=authentication_failed", w.Header().Get("Location"))
			for _, c := range w.Result().Cookies() {
				if c.Name == identityCookie {
					require.Less(t, c.MaxAge, 0, "callback must not set an identity")
				}
			}
		})
	}
}

func TestProviderFailures(t *testing.T) {
	t.Run("discovery", func(t *testing.T) {
		p := newTestProvider(t)
		p.discoveryStatus = http.StatusServiceUnavailable
		h := testHandler(t, p)
		w := httptest.NewRecorder()
		h.Start(w, httptest.NewRequest(http.MethodGet, "/login", nil))
		require.Equal(t, "/observe/login?oidcError=authentication_failed", w.Header().Get("Location"))
	})
	t.Run("exchange", func(t *testing.T) {
		p := newTestProvider(t)
		h := testHandler(t, p)
		cookie, authorization := startLogin(t, h, p)
		p.tokenStatus = http.StatusBadRequest
		w := callbackLogin(h, cookie, url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}})
		require.Equal(t, "/observe/login?oidcError=authentication_failed", w.Header().Get("Location"))
	})
}

func TestRejectInsecureDiscoveredEndpoints(t *testing.T) {
	for _, endpoint := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		t.Run(endpoint, func(t *testing.T) {
			p := newTestProvider(t)
			h := testHandler(t, p)
			cookie, authorization := startLogin(t, h, p)
			p.metadataOverrides = map[string]string{endpoint: "http://keycloak.example.com/insecure"}
			w := callbackLogin(h, cookie, url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}})
			require.Equal(t, "/observe/login?oidcError=authentication_failed", w.Header().Get("Location"))
			require.Zero(t, p.exchanges, "insecure endpoint must be rejected before exchanging the code")
			w = httptest.NewRecorder()
			h.Start(w, httptest.NewRequest(http.MethodGet, "/login", nil))
			require.Equal(t, "/observe/login?oidcError=authentication_failed", w.Header().Get("Location"))
		})
	}
}

func TestCompleteRequiresOriginAndIdentity(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	for _, origin := range []string{"", "https://attacker.example.com", "https://signoz.example.com.attacker.example.com"} {
		r := httptest.NewRequest(http.MethodPost, "/session", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.Complete(w, r)
		require.Equal(t, http.StatusForbidden, w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/session", nil)
	r.Header.Set("Origin", "https://signoz.example.com")
	w := httptest.NewRecorder()
	h.Complete(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	w = httptest.NewRecorder()
	require.NoError(t, h.setCookie(w, identityCookie, loginCookie{Email: "alice@example.com"}, time.Minute, http.SameSiteStrictMode))
	r.AddCookie(responseCookie(t, w, identityCookie))
	w = httptest.NewRecorder()
	h.createSession = func(context.Context, valuer.Email) (*authtypes.GettableToken, error) {
		return nil, fmt.Errorf("sensitive db error")
	}
	h.Complete(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.NotContains(t, w.Body.String(), "sensitive db error")
}

func TestPublicConfigAndDisabledHandlers(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	w := httptest.NewRecorder()
	h.GetConfig(w, httptest.NewRequest(http.MethodGet, Route, nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"enabled":true`)
	require.Contains(t, w.Body.String(), `"loginURL":"/observe/api/v2/sessions/oidc/login"`)
	for _, secret := range []string{h.config.ClientSecret, h.config.CookieKey, h.config.Issuer} {
		require.NotContains(t, w.Body.String(), secret)
	}
	h.config.Enabled = false
	for _, handler := range []http.HandlerFunc{h.Start, h.Callback, h.Complete} {
		w = httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, Route, nil))
		require.Equal(t, http.StatusNotFound, w.Code)
	}
	w = httptest.NewRecorder()
	h.GetConfig(w, httptest.NewRequest(http.MethodGet, Route, nil))
	require.Contains(t, w.Body.String(), `"enabled":false`)
	require.NotContains(t, w.Body.String(), "loginURL")
}
