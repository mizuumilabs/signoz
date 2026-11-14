package oidclogin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/stretchr/testify/require"
)

func TestBackchannelLogoutValidation(t *testing.T) {
	for _, name := range []string{"valid", "subject only", "sid only", "unknown session", "retry", "issuer", "audience", "signature", "expired", "missing expiry", "missing iat", "old iat", "future iat", "missing jti", "no subject or sid", "nonce", "empty nonce", "null nonce", "missing events", "wrong event", "null event", "array event", "future nbf", "storage failure", "disabled"} {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t)
			h := testHandler(t, p)
			p.claims = map[string]any{"iss": p.server.URL, "aud": "signoz", "sub": "keycloak-user", "sid": "session-one", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "logout-one", "events": map[string]any{logoutEvent: map[string]any{}}}
			called := 0
			h.revokeSessions = func(_ context.Context, session authtypes.OIDCSession) error {
				called++
				require.Equal(t, h.config.Issuer, session.Issuer)
				require.Equal(t, h.config.ClientID, session.ClientID)
				require.Equal(t, h.config.OrgID.String(), session.OrgID)
				require.Equal(t, p.claims["iat"], session.IssuedAt)
				if name == "storage failure" {
					return fmt.Errorf("private database details")
				}
				return nil
			}
			status := http.StatusBadRequest
			switch name {
			case "valid", "retry", "unknown session":
				status = http.StatusOK
			case "subject only":
				delete(p.claims, "sid")
				status = http.StatusOK
			case "sid only":
				delete(p.claims, "sub")
				status = http.StatusOK
			case "issuer":
				p.claims["iss"] = "https://other.example.com"
			case "audience":
				p.claims["aud"] = "other-client"
			case "signature":
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				p.key = key
			case "expired":
				p.claims["exp"] = time.Now().Add(-time.Minute).Unix()
			case "missing expiry":
				delete(p.claims, "exp")
			case "missing iat":
				delete(p.claims, "iat")
			case "old iat":
				p.claims["iat"] = time.Now().Add(-10 * time.Minute).Unix()
			case "future iat":
				p.claims["iat"] = time.Now().Add(2 * time.Minute).Unix()
			case "missing jti":
				delete(p.claims, "jti")
			case "no subject or sid":
				delete(p.claims, "sub")
				delete(p.claims, "sid")
			case "nonce":
				p.claims["nonce"] = "login-nonce"
			case "empty nonce":
				p.claims["nonce"] = ""
			case "null nonce":
				p.claims["nonce"] = nil
			case "missing events":
				delete(p.claims, "events")
			case "wrong event":
				p.claims["events"] = map[string]any{"other": map[string]any{}}
			case "null event":
				p.claims["events"] = map[string]any{logoutEvent: nil}
			case "array event":
				p.claims["events"] = map[string]any{logoutEvent: []string{}}
			case "future nbf":
				p.claims["nbf"] = time.Now().Add(time.Minute).Unix()
			case "disabled":
				h.config.Enabled = false
				status = http.StatusNotFound
			}
			encoded := url.Values{"logout_token": {p.sign(t)}}.Encode()
			attempts := 1
			if name == "retry" {
				attempts = 2
			}
			for range attempts {
				r := httptest.NewRequest(http.MethodPost, Route+"/backchannel-logout", strings.NewReader(encoded))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				h.BackchannelLogout(w, r)
				require.Equal(t, status, w.Code, w.Body.String())
				require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
				require.NotContains(t, w.Body.String(), "private database details")
			}
			if status == http.StatusOK {
				require.Equal(t, attempts, called)
			} else if name != "storage failure" {
				require.Zero(t, called)
			}
		})
	}
}

func TestBackchannelLogoutRequiresFormBody(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	for _, tc := range []struct{ method, contentType, body, query string }{
		{http.MethodGet, "application/x-www-form-urlencoded", "", ""},
		{http.MethodPost, "application/json", `{"logout_token":"test"}`, ""},
		{http.MethodPost, "application/x-www-form-urlencoded", "", "?logout_token=test"},
		{http.MethodPost, "application/x-www-form-urlencoded", "logout_token=one&logout_token=two", ""},
		{http.MethodPost, "application/x-www-form-urlencoded", "logout_token=" + strings.Repeat("a", 65<<10), ""},
	} {
		r := httptest.NewRequest(tc.method, Route+"/backchannel-logout"+tc.query, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		h.BackchannelLogout(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
}

func TestLoginPreservesProviderSession(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	p.claims["sid"] = "keycloak-session"
	cookie, authorization := startLogin(t, h, p)
	w := callbackLogin(h, cookie, url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}})
	r := httptest.NewRequest(http.MethodPost, Route+"/session", nil)
	r.Header.Set("Origin", "https://signoz.example.com")
	r.AddCookie(responseCookie(t, w, identityCookie))
	called := false
	h.createSession = func(_ context.Context, identity Identity) (*authtypes.GettableToken, error) {
		called = true
		require.Equal(t, "keycloak-user", identity.Session.Subject)
		require.Equal(t, "keycloak-session", identity.Session.SID)
		require.Equal(t, p.claims["iat"], identity.Session.IssuedAt)
		require.Equal(t, p.server.URL, identity.Session.Issuer)
		return &authtypes.GettableToken{}, nil
	}
	w = httptest.NewRecorder()
	h.Complete(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.True(t, called)
}
