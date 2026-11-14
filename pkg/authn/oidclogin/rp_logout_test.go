package oidclogin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRPInitiatedLogout(t *testing.T) {
	for _, name := range []string{"hint", "no hint", "tampered hint", "expired hint", "missing endpoint", "insecure endpoint", "unavailable", "cross origin", "missing origin", "disabled"} {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t)
			p.metadataOverrides = map[string]string{"end_session_endpoint": p.server.URL + "/logout"}
			h := testHandler(t, p)
			r := httptest.NewRequest(http.MethodDelete, "https://signoz.example.com/observe/api/v2/sessions?logout_provider=true&redirect=https://attacker.example.com", nil)
			r.Header.Set("Origin", "https://signoz.example.com")
			w := httptest.NewRecorder()
			if name == "hint" || name == "tampered hint" || name == "expired hint" {
				lifetime := time.Hour
				if name == "expired hint" {
					lifetime = -time.Hour
				}
				require.NoError(t, h.setCookie(w, logoutCookie, loginCookie{IDToken: "verified-id-token"}, lifetime, http.SameSiteStrictMode))
				cookie := w.Result().Cookies()[0]
				if name == "tampered hint" {
					cookie.Value = "invalid"
				}
				r.AddCookie(cookie)
			}
			switch name {
			case "missing endpoint":
				delete(p.metadataOverrides, "end_session_endpoint")
			case "insecure endpoint":
				p.metadataOverrides["end_session_endpoint"] = "http://keycloak.example.com/logout"
			case "unavailable":
				p.discoveryStatus = http.StatusServiceUnavailable
			case "cross origin":
				r.Header.Set("Origin", "https://attacker.example.com")
			case "missing origin":
				r.Header.Del("Origin")
			case "disabled":
				h.config.Enabled = false
			}
			w = httptest.NewRecorder()
			raw, err := h.LogoutURL(context.Background(), w, r)
			switch name {
			case "missing endpoint", "insecure endpoint", "unavailable", "cross origin", "missing origin":
				require.Error(t, err)
				require.Empty(t, raw)
				return
			case "disabled":
				require.NoError(t, err)
				require.Empty(t, raw)
				return
			}
			require.NoError(t, err)
			endpoint, err := url.Parse(raw)
			require.NoError(t, err)
			require.Equal(t, p.server.URL+"/logout", endpoint.Scheme+"://"+endpoint.Host+endpoint.Path)
			require.Equal(t, "signoz", endpoint.Query().Get("client_id"))
			require.Equal(t, "https://signoz.example.com/observe/login", endpoint.Query().Get("post_logout_redirect_uri"))
			if name == "hint" {
				require.Equal(t, "verified-id-token", endpoint.Query().Get("id_token_hint"))
			} else {
				require.Empty(t, endpoint.Query().Get("id_token_hint"))
			}
			for _, cookie := range w.Result().Cookies() {
				require.Equal(t, -1, cookie.MaxAge)
			}
		})
	}
}

func TestLoginRetainsEncryptedLogoutHint(t *testing.T) {
	p := newTestProvider(t)
	h := testHandler(t, p)
	cookie, authorization := startLogin(t, h, p)
	w := callbackLogin(h, cookie, url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}})
	hint := responseCookie(t, w, logoutCookie)
	require.True(t, hint.HttpOnly)
	require.True(t, hint.Secure)
	require.Equal(t, http.SameSiteStrictMode, hint.SameSite)
	require.Equal(t, "/observe/api/v2/sessions", hint.Path)
	require.NotContains(t, hint.Value, "keycloak-user")
	r := httptest.NewRequest(http.MethodDelete, "/observe/api/v2/sessions", nil)
	r.AddCookie(hint)
	value, err := h.readCookie(r, logoutCookie)
	require.NoError(t, err)
	require.Equal(t, p.sign(t), value.IDToken)
}
