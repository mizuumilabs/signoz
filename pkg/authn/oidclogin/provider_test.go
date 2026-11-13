package oidclogin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type testProvider struct {
	server            *httptest.Server
	key               *rsa.PrivateKey
	claims            map[string]any
	authorization     url.Values
	exchanges         int
	tokenStatus       int
	discoveryStatus   int
	metadataOverrides map[string]string
}

func newTestProvider(t *testing.T) *testProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &testProvider{key: key, tokenStatus: http.StatusOK, discoveryStatus: http.StatusOK}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if p.discoveryStatus != http.StatusOK {
				w.WriteHeader(p.discoveryStatus)
				return
			}
			metadata := map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}}
			for key, value := range p.metadataOverrides {
				metadata[key] = value
			}
			_ = json.NewEncoder(w).Encode(metadata)
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			p.exchanges++
			if p.tokenStatus != http.StatusOK {
				w.WriteHeader(p.tokenStatus)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			assert.NoError(t, r.ParseForm())
			assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
			assert.Equal(t, "test-code", r.Form.Get("code"))
			assert.Equal(t, p.authorization.Get("redirect_uri"), r.Form.Get("redirect_uri"))
			assert.Equal(t, p.authorization.Get("code_challenge"), oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")))
			client, secret, basic := r.BasicAuth()
			assert.True(t, basic)
			assert.Equal(t, "signoz", client)
			assert.Equal(t, "secret", secret)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-token", "token_type": "Bearer", "id_token": p.sign(t)})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))
	t.Cleanup(p.server.Close)
	p.claims = map[string]any{"iss": p.server.URL, "aud": "signoz", "sub": "keycloak-user", "email": "alice@example.com", "email_verified": true, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
	return p
}

func (p *testProvider) sign(t *testing.T) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test","typ":"JWT"}`))
	payload, err := json.Marshal(p.claims)
	require.NoError(t, err)
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func startLogin(t *testing.T, h *Handler, p *testProvider) (*http.Cookie, url.Values) {
	t.Helper()
	w := httptest.NewRecorder()
	h.Start(w, httptest.NewRequest(http.MethodGet, "https://signoz.example.com/observe"+Route+"/login", nil))
	require.Equal(t, http.StatusSeeOther, w.Code)
	authorization, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, p.server.URL+"/authorize", authorization.Scheme+"://"+authorization.Host+authorization.Path)
	p.authorization = authorization.Query()
	p.claims["nonce"] = p.authorization.Get("nonce")
	require.Equal(t, "S256", p.authorization.Get("code_challenge_method"))
	require.NotEmpty(t, p.authorization.Get("state"))
	require.NotEmpty(t, p.authorization.Get("nonce"))
	require.Equal(t, "https://signoz.example.com/observe"+Route+"/callback", p.authorization.Get("redirect_uri"))
	return responseCookie(t, w, transactionCookie), p.authorization
}

func responseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge > 0 {
			return cookie
		}
	}
	t.Fatalf("missing %s cookie", name)
	return nil
}

func callbackLogin(h *Handler, cookie *http.Cookie, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://signoz.example.com/observe"+Route+"/callback?"+values.Encode(), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.Callback(w, r)
	return w
}
