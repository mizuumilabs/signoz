package oidcidentn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/identn"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

type oidcFixture struct {
	server          *httptest.Server
	mu              sync.Mutex
	key             *rsa.PrivateKey
	kid             string
	jwksURL         string
	discoveryIssuer string
	discoveryStatus int
	discoveries     atomic.Int32
	keyRequests     atomic.Int32
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &oidcFixture{key: key, kid: "first", discoveryStatus: http.StatusOK}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			f.discoveries.Add(1)
			if f.discoveryStatus != http.StatusOK {
				w.WriteHeader(f.discoveryStatus)
				return
			}
			keys := f.server.URL + "/keys"
			if f.jwksURL != "" {
				keys = f.jwksURL
			}
			issuer := f.server.URL
			if f.discoveryIssuer != "" {
				issuer = f.discoveryIssuer
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": keys, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			f.keyRequests.Add(1)
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"}}})
		default:
			w.WriteHeader(http.StatusNotImplemented)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *oidcFixture) claims() map[string]any {
	return map[string]any{"iss": f.server.URL, "aud": "signoz-api", "sub": "service-account-subject", "azp": "automation", "typ": "Bearer", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
}

func (f *oidcFixture) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	return signClaims(t, f.key, f.kid, claims)
}

func signClaims(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	require.NoError(t, err)
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type bindingStore struct {
	issuer   string
	identity *authtypes.Identity
	calls    int
	revoked  bool
}

func (s *bindingStore) GetOIDCIdentity(_ context.Context, issuer, subject, clientID string) (*authtypes.Identity, error) {
	s.calls++
	if s.revoked || issuer != s.issuer || subject != "service-account-subject" || clientID != "automation" {
		return nil, errors.New(errors.TypeNotFound, errors.CodeNotFound, "private binding lookup details")
	}
	if s.identity == nil {
		return nil, nil
	}
	copy := *s.identity
	return &copy, nil
}

func setupProvider(t *testing.T) (*provider, *oidcFixture, *bindingStore) {
	t.Helper()
	f := newOIDCFixture(t)
	s := &bindingStore{issuer: f.server.URL, identity: authtypes.NewPrincipalServiceAccountIdentity(valuer.GenerateUUID(), valuer.GenerateUUID(), valuer.MustNewEmail("automation@serviceaccount.test"), authtypes.IdentNProviderAPIKey)}
	idn, err := New(identn.OIDCConfig{Enabled: true, Issuer: f.server.URL, Audience: "signoz-api"}, s)
	require.NoError(t, err)
	return idn.(*provider), f, s
}

func requestWithToken(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://signoz.example.com/api/v1/service_accounts/me", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
