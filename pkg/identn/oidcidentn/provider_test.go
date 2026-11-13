package oidcidentn

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func TestAccessTokenAuthenticationAndBindingRevocation(t *testing.T) {
	p, f, store := setupProvider(t)
	r := requestWithToken(f.sign(t, f.claims()))
	require.True(t, p.Test(r))
	require.Zero(t, f.discoveries.Load())
	identity, err := p.GetIdentity(r)
	require.NoError(t, err)
	require.Equal(t, store.identity.ServiceAccountID, identity.ServiceAccountID)
	require.Equal(t, store.identity.OrgID, identity.OrgID)
	require.Equal(t, authtypes.PrincipalServiceAccount, identity.Principal)
	require.Equal(t, authtypes.IdentNProviderOIDC, identity.IdenNProvider)
	require.True(t, identity.UserID.IsZero())
	_, err = p.GetIdentity(r)
	require.NoError(t, err)
	require.Equal(t, 2, store.calls)
	require.EqualValues(t, 1, f.discoveries.Load())
	require.EqualValues(t, 1, f.keyRequests.Load())
	store.revoked = true
	identity, err = p.GetIdentity(r)
	require.Nil(t, identity)
	require.True(t, errors.Ast(err, errors.TypeUnauthenticated))
	require.Equal(t, "invalid service-account access token", err.Error())
	require.Equal(t, 3, store.calls)
}

func TestRejectInvalidAccessTokens(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"ID token", func(c map[string]any) { c["typ"] = "ID" }},
		{"missing type", func(c map[string]any) { delete(c, "typ") }},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://other.example.com/realm" }},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other-api" }},
		{"missing audience", func(c map[string]any) { delete(c, "aud") }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"missing expiry", func(c map[string]any) { delete(c, "exp") }},
		{"future not before", func(c map[string]any) { c["nbf"] = time.Now().Add(10 * time.Minute).Unix() }},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }},
		{"missing authorized party", func(c map[string]any) { delete(c, "azp") }},
		{"wrong subject binding", func(c map[string]any) { c["sub"] = "human-user" }},
		{"wrong client binding", func(c map[string]any) { c["azp"] = "unbound-client" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, f, _ := setupProvider(t)
			claims := f.claims()
			tc.change(claims)
			identity, err := p.GetIdentity(requestWithToken(f.sign(t, claims)))
			require.Nil(t, identity)
			require.True(t, errors.Ast(err, errors.TypeUnauthenticated))
			require.Equal(t, "invalid service-account access token", err.Error())
		})
	}
}

func TestRejectInvalidSignature(t *testing.T) {
	p, f, store := setupProvider(t)
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	identity, err := p.GetIdentity(requestWithToken(signClaims(t, foreign, "first", f.claims())))
	require.Nil(t, identity)
	require.True(t, errors.Ast(err, errors.TypeUnauthenticated))
	require.Zero(t, store.calls)
}

func TestRejectNonServiceAccountIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*bindingStore)
	}{
		{"nil identity", func(s *bindingStore) { s.identity = nil }},
		{"user principal", func(s *bindingStore) { s.identity.Principal = authtypes.PrincipalUser }},
		{"user id present", func(s *bindingStore) { s.identity.UserID = valuer.GenerateUUID() }},
		{"missing organization", func(s *bindingStore) { s.identity.OrgID = valuer.UUID{} }},
		{"missing service account", func(s *bindingStore) { s.identity.ServiceAccountID = valuer.UUID{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, f, s := setupProvider(t)
			tc.change(s)
			identity, err := p.GetIdentity(requestWithToken(f.sign(t, f.claims())))
			require.Nil(t, identity)
			require.True(t, errors.Ast(err, errors.TypeUnauthenticated))
		})
	}
}

func TestTokenSelectionDoesNotMakeNetworkRequests(t *testing.T) {
	p, f, _ := setupProvider(t)
	valid := f.sign(t, f.claims())
	for _, tc := range []struct {
		name     string
		value    string
		accepted bool
	}{
		{"external token", "Bearer " + valid, true},
		{"case insensitive bearer", "bearer " + valid, true},
		{"no header", "", false},
		{"opaque local token", "Bearer application-access", false},
		{"basic", "Basic " + valid, false},
		{"raw token", valid, false},
		{"malformed", "Bearer invalid.payload.signature", false},
		{"oversized", "Bearer " + strings.Repeat("a", 16*1024), false},
		{"extra fields", "Bearer " + valid + " extra", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := requestWithToken("")
			r.Header.Set("Authorization", tc.value)
			require.Equal(t, tc.accepted, p.Test(r))
		})
	}
	r := requestWithToken(valid)
	r.Header.Add("Authorization", "Bearer another-token")
	require.False(t, p.Test(r))
	p.config.Enabled = false
	require.False(t, p.Test(requestWithToken(valid)))
	require.Zero(t, f.discoveries.Load())
	require.Zero(t, f.keyRequests.Load())
}

func TestDiscoveryFailureIsThrottled(t *testing.T) {
	p, f, _ := setupProvider(t)
	f.mu.Lock()
	f.discoveryStatus = http.StatusServiceUnavailable
	f.mu.Unlock()
	r := requestWithToken(f.sign(t, f.claims()))
	_, err := p.GetIdentity(r)
	require.Error(t, err)
	_, err = p.GetIdentity(r)
	require.Error(t, err)
	require.EqualValues(t, 1, f.discoveries.Load())
	f.mu.Lock()
	f.discoveryStatus = http.StatusOK
	f.mu.Unlock()
	p.retryDiscoveryAt = time.Now().Add(-time.Second)
	_, err = p.GetIdentity(r)
	require.NoError(t, err)
	require.EqualValues(t, 2, f.discoveries.Load())
}

func TestRejectInsecureDiscoveredSigningKeys(t *testing.T) {
	p, f, store := setupProvider(t)
	f.mu.Lock()
	f.jwksURL = "http://remote.example.com/keys"
	f.mu.Unlock()
	_, err := p.GetIdentity(requestWithToken(f.sign(t, f.claims())))
	require.True(t, errors.Ast(err, errors.TypeUnauthenticated))
	require.Zero(t, f.keyRequests.Load())
	require.Zero(t, store.calls)
}

func TestRejectDiscoveryIssuerMismatch(t *testing.T) {
	p, f, store := setupProvider(t)
	f.mu.Lock()
	f.discoveryIssuer = "https://other.example.com/realms/test"
	f.mu.Unlock()
	_, err := p.GetIdentity(requestWithToken(f.sign(t, f.claims())))
	require.True(t, errors.Ast(err, errors.TypeUnauthenticated))
	require.Zero(t, f.keyRequests.Load())
	require.Zero(t, store.calls)
}

func TestSigningKeyRotation(t *testing.T) {
	p, f, _ := setupProvider(t)
	_, err := p.GetIdentity(requestWithToken(f.sign(t, f.claims())))
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f.mu.Lock()
	f.key = newKey
	f.kid = "rotated"
	f.mu.Unlock()
	_, err = p.GetIdentity(requestWithToken(f.sign(t, f.claims())))
	require.NoError(t, err)
	require.EqualValues(t, 2, f.keyRequests.Load())
}
