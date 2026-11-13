package identn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/factory/factorytest"
	"github.com/SigNoz/signoz/pkg/identn"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/stretchr/testify/require"
)

type resolverProvider struct {
	name          authtypes.IdentNProvider
	match         func(*http.Request) bool
	identityCalls int
}

func (p *resolverProvider) Name() authtypes.IdentNProvider { return p.name }
func (p *resolverProvider) Test(r *http.Request) bool      { return p.match(r) }
func (p *resolverProvider) GetIdentity(*http.Request) (*authtypes.Identity, error) {
	p.identityCalls++
	return nil, errors.New(errors.TypeUnauthenticated, errors.CodeUnauthenticated, "invalid token")
}

func resolverFactory(p *resolverProvider) factory.ProviderFactory[identn.IdentN, identn.Config] {
	return factory.NewProviderFactory(factory.MustNewName(p.name.StringValue()), func(context.Context, factory.ProviderSettings, identn.Config) (identn.IdentN, error) { return p, nil })
}

func TestOIDCResolverPrecedesTokenizerWithoutAuthenticationFallback(t *testing.T) {
	oidc := &resolverProvider{name: authtypes.IdentNProviderOIDC, match: func(r *http.Request) bool {
		return r.Header.Get("Authorization") == "Bearer external.invalid.signature"
	}}
	tokenizer := &resolverProvider{name: authtypes.IdentNProviderTokenizer, match: func(r *http.Request) bool { return r.Header.Get("Authorization") != "" }}
	apiKey := &resolverProvider{name: authtypes.IdentNProviderAPIKey, match: func(r *http.Request) bool { return r.Header.Get("SIGNOZ-API-KEY") != "" }}
	config := identn.Config{OIDC: identn.OIDCConfig{Enabled: true}, Tokenizer: identn.TokenizerConfig{Enabled: true}, APIKeyConfig: identn.APIKeyConfig{Enabled: true}}
	factories := factory.MustNewNamedMap(resolverFactory(oidc), resolverFactory(tokenizer), resolverFactory(apiKey))
	resolver, err := identn.NewIdentNResolver(context.Background(), factorytest.NewSettings(), config, factories)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, authorization, apiKey string
		expected                    authtypes.IdentNProvider
	}{
		{"external OIDC", "Bearer external.invalid.signature", "", authtypes.IdentNProviderOIDC},
		{"local JWT", "Bearer local.jwt.signature", "", authtypes.IdentNProviderTokenizer},
		{"local opaque token", "Bearer application-access", "", authtypes.IdentNProviderTokenizer},
		{"existing API key", "", "application-key", authtypes.IdentNProviderAPIKey},
		{"external plus API key", "Bearer external.invalid.signature", "application-key", authtypes.IdentNProviderOIDC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://signoz.example.com/api", nil)
			if tc.authorization != "" {
				r.Header.Set("Authorization", tc.authorization)
			}
			if tc.apiKey != "" {
				r.Header.Set("SIGNOZ-API-KEY", tc.apiKey)
			}
			selected := resolver.GetIdentN(r)
			require.NotNil(t, selected)
			require.Equal(t, tc.expected, selected.Name())
		})
	}
	r := httptest.NewRequest(http.MethodGet, "https://signoz.example.com/api", nil)
	require.Nil(t, resolver.GetIdentN(r))
	r.Header.Set("Authorization", "Bearer external.invalid.signature")
	_, err = resolver.GetIdentN(r).GetIdentity(r)
	require.Error(t, err)
	require.Equal(t, 1, oidc.identityCalls)
	require.Zero(t, tokenizer.identityCalls)
	require.Zero(t, apiKey.identityCalls)
}

func TestDisabledOIDCDoesNotRequireOIDCFactory(t *testing.T) {
	tokenizer := &resolverProvider{name: authtypes.IdentNProviderTokenizer, match: func(r *http.Request) bool { return r.Header.Get("Authorization") != "" }}
	factories := factory.MustNewNamedMap(resolverFactory(tokenizer))
	resolver, err := identn.NewIdentNResolver(context.Background(), factorytest.NewSettings(), identn.Config{Tokenizer: identn.TokenizerConfig{Enabled: true}}, factories)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "https://signoz.example.com/api", nil)
	r.Header.Set("Authorization", "Bearer application-access")
	require.Equal(t, authtypes.IdentNProviderTokenizer, resolver.GetIdentN(r).Name())
}
