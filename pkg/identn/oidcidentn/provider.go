package oidcidentn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/identn"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/coreos/go-oidc/v3/oidc"
)

type IdentityStore interface {
	GetOIDCIdentity(context.Context, string, string, string) (*authtypes.Identity, error)
}

type provider struct {
	config           identn.OIDCConfig
	store            IdentityStore
	client           *http.Client
	mu               sync.Mutex
	verifier         *oidc.IDTokenVerifier
	retryDiscoveryAt time.Time
}

func NewFactory(store IdentityStore) factory.ProviderFactory[identn.IdentN, identn.Config] {
	return factory.NewProviderFactory(factory.MustNewName(authtypes.IdentNProviderOIDC.StringValue()), func(_ context.Context, _ factory.ProviderSettings, config identn.Config) (identn.IdentN, error) {
		return New(config.OIDC, store)
	})
}

func New(config identn.OIDCConfig, store IdentityStore) (identn.IdentN, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &provider{config: config, store: store, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (p *provider) Name() authtypes.IdentNProvider { return authtypes.IdentNProviderOIDC }

// The unverified issuer only selects the verifier; it never establishes identity.
func (p *provider) Test(r *http.Request) bool {
	if !p.config.Enabled {
		return false
	}
	token := bearerToken(r)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	return json.Unmarshal(payload, &claims) == nil && claims.Issuer == p.config.Issuer
}

func (p *provider) GetIdentity(r *http.Request) (*authtypes.Identity, error) {
	if !p.Test(r) {
		return nil, invalidToken()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	verifier, err := p.getVerifier(ctx)
	if err != nil {
		return nil, invalidToken()
	}
	token, err := verifier.Verify(ctx, bearerToken(r))
	if err != nil || token.Subject == "" {
		return nil, invalidToken()
	}
	var claims struct {
		Type     string `json:"typ"`
		ClientID string `json:"azp"`
	}
	if err := token.Claims(&claims); err != nil || claims.Type != "Bearer" || claims.ClientID == "" {
		return nil, invalidToken()
	}
	identity, err := p.store.GetOIDCIdentity(ctx, token.Issuer, token.Subject, claims.ClientID)
	if err != nil || identity == nil || identity.Principal != authtypes.PrincipalServiceAccount || identity.ServiceAccountID.IsZero() || !identity.UserID.IsZero() || identity.OrgID.IsZero() {
		return nil, invalidToken()
	}
	identity.IdenNProvider = authtypes.IdentNProviderOIDC
	return identity, nil
}

func (p *provider) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifier != nil {
		return p.verifier, nil
	}
	if time.Now().Before(p.retryDiscoveryAt) {
		return nil, invalidToken()
	}
	p.retryDiscoveryAt = time.Now().Add(5 * time.Second)
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.config.Issuer)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, err
	}
	if err := identn.ValidateOIDCURL(metadata.JWKSURL); err != nil {
		return nil, err
	}
	p.verifier = provider.Verifier(&oidc.Config{ClientID: p.config.Audience, SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512}})
	return p.verifier, nil
}

func bearerToken(r *http.Request) string {
	if len(r.Header.Values("Authorization")) != 1 {
		return ""
	}
	value := r.Header.Get("Authorization")
	if len(value) > 16*1024 {
		return ""
	}
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func invalidToken() error {
	return errors.New(errors.TypeUnauthenticated, errors.CodeUnauthenticated, "invalid service-account access token")
}
