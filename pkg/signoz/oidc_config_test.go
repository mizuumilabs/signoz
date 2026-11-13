package signoz

import (
	"context"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/SigNoz/signoz/pkg/config/configtest"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func TestOIDCEnvironmentConfiguration(t *testing.T) {
	orgID := valuer.GenerateUUID()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for name, value := range map[string]string{
		"SIGNOZ_OIDC_ENABLED":         "true",
		"SIGNOZ_OIDC_ISSUER":          "https://keycloak.example.com/realms/test",
		"SIGNOZ_OIDC_CLIENT__ID":      "signoz",
		"SIGNOZ_OIDC_CLIENT__SECRET":  "test-client-secret",
		"SIGNOZ_OIDC_COOKIE__KEY":     key,
		"SIGNOZ_OIDC_ORG__ID":         orgID.String(),
		"SIGNOZ_GLOBAL_EXTERNAL__URL": "https://signoz.example.com/observe",
	} {
		t.Setenv(name, value)
	}
	config, err := NewConfig(context.Background(), slog.New(slog.DiscardHandler), configtest.NewResolverConfig())
	require.NoError(t, err)
	require.True(t, config.OIDC.Enabled)
	require.Equal(t, orgID, config.OIDC.OrgID)
	require.Equal(t, "signoz", config.OIDC.ClientID)
	require.Equal(t, "test-client-secret", config.OIDC.ClientSecret)
	require.Equal(t, key, config.OIDC.CookieKey)
	require.Equal(t, "/observe", config.Global.ExternalPath())
	t.Setenv("SIGNOZ_GLOBAL_EXTERNAL__URL", "http://signoz.example.com")
	_, err = NewConfig(context.Background(), slog.New(slog.DiscardHandler), configtest.NewResolverConfig())
	require.Error(t, err)
}

func TestServiceAccountOIDCEnvironmentConfiguration(t *testing.T) {
	for name, value := range map[string]string{
		"SIGNOZ_IDENTN_OIDC_ENABLED":  "true",
		"SIGNOZ_IDENTN_OIDC_ISSUER":   "https://keycloak.example.com/realms/test",
		"SIGNOZ_IDENTN_OIDC_AUDIENCE": "signoz-api",
	} {
		t.Setenv(name, value)
	}
	config, err := NewConfig(context.Background(), slog.New(slog.DiscardHandler), configtest.NewResolverConfig())
	require.NoError(t, err)
	require.True(t, config.IdentN.OIDC.Enabled)
	require.Equal(t, "https://keycloak.example.com/realms/test", config.IdentN.OIDC.Issuer)
	require.Equal(t, "signoz-api", config.IdentN.OIDC.Audience)
	require.False(t, config.OIDC.Enabled)
	require.True(t, config.IdentN.Tokenizer.Enabled)
	require.True(t, config.IdentN.APIKeyConfig.Enabled)
}
