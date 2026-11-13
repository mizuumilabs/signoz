package identn

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOIDCConfigurationValidation(t *testing.T) {
	require.NoError(t, (OIDCConfig{}).Validate())
	base := OIDCConfig{Enabled: true, Issuer: "https://keycloak.example.com/realms/observability", Audience: "signoz-api"}
	require.NoError(t, base.Validate())
	for _, tc := range []struct {
		name   string
		change func(*OIDCConfig)
	}{
		{"missing issuer", func(c *OIDCConfig) { c.Issuer = "" }},
		{"missing audience", func(c *OIDCConfig) { c.Audience = "" }},
		{"whitespace audience", func(c *OIDCConfig) { c.Audience = "signoz api" }},
		{"control audience", func(c *OIDCConfig) { c.Audience = "signoz\x00api" }},
		{"long audience", func(c *OIDCConfig) { c.Audience = strings.Repeat("a", 513) }},
		{"remote HTTP issuer", func(c *OIDCConfig) { c.Issuer = "http://keycloak.example.com/realm" }},
	} {
		t.Run(tc.name, func(t *testing.T) { c := base; tc.change(&c); require.Error(t, c.Validate()) })
	}
	c := Config{OIDC: base, Impersonation: ImpersonationConfig{Enabled: true}}
	require.Error(t, c.Validate())
	c.Impersonation.Enabled = false
	require.NoError(t, c.Validate())
}

func TestValidateOIDCURL(t *testing.T) {
	for _, raw := range []string{"https://keycloak.example.com/realms/test", "http://localhost:8080/realm", "http://127.0.0.1:8080/keys", "http://[::1]:8080/realm"} {
		t.Run(raw, func(t *testing.T) { require.NoError(t, ValidateOIDCURL(raw)) })
	}
	for _, raw := range []string{"", "/realms/test", "http://keycloak.example.com/realm", "https:///realm", "https://user:secret@keycloak.example.com", "https://keycloak.example.com?key=secret", "https://keycloak.example.com#fragment", "file:///tmp/keys", "http://localhost.example.com/realm"} {
		t.Run(raw, func(t *testing.T) { require.Error(t, ValidateOIDCURL(raw)) })
	}
}
