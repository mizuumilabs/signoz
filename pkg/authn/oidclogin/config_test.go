package oidclogin

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	return Config{Enabled: true, Issuer: "https://keycloak.example.com/realms/signoz", ClientID: "signoz", ClientSecret: "secret", CookieKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), OrgID: valuer.GenerateUUID()}
}

func TestValidateExternalURL(t *testing.T) {
	for _, test := range []struct {
		name  string
		u     *url.URL
		valid bool
	}{
		{"nil", nil, false},
		{"unset", &url.URL{Host: "<unset>"}, false},
		{"relative", &url.URL{Path: "/observe"}, false},
		{"https", &url.URL{Scheme: "https", Host: "signoz.example.com", Path: "/observe"}, true},
		{"loopback", &url.URL{Scheme: "http", Host: "localhost:8080"}, true},
		{"remote http", &url.URL{Scheme: "http", Host: "signoz.example.com"}, false},
		{"query", &url.URL{Scheme: "https", Host: "signoz.example.com", RawQuery: "next=/"}, false},
		{"fragment", &url.URL{Scheme: "https", Host: "signoz.example.com", Fragment: "login"}, false},
		{"userinfo", &url.URL{Scheme: "https", Host: "signoz.example.com", User: url.UserPassword("user", "secret")}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateExternalURL(test.u)
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	require.NoError(t, (Config{}).Validate())
	require.NoError(t, validConfig().Validate())
	for _, tt := range []struct {
		name   string
		change func(*Config)
	}{
		{"issuer missing", func(c *Config) { c.Issuer = "" }},
		{"remote http", func(c *Config) { c.Issuer = "http://keycloak.example.com/realm" }},
		{"issuer credentials", func(c *Config) { c.Issuer = "https://user:password@keycloak.example.com" }},
		{"issuer query", func(c *Config) { c.Issuer += "?secret=value" }},
		{"issuer fragment", func(c *Config) { c.Issuer += "#fragment" }},
		{"client id", func(c *Config) { c.ClientID = "" }},
		{"secret", func(c *Config) { c.ClientSecret = "" }},
		{"org", func(c *Config) { c.OrgID = valuer.UUID{} }},
		{"key missing", func(c *Config) { c.CookieKey = "" }},
		{"key malformed", func(c *Config) { c.CookieKey = "not base64" }},
		{"short key", func(c *Config) { c.CookieKey = base64.StdEncoding.EncodeToString(make([]byte, 16)) }},
	} {
		t.Run(tt.name, func(t *testing.T) { c := validConfig(); tt.change(&c); require.Error(t, c.Validate()) })
	}
	for _, issuer := range []string{"http://localhost:8080/realm", "http://127.0.0.1:8080/realm", "http://[::1]:8080/realm"} {
		c := validConfig()
		c.Issuer = issuer
		require.NoError(t, c.Validate())
	}
}
