package oidclogin

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/valuer"
)

type Config struct {
	Enabled      bool        `mapstructure:"enabled"`
	Issuer       string      `mapstructure:"issuer"`
	ClientID     string      `mapstructure:"client_id"`
	ClientSecret string      `mapstructure:"client_secret"`
	CookieKey    string      `mapstructure:"cookie_key"`
	OrgID        valuer.UUID `mapstructure:"org_id"`
}

func NewConfigFactory() factory.ConfigFactory {
	return factory.NewConfigFactory(factory.MustNewName("oidc"), func() factory.Config { return &Config{} })
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if err := validateURL(c.Issuer); err != nil {
		return fmt.Errorf("oidc::issuer: %w", err)
	}
	if c.ClientID == "" || c.ClientSecret == "" || c.OrgID.IsZero() {
		return fmt.Errorf("oidc requires client_id, client_secret and org_id")
	}
	key, err := base64.StdEncoding.DecodeString(c.CookieKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("oidc::cookie_key must be a base64-encoded 32-byte random key")
	}
	return nil
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("expected an absolute HTTPS URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return fmt.Errorf("HTTPS is required except on loopback hosts")
	}
	return nil
}

func ValidateExternalURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("global::external_url is required for OIDC")
	}
	if err := validateURL(u.String()); err != nil {
		return fmt.Errorf("global::external_url: %w", err)
	}
	return nil
}
