package identn

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/SigNoz/signoz/pkg/errors"
)

type OIDCConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Issuer   string `mapstructure:"issuer"`
	Audience string `mapstructure:"audience"`
}

func (c OIDCConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if err := ValidateOIDCURL(c.Issuer); err != nil {
		return err
	}
	if c.Audience == "" || len(c.Audience) > 512 || strings.IndexFunc(c.Audience, unicode.IsSpace) >= 0 || strings.IndexFunc(c.Audience, unicode.IsControl) >= 0 {
		return errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "identn::oidc::audience must be a nonempty audience without whitespace")
	}
	return nil
}

func ValidateOIDCURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "OIDC URLs must be absolute HTTPS URLs without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "OIDC URLs require HTTPS except on loopback hosts")
	}
	return nil
}
