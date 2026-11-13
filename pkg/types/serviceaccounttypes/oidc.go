package serviceaccounttypes

import (
	"context"
	"strings"
	"unicode"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/uptrace/bun"
)

type PostableOIDCBinding struct {
	ClientID string `json:"clientId" required:"true"`
	Subject  string `json:"subject" required:"true"`
}

func (b *PostableOIDCBinding) Validate() error {
	if b == nil {
		return errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "OIDC binding is required")
	}
	for _, field := range []struct{ name, value string }{{"clientId", b.ClientID}, {"subject", b.Subject}} {
		if strings.TrimSpace(field.value) == "" || len(field.value) > 255 || strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
			return errors.Newf(errors.TypeInvalidInput, errors.CodeInvalidInput, "%s must contain 1 to 255 bytes without control characters", field.name)
		}
	}
	return nil
}

type OIDCBinding struct {
	bun.BaseModel    `bun:"table:service_account_oidc_binding,alias:service_account_oidc_binding"`
	ServiceAccountID valuer.UUID `bun:"service_account_id,pk,type:text" json:"-"`
	OrgID            valuer.UUID `bun:"org_id,type:text" json:"-"`
	Issuer           string      `bun:"issuer" json:"issuer"`
	ClientID         string      `bun:"client_id" json:"clientId"`
	Subject          string      `bun:"subject" json:"subject"`
}

type GettableOIDCBinding struct {
	Enabled  bool         `json:"enabled"`
	Issuer   string       `json:"issuer"`
	Audience string       `json:"audience"`
	Binding  *OIDCBinding `json:"binding"`
}

type OIDCStore interface {
	GetOIDCBinding(context.Context, valuer.UUID, valuer.UUID) (*OIDCBinding, error)
	SetOIDCBinding(context.Context, *OIDCBinding) error
	DeleteOIDCBinding(context.Context, valuer.UUID, valuer.UUID) error
	GetOIDCServiceAccount(context.Context, string, string, string) (*ServiceAccount, error)
}
