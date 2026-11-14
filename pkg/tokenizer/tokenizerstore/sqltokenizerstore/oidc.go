package sqltokenizerstore

import (
	"context"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/uptrace/bun"
)

type oidcRevocation struct {
	bun.BaseModel `bun:"table:oidc_session_revocation,alias:oidc_session_revocation"`
	ID            string `bun:"id,pk"`
	IssuedAt      int64  `bun:"issued_at"`
}

func (store *store) RevokeOIDCSessions(ctx context.Context, session authtypes.OIDCSession) error {
	kind, value := "sub", session.Subject
	if session.SID != "" {
		kind, value = "sid", session.SID
	}
	row := &oidcRevocation{ID: session.RevocationKey(kind, value), IssuedAt: session.IssuedAt}
	_, err := store.sqlstore.BunDBCtx(ctx).NewInsert().Model(row).
		On("CONFLICT (id) DO UPDATE").
		Set("issued_at = CASE WHEN EXCLUDED.issued_at > oidc_session_revocation.issued_at THEN EXCLUDED.issued_at ELSE oidc_session_revocation.issued_at END").Exec(ctx)
	return err
}

func (store *store) CheckOIDCSession(ctx context.Context, meta map[string]string) error {
	if meta["authn"] != "oidc" {
		return nil
	}
	session := authtypes.OIDCSessionFromMeta(meta)
	if session.Issuer == "" || session.ClientID == "" || session.OrgID == "" || session.Subject == "" || session.IssuedAt <= 0 {
		return errors.NewUnauthenticatedf(errors.CodeUnauthenticated, "OIDC session requires a new login")
	}
	query := store.sqlstore.BunDBCtx(ctx).NewSelect().Model((*oidcRevocation)(nil)).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			q = q.Where("(id = ? AND issued_at >= ?)", session.RevocationKey("sub", session.Subject), session.IssuedAt)
			if session.SID != "" {
				q = q.WhereOr("id = ?", session.RevocationKey("sid", session.SID))
			}
			return q
		})
	revoked, err := query.Exists(ctx)
	if err != nil {
		return err
	}
	if revoked {
		return errors.NewUnauthenticatedf(errors.CodeUnauthenticated, "OIDC session has been logged out")
	}
	return nil
}
