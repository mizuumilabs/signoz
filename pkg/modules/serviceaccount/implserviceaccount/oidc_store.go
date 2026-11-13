package implserviceaccount

import (
	"context"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/types/serviceaccounttypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

func (s *store) GetOIDCBinding(ctx context.Context, orgID, id valuer.UUID) (*serviceaccounttypes.OIDCBinding, error) {
	binding := new(serviceaccounttypes.OIDCBinding)
	err := s.sqlstore.BunDBCtx(ctx).NewSelect().Model(binding).Where("service_account_id = ?", id).Where("org_id = ?", orgID).Scan(ctx)
	if err != nil {
		return nil, s.sqlstore.WrapNotFoundErrf(err, serviceaccounttypes.ErrCodeServiceAccountNotFound, "OIDC binding does not exist")
	}
	return binding, nil
}

func (s *store) SetOIDCBinding(ctx context.Context, b *serviceaccounttypes.OIDCBinding) error {
	result, err := s.sqlstore.BunDBCtx(ctx).ExecContext(ctx, `INSERT INTO service_account_oidc_binding (service_account_id,org_id,issuer,client_id,subject)
		SELECT id,org_id,?,?,? FROM service_account WHERE id=? AND org_id=? AND status='active'
		ON CONFLICT (service_account_id) DO UPDATE SET client_id=excluded.client_id,subject=excluded.subject
		WHERE service_account_oidc_binding.org_id=excluded.org_id AND service_account_oidc_binding.issuer=excluded.issuer`, b.Issuer, b.ClientID, b.Subject, b.ServiceAccountID, b.OrgID)
	if err != nil {
		return s.sqlstore.WrapAlreadyExistsErrf(err, errors.CodeAlreadyExists, "OIDC subject or client is already bound to another service account")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New(errors.TypeAlreadyExists, errors.CodeAlreadyExists, "service account is unavailable or its binding belongs to another issuer")
	}
	return nil
}

func (s *store) DeleteOIDCBinding(ctx context.Context, orgID, id valuer.UUID) error {
	_, err := s.sqlstore.BunDBCtx(ctx).NewDelete().Model((*serviceaccounttypes.OIDCBinding)(nil)).Where("org_id = ?", orgID).Where("service_account_id = ?", id).Exec(ctx)
	return err
}

func (s *store) GetOIDCServiceAccount(ctx context.Context, issuer, subject, clientID string) (*serviceaccounttypes.ServiceAccount, error) {
	sa := new(serviceaccounttypes.ServiceAccount)
	err := s.sqlstore.BunDBCtx(ctx).NewSelect().Model(sa).
		Join("JOIN service_account_oidc_binding AS oidc ON oidc.service_account_id=service_account.id AND oidc.org_id=service_account.org_id").
		Where("oidc.issuer = ?", issuer).Where("oidc.subject = ?", subject).Where("oidc.client_id = ?", clientID).
		Where("service_account.status = ?", serviceaccounttypes.ServiceAccountStatusActive.StringValue()).Scan(ctx)
	if err != nil {
		return nil, s.sqlstore.WrapNotFoundErrf(err, serviceaccounttypes.ErrCodeServiceAccountNotFound, "active OIDC service account binding does not exist")
	}
	return sa, nil
}
