package implserviceaccount

import (
	"context"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/identn"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/serviceaccounttypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

func (m *module) OIDCConfig() identn.OIDCConfig { return m.oidcConfig }

func (m *module) GetOIDCBinding(ctx context.Context, orgID, id valuer.UUID) (*serviceaccounttypes.GettableOIDCBinding, error) {
	if _, err := m.store.Get(ctx, orgID, id); err != nil {
		return nil, err
	}
	binding, err := m.store.GetOIDCBinding(ctx, orgID, id)
	if err != nil && !errors.Ast(err, errors.TypeNotFound) {
		return nil, err
	}
	return &serviceaccounttypes.GettableOIDCBinding{Enabled: m.oidcConfig.Enabled, Issuer: m.oidcConfig.Issuer, Audience: m.oidcConfig.Audience, Binding: binding}, nil
}

func (m *module) SetOIDCBinding(ctx context.Context, orgID, id valuer.UUID, binding *serviceaccounttypes.PostableOIDCBinding) error {
	if !m.oidcConfig.Enabled {
		return errors.New(errors.TypeForbidden, errors.CodeForbidden, "service account OIDC is disabled")
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	sa, err := m.store.Get(ctx, orgID, id)
	if err != nil {
		return err
	}
	if err := sa.ErrIfDeleted(); err != nil {
		return err
	}
	existing, err := m.store.GetOIDCBinding(ctx, orgID, id)
	if err != nil && !errors.Ast(err, errors.TypeNotFound) {
		return err
	}
	if existing != nil && existing.Issuer != m.oidcConfig.Issuer {
		return errors.New(errors.TypeAlreadyExists, errors.CodeAlreadyExists, "delete the binding for the previous issuer before creating a new binding")
	}
	return m.store.SetOIDCBinding(ctx, &serviceaccounttypes.OIDCBinding{ServiceAccountID: id, OrgID: orgID, Issuer: m.oidcConfig.Issuer, ClientID: binding.ClientID, Subject: binding.Subject})
}

func (m *module) DeleteOIDCBinding(ctx context.Context, orgID, id valuer.UUID) error {
	if _, err := m.store.Get(ctx, orgID, id); err != nil {
		return err
	}
	return m.store.DeleteOIDCBinding(ctx, orgID, id)
}

func (m *module) GetOIDCIdentity(ctx context.Context, issuer, subject, clientID string) (*authtypes.Identity, error) {
	if !m.oidcConfig.Enabled || issuer != m.oidcConfig.Issuer {
		return nil, errors.New(errors.TypeUnauthenticated, errors.CodeUnauthenticated, "service account OIDC is unavailable for this issuer")
	}
	if err := (&serviceaccounttypes.PostableOIDCBinding{ClientID: clientID, Subject: subject}).Validate(); err != nil {
		return nil, err
	}
	sa, err := m.store.GetOIDCServiceAccount(ctx, issuer, subject, clientID)
	if err != nil {
		return nil, err
	}
	identity := sa.ToIdentity()
	identity.IdenNProvider = authtypes.IdentNProviderOIDC
	return identity, nil
}
