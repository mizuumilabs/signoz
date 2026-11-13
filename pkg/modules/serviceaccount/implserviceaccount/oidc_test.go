package implserviceaccount

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory/factorytest"
	"github.com/SigNoz/signoz/pkg/identn"
	"github.com/SigNoz/signoz/pkg/modules/serviceaccount"
	"github.com/SigNoz/signoz/pkg/sqlmigration"
	"github.com/SigNoz/signoz/pkg/sqlschema"
	"github.com/SigNoz/signoz/pkg/sqlschema/sqlitesqlschema"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	"github.com/SigNoz/signoz/pkg/sqlstore/sqlitesqlstore"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/serviceaccounttypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func openOIDCStore(t *testing.T, path string) sqlstore.SQLStore {
	t.Helper()
	s, err := sqlitesqlstore.New(context.Background(), factorytest.NewSettings(), sqlstore.Config{Provider: "sqlite", Connection: sqlstore.ConnectionConfig{MaxOpenConns: 1}, Sqlite: sqlstore.SqliteConfig{Path: path, Mode: "wal", BusyTimeout: time.Second, TransactionMode: "deferred"}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.SQLDB().Close()) })
	return s
}

func newOIDCTestModule(t *testing.T) (*module, sqlstore.SQLStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oidc.db")
	s := openOIDCStore(t, path)
	ctx := context.Background()
	_, err := s.BunDB().ExecContext(ctx, "CREATE TABLE organizations (id TEXT PRIMARY KEY)")
	require.NoError(t, err)
	_, err = s.BunDB().NewCreateTable().Model((*serviceaccounttypes.ServiceAccount)(nil)).Exec(ctx)
	require.NoError(t, err)
	_, err = s.BunDB().NewCreateTable().Model((*serviceaccounttypes.FactorAPIKey)(nil)).Exec(ctx)
	require.NoError(t, err)
	schema, err := sqlitesqlschema.New(ctx, factorytest.NewSettings(), sqlschema.Config{}, s)
	require.NoError(t, err)
	migration, err := sqlmigration.NewAddServiceAccountOIDCBindingFactory(s, schema).New(ctx, factorytest.NewSettings(), sqlmigration.Config{})
	require.NoError(t, err)
	require.NoError(t, migration.Up(ctx, s.BunDB()))
	m := NewModule(NewStore(s), nil, nil, nil, factorytest.NewSettings(), serviceaccount.Config{}, identn.OIDCConfig{Enabled: true, Issuer: "https://keycloak.example.com/realms/test", Audience: "signoz-api"}).(*module)
	return m, s, path
}

func addOIDCTestAccount(t *testing.T, m *module, s sqlstore.SQLStore, name string, orgID valuer.UUID) *serviceaccounttypes.ServiceAccount {
	t.Helper()
	_, err := s.BunDB().ExecContext(context.Background(), "INSERT INTO organizations (id) VALUES (?) ON CONFLICT DO NOTHING", orgID)
	require.NoError(t, err)
	sa := serviceaccounttypes.NewServiceAccount(name, "serviceaccount.example.com", serviceaccounttypes.ServiceAccountStatusActive, orgID)
	require.NoError(t, m.store.Create(context.Background(), sa))
	return sa
}

func TestOIDCBindingPersistenceAndRevocation(t *testing.T) {
	m, s, path := newOIDCTestModule(t)
	ctx := context.Background()
	sa := addOIDCTestAccount(t, m, s, "worker", valuer.GenerateUUID())
	initial, err := m.GetOIDCBinding(ctx, sa.OrgID, sa.ID)
	require.NoError(t, err)
	require.Nil(t, initial.Binding)
	require.True(t, initial.Enabled)
	key, err := sa.NewFactorAPIKey("existing", 0)
	require.NoError(t, err)
	require.NoError(t, m.store.CreateFactorAPIKey(ctx, key))
	require.NoError(t, m.SetOIDCBinding(ctx, sa.OrgID, sa.ID, &serviceaccounttypes.PostableOIDCBinding{ClientID: "worker-client", Subject: "keycloak-subject"}))
	identity, err := m.GetOIDCIdentity(ctx, m.oidcConfig.Issuer, "keycloak-subject", "worker-client")
	require.NoError(t, err)
	require.Equal(t, sa.ID, identity.ServiceAccountID)
	require.Equal(t, sa.OrgID, identity.OrgID)
	require.Equal(t, authtypes.IdentNProviderOIDC, identity.IdenNProvider)
	newModule := *m
	newModule.store = NewStore(openOIDCStore(t, path))
	stored, err := newModule.GetOIDCBinding(ctx, sa.OrgID, sa.ID)
	require.NoError(t, err)
	require.Equal(t, "worker-client", stored.Binding.ClientID)
	require.NoError(t, newModule.DeleteOIDCBinding(ctx, sa.OrgID, sa.ID))
	_, err = m.GetOIDCIdentity(ctx, m.oidcConfig.Issuer, "keycloak-subject", "worker-client")
	require.Error(t, err)
	_, err = m.store.GetFactorAPIKeyByKey(ctx, key.Key)
	require.NoError(t, err, "OIDC removal must preserve existing API keys")
	require.NoError(t, m.SetOIDCBinding(ctx, sa.OrgID, sa.ID, &serviceaccounttypes.PostableOIDCBinding{ClientID: "new-client", Subject: "new-subject"}))
	_, err = s.BunDB().ExecContext(ctx, "UPDATE service_account SET status='deleted' WHERE id=?", sa.ID)
	require.NoError(t, err)
	_, err = m.GetOIDCIdentity(ctx, m.oidcConfig.Issuer, "new-subject", "new-client")
	require.Error(t, err, "service account deletion must apply without identity cache expiry")
}

func TestOIDCBindingOrganizationIsolationAndConflicts(t *testing.T) {
	m, s, _ := newOIDCTestModule(t)
	ctx := context.Background()
	first := addOIDCTestAccount(t, m, s, "first", valuer.GenerateUUID())
	second := addOIDCTestAccount(t, m, s, "second", valuer.GenerateUUID())
	binding := &serviceaccounttypes.PostableOIDCBinding{ClientID: "client", Subject: "subject"}
	require.NoError(t, m.SetOIDCBinding(ctx, first.OrgID, first.ID, binding))
	for _, input := range []*serviceaccounttypes.PostableOIDCBinding{binding, {ClientID: "other", Subject: "subject"}, {ClientID: "client", Subject: "other"}} {
		err := m.SetOIDCBinding(ctx, second.OrgID, second.ID, input)
		require.True(t, errors.Ast(err, errors.TypeAlreadyExists), "%v", err)
	}
	_, err := m.GetOIDCBinding(ctx, second.OrgID, first.ID)
	require.Error(t, err)
	require.Error(t, m.SetOIDCBinding(ctx, second.OrgID, first.ID, binding))
	require.Error(t, m.DeleteOIDCBinding(ctx, second.OrgID, first.ID))
	_, err = m.GetOIDCIdentity(ctx, m.oidcConfig.Issuer, "subject", "other-client")
	require.Error(t, err)
	_, err = m.GetOIDCIdentity(ctx, "https://other.example.com", "subject", "client")
	require.Error(t, err)
	_, err = s.BunDB().ExecContext(ctx, "UPDATE service_account_oidc_binding SET org_id=? WHERE service_account_id=?", second.OrgID, first.ID)
	require.NoError(t, err)
	_, err = m.GetOIDCIdentity(ctx, m.oidcConfig.Issuer, "subject", "client")
	require.Error(t, err, "identity join must verify service-account and binding organization agree")
}

func TestOIDCDisabledRecoveryAndIssuerChange(t *testing.T) {
	m, s, _ := newOIDCTestModule(t)
	ctx := context.Background()
	sa := addOIDCTestAccount(t, m, s, "worker", valuer.GenerateUUID())
	binding := &serviceaccounttypes.PostableOIDCBinding{ClientID: "client", Subject: "subject"}
	require.NoError(t, m.SetOIDCBinding(ctx, sa.OrgID, sa.ID, binding))
	originalIssuer := m.oidcConfig.Issuer
	m.oidcConfig.Issuer = "https://new.example.com/realm"
	stored, err := m.GetOIDCBinding(ctx, sa.OrgID, sa.ID)
	require.NoError(t, err)
	require.Equal(t, originalIssuer, stored.Binding.Issuer)
	require.Error(t, m.SetOIDCBinding(ctx, sa.OrgID, sa.ID, binding), "configuration changes must not silently move bindings")
	_, err = m.GetOIDCIdentity(ctx, originalIssuer, "subject", "client")
	require.Error(t, err)
	m.oidcConfig.Enabled = false
	stored, err = m.GetOIDCBinding(ctx, sa.OrgID, sa.ID)
	require.NoError(t, err)
	require.False(t, stored.Enabled)
	require.NotNil(t, stored.Binding)
	require.Error(t, m.SetOIDCBinding(ctx, sa.OrgID, sa.ID, binding))
	_, err = m.GetOIDCIdentity(ctx, m.oidcConfig.Issuer, "subject", "client")
	require.Error(t, err)
	require.NoError(t, m.DeleteOIDCBinding(ctx, sa.OrgID, sa.ID))
	stored, err = m.GetOIDCBinding(ctx, sa.OrgID, sa.ID)
	require.NoError(t, err)
	require.Nil(t, stored.Binding)
	m.oidcConfig.Enabled = true
	require.NoError(t, m.SetOIDCBinding(ctx, sa.OrgID, sa.ID, binding))
}
