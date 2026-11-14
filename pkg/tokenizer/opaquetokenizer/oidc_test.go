package opaquetokenizer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/cache"
	"github.com/SigNoz/signoz/pkg/cache/cachetest"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory/factorytest"
	"github.com/SigNoz/signoz/pkg/sqlmigration"
	"github.com/SigNoz/signoz/pkg/sqlschema"
	"github.com/SigNoz/signoz/pkg/sqlschema/sqlitesqlschema"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	"github.com/SigNoz/signoz/pkg/sqlstore/sqlitesqlstore"
	"github.com/SigNoz/signoz/pkg/tokenizer"
	"github.com/SigNoz/signoz/pkg/tokenizer/tokenizerstore/sqltokenizerstore"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func openLogoutStore(t *testing.T, path string) sqlstore.SQLStore {
	t.Helper()
	s, err := sqlitesqlstore.New(context.Background(), factorytest.NewSettings(), sqlstore.Config{Provider: "sqlite", Connection: sqlstore.ConnectionConfig{MaxOpenConns: 1}, Sqlite: sqlstore.SqliteConfig{Path: path, Mode: "wal", BusyTimeout: time.Second, TransactionMode: "deferred"}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.SQLDB().Close()) })
	return s
}

func logoutTokenizer(t *testing.T, s sqlstore.SQLStore) tokenizer.Tokenizer {
	t.Helper()
	c, err := cachetest.New(cache.Config{Memory: cache.Memory{NumCounters: 1000, MaxCost: 1 << 20}})
	require.NoError(t, err)
	tokens, err := New(context.Background(), factorytest.NewSettings(), tokenizer.Config{Provider: "opaque",
		Opaque:   tokenizer.OpaqueConfig{Token: tokenizer.TokenConfig{MaxPerUser: 100}},
		Rotation: tokenizer.RotationConfig{Interval: 30 * time.Minute, Duration: time.Minute},
		Lifetime: tokenizer.LifetimeConfig{Idle: 7 * 24 * time.Hour, Max: 30 * 24 * time.Hour}}, c, sqltokenizerstore.NewStore(s), nil)
	require.NoError(t, err)
	return tokens
}

func TestOIDCLogoutRevokesCachedAndRotatedSessionsAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sessions.db")
	s := openLogoutStore(t, path)
	_, err := s.BunDB().NewCreateTable().Model((*authtypes.Token)(nil)).Exec(ctx)
	require.NoError(t, err)
	schema, err := sqlitesqlschema.New(ctx, factorytest.NewSettings(), sqlschema.Config{}, s)
	require.NoError(t, err)
	migration, err := sqlmigration.NewAddOIDCSessionRevocationFactory(schema).New(ctx, factorytest.NewSettings(), sqlmigration.Config{})
	require.NoError(t, err)
	require.NoError(t, migration.Up(ctx, s.BunDB()))
	first, second := logoutTokenizer(t, s), logoutTokenizer(t, openLogoutStore(t, path))
	identity := authtypes.NewPrincipalUserIdentity(valuer.GenerateUUID(), valuer.GenerateUUID(), valuer.MustNewEmail("alice@example.com"), authtypes.IdentNProviderTokenizer)
	login := authtypes.OIDCSession{Issuer: "https://keycloak.example.com/realms/test", ClientID: "signoz", OrgID: identity.OrgID.String(), Subject: "alice", SID: "browser-one", IssuedAt: time.Now().Add(-time.Minute).Unix()}
	create := func(provider tokenizer.Tokenizer, session authtypes.OIDCSession) *authtypes.Token {
		token, err := provider.CreateToken(ctx, identity, session.Meta())
		require.NoError(t, err)
		_, err = provider.GetIdentity(ctx, token.AccessToken)
		require.NoError(t, err)
		return token
	}
	one := create(first, login)
	two := create(second, login)
	rotated, err := first.RotateToken(ctx, one.AccessToken, one.RefreshToken)
	require.NoError(t, err)
	otherBrowser := login
	otherBrowser.SID = "browser-two"
	other := create(first, otherBrowser)
	password, err := first.CreateToken(ctx, identity, nil)
	require.NoError(t, err)
	otherSubject := login
	otherSubject.Subject, otherSubject.SID = "bob", "bob-browser"
	bob := create(first, otherSubject)
	logout := login
	logout.IssuedAt = time.Now().Unix()
	require.NoError(t, second.RevokeOIDCSessions(ctx, logout))
	for _, pair := range []struct {
		provider tokenizer.Tokenizer
		token    *authtypes.Token
	}{{first, rotated}, {second, two}} {
		_, err := pair.provider.GetIdentity(ctx, pair.token.AccessToken)
		require.True(t, errors.Ast(err, errors.TypeUnauthenticated), "%v", err)
		_, err = pair.provider.RotateToken(ctx, pair.token.AccessToken, pair.token.RefreshToken)
		require.True(t, errors.Ast(err, errors.TypeUnauthenticated), "%v", err)
	}
	_, err = first.RotateToken(ctx, one.AccessToken, one.RefreshToken)
	require.Error(t, err, "rotation grace must not bypass logout")
	_, err = first.CreateToken(ctx, identity, login.Meta())
	require.Error(t, err, "pending completion must not recreate a logged-out session")
	_, err = first.GetIdentity(ctx, other.AccessToken)
	require.NoError(t, err, "sid logout must preserve other browsers")
	logout.SID = ""
	require.NoError(t, second.RevokeOIDCSessions(ctx, logout))
	_, err = first.GetIdentity(ctx, other.AccessToken)
	require.Error(t, err, "subject logout must revoke every browser")
	for _, token := range []*authtypes.Token{password, bob} {
		_, err = first.GetIdentity(ctx, token.AccessToken)
		require.NoError(t, err, "unrelated sessions must survive")
	}
	fresh := login
	fresh.SID, fresh.IssuedAt = "new-browser", logout.IssuedAt+1
	freshToken := create(first, fresh)
	require.NoError(t, second.RevokeOIDCSessions(ctx, logout), "retry is idempotent")
	logout.IssuedAt -= 60
	require.NoError(t, second.RevokeOIDCSessions(ctx, logout), "out-of-order logout must not lower cutoff")
	_, err = first.GetIdentity(ctx, freshToken.AccessToken)
	require.NoError(t, err, "replayed old logout must preserve fresh login")
	_, err = first.GetIdentity(ctx, other.AccessToken)
	require.Error(t, err)
	restarted := sqltokenizerstore.NewStore(openLogoutStore(t, path))
	require.Error(t, restarted.CheckOIDCSession(ctx, login.Meta()), "revocation must survive restart")
	for _, change := range []func(*authtypes.OIDCSession){
		func(s *authtypes.OIDCSession) { s.Issuer += "/another" },
		func(s *authtypes.OIDCSession) { s.ClientID = "another" },
		func(s *authtypes.OIDCSession) { s.OrgID = valuer.GenerateUUID().String() },
	} {
		unrelated := login
		change(&unrelated)
		require.NoError(t, restarted.CheckOIDCSession(ctx, unrelated.Meta()))
	}
	require.Error(t, restarted.CheckOIDCSession(ctx, map[string]string{"authn": "oidc"}), "legacy sessions must reauthenticate")
	_, err = s.BunDB().ExecContext(ctx, "DROP TABLE oidc_session_revocation")
	require.NoError(t, err)
	_, err = first.GetIdentity(ctx, freshToken.AccessToken)
	require.Error(t, err, "storage failure must fail closed even with cached identity")
}
