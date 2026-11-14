package implsession

import (
	"context"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/authn/oidclogin"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/modules/user"
	"github.com/SigNoz/signoz/pkg/tokenizer"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

type oidcUserGetter struct {
	user.Getter
	user  *types.User
	err   error
	orgID valuer.UUID
	email valuer.Email
}

func (g *oidcUserGetter) GetNonDeletedUserByEmailAndOrgID(_ context.Context, email valuer.Email, orgID valuer.UUID) (*types.User, error) {
	g.orgID, g.email = orgID, email
	return g.user, g.err
}

type oidcTokenizer struct {
	tokenizer.Tokenizer
	identity *authtypes.Identity
}

func (t *oidcTokenizer) CreateToken(_ context.Context, identity *authtypes.Identity, _ map[string]string) (*authtypes.Token, error) {
	t.identity = identity
	return &authtypes.Token{AccessToken: "application-access", RefreshToken: "application-refresh", CreatedAt: time.Now()}, nil
}

func (t *oidcTokenizer) Config() tokenizer.Config { return tokenizer.Config{} }

func TestOIDCRequiresActiveMembership(t *testing.T) {
	orgID := valuer.GenerateUUID()
	email, err := valuer.NewEmail("operator@example.com")
	require.NoError(t, err)
	for _, tc := range []struct {
		name        string
		status      valuer.String
		root        bool
		missing     bool
		wrongOrg    bool
		wrongEmail  bool
		lookupError bool
		disabled    bool
		allowed     bool
	}{
		{name: "active", status: types.UserStatusActive, allowed: true},
		{name: "root", status: types.UserStatusActive, root: true, allowed: true},
		{name: "pending", status: types.UserStatusPendingInvite},
		{name: "deleted", status: types.UserStatusDeleted},
		{name: "missing", missing: true},
		{name: "wrong organization", status: types.UserStatusActive, wrongOrg: true},
		{name: "wrong email", status: types.UserStatusActive, wrongEmail: true},
		{name: "lookup failure", lookupError: true},
		{name: "disabled", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := &types.User{Identifiable: types.Identifiable{ID: valuer.GenerateUUID()}, Email: email, OrgID: orgID, IsRoot: tc.root, Status: tc.status}
			if tc.wrongOrg {
				account.OrgID = valuer.GenerateUUID()
			}
			if tc.wrongEmail {
				account.Email, _ = valuer.NewEmail("other@example.com")
			}
			getter := &oidcUserGetter{user: account}
			if tc.missing {
				getter.user = nil
			}
			if tc.lookupError {
				getter.err = errors.New(errors.TypeNotFound, errors.CodeNotFound, "missing")
			}
			tokens := &oidcTokenizer{}
			m := &module{oidcConfig: oidclogin.Config{Enabled: !tc.disabled, OrgID: orgID}, userGetter: getter, tokenizer: tokens}
			result, err := m.CreateOIDCSession(context.Background(), oidclogin.Identity{Email: email})
			if !tc.allowed {
				require.Error(t, err)
				require.Nil(t, result)
				require.Nil(t, tokens.identity)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "application-access", result.AccessToken)
			require.Equal(t, account.ID, tokens.identity.UserID)
			require.Equal(t, orgID, getter.orgID)
			require.Equal(t, email, getter.email)
		})
	}
}

func TestOIDCDisablesAlternateLogin(t *testing.T) {
	m := &module{oidcConfig: oidclogin.Config{Enabled: true}}
	email, err := valuer.NewEmail("operator@example.com")
	require.NoError(t, err)
	_, err = m.CreatePasswordAuthNSession(context.Background(), authtypes.AuthNProviderEmailPassword, email, "password", valuer.GenerateUUID())
	require.True(t, errors.Ast(err, errors.TypeForbidden))
	_, err = m.CreateCallbackAuthNSession(context.Background(), authtypes.AuthNProviderGoogle, nil)
	require.True(t, errors.Ast(err, errors.TypeForbidden))
	_, err = m.GetSessionContext(context.Background(), valuer.Email{}, nil)
	require.True(t, errors.Ast(err, errors.TypeForbidden))
}
