package implsession

import (
	"context"
	"net/http"

	"github.com/SigNoz/signoz/pkg/authn/oidclogin"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
)

func (module *module) OIDCConfig() oidclogin.Config { return module.oidcConfig }

func (module *module) CreateOIDCSession(ctx context.Context, oidcIdentity oidclogin.Identity) (*authtypes.GettableToken, error) {
	if !module.oidcConfig.Enabled {
		return nil, errors.New(errors.TypeForbidden, errors.CodeForbidden, "OIDC login is disabled")
	}
	email := oidcIdentity.Email
	user, err := module.userGetter.GetNonDeletedUserByEmailAndOrgID(ctx, email, module.oidcConfig.OrgID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != types.UserStatusActive || user.OrgID != module.oidcConfig.OrgID || user.Email != email {
		return nil, errors.New(errors.TypeForbidden, errors.CodeForbidden, "an active organization membership is required")
	}
	identity := authtypes.NewPrincipalUserIdentity(user.ID, user.OrgID, user.Email, authtypes.IdentNProviderTokenizer)
	token, err := module.tokenizer.CreateToken(ctx, identity, oidcIdentity.Session.Meta())
	if err != nil {
		return nil, err
	}
	return authtypes.NewGettableTokenFromToken(token, module.GetRotationInterval(ctx)), nil
}

func (module *module) RevokeOIDCSessions(ctx context.Context, session authtypes.OIDCSession) error {
	return module.tokenizer.RevokeOIDCSessions(ctx, session)
}

func (handler *handler) BackchannelOIDCLogout(w http.ResponseWriter, r *http.Request) {
	handler.oidc.BackchannelLogout(w, r)
}

func (handler *handler) GetOIDCConfig(w http.ResponseWriter, r *http.Request) {
	handler.oidc.GetConfig(w, r)
}
func (handler *handler) StartOIDCLogin(w http.ResponseWriter, r *http.Request) {
	handler.oidc.Start(w, r)
}
func (handler *handler) CompleteOIDCLogin(w http.ResponseWriter, r *http.Request) {
	handler.oidc.Callback(w, r)
}
func (handler *handler) CreateOIDCSession(w http.ResponseWriter, r *http.Request) {
	handler.oidc.Complete(w, r)
}
