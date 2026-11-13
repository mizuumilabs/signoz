package signozapiserver

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SigNoz/signoz/pkg/authz"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/http/middleware"
	"github.com/SigNoz/signoz/pkg/modules/serviceaccount"
	"github.com/SigNoz/signoz/pkg/modules/serviceaccount/implserviceaccount"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/coretypes"
	"github.com/SigNoz/signoz/pkg/types/serviceaccounttypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

type oidcBindingRouteModule struct {
	serviceaccount.Module
	orgID, id                       valuer.UUID
	getCalls, setCalls, deleteCalls int
	binding                         *serviceaccounttypes.OIDCBinding
}

func (m *oidcBindingRouteModule) GetOIDCBinding(_ context.Context, orgID, id valuer.UUID) (*serviceaccounttypes.GettableOIDCBinding, error) {
	m.getCalls++
	if orgID != m.orgID || id != m.id {
		return nil, errors.New(errors.TypeNotFound, errors.CodeNotFound, "service account not found")
	}
	return &serviceaccounttypes.GettableOIDCBinding{Enabled: true, Issuer: "https://keycloak.example.com/realm", Audience: "signoz-api", Binding: m.binding}, nil
}

func (m *oidcBindingRouteModule) SetOIDCBinding(_ context.Context, orgID, id valuer.UUID, binding *serviceaccounttypes.PostableOIDCBinding) error {
	m.setCalls++
	if orgID != m.orgID || id != m.id {
		return errors.New(errors.TypeNotFound, errors.CodeNotFound, "service account not found")
	}
	m.binding = &serviceaccounttypes.OIDCBinding{Issuer: "https://keycloak.example.com/realm", ClientID: binding.ClientID, Subject: binding.Subject}
	return nil
}

func (m *oidcBindingRouteModule) DeleteOIDCBinding(_ context.Context, orgID, id valuer.UUID) error {
	m.deleteCalls++
	if orgID != m.orgID || id != m.id {
		return errors.New(errors.TypeNotFound, errors.CodeNotFound, "service account not found")
	}
	m.binding = nil
	return nil
}

type oidcBindingRouteAuthZ struct {
	authz.AuthZ
	check func(authtypes.Claims, valuer.UUID, authtypes.Relation, coretypes.Resource, []coretypes.Selector, []coretypes.Selector) error
	calls int
}

func (a *oidcBindingRouteAuthZ) CheckWithTupleCreation(_ context.Context, claims authtypes.Claims, orgID valuer.UUID, relation authtypes.Relation, resource coretypes.Resource, selectors, roles []coretypes.Selector) error {
	a.calls++
	return a.check(claims, orgID, relation, resource, selectors, roles)
}

func TestServiceAccountOIDCRouteAuthorization(t *testing.T) {
	for _, route := range []struct {
		method        string
		verb          coretypes.Verb
		allowedStatus int
	}{
		{http.MethodGet, coretypes.VerbRead, http.StatusOK},
		{http.MethodPut, coretypes.VerbUpdate, http.StatusNoContent},
		{http.MethodDelete, coretypes.VerbUpdate, http.StatusNoContent},
	} {
		for _, access := range []string{"anonymous", "denied", "allowed"} {
			t.Run(route.method+"/"+access, func(t *testing.T) {
				orgID, id := valuer.GenerateUUID(), valuer.GenerateUUID()
				claims := authtypes.Claims{OrgID: orgID.String(), UserID: valuer.GenerateUUID().String(), Principal: authtypes.PrincipalUser}
				original := &serviceaccounttypes.OIDCBinding{Issuer: "https://keycloak.example.com/realm", ClientID: "original-client", Subject: "original-subject"}
				module := &oidcBindingRouteModule{orgID: orgID, id: id, binding: original}
				authorizer := &oidcBindingRouteAuthZ{check: func(actualClaims authtypes.Claims, actualOrg valuer.UUID, relation authtypes.Relation, resource coretypes.Resource, selectors, roles []coretypes.Selector) error {
					require.Equal(t, claims, actualClaims)
					require.Equal(t, orgID, actualOrg)
					require.Equal(t, route.verb, relation.Verb)
					require.Equal(t, coretypes.ResourceServiceAccount.Type(), resource.Type())
					require.Equal(t, coretypes.ResourceServiceAccount.Kind(), resource.Kind())
					require.Equal(t, []coretypes.Selector{coretypes.ResourceServiceAccount.Type().MustSelector(id.String()), coretypes.ResourceServiceAccount.Type().MustSelector(coretypes.WildCardSelectorString)}, selectors)
					require.Equal(t, []coretypes.Selector{coretypes.TypeRole.MustSelector(authtypes.SigNozAdminRoleName)}, roles)
					if access == "denied" {
						return errors.New(errors.TypeForbidden, authtypes.ErrCodeAuthZForbidden, "permission denied")
					}
					return nil
				}}
				logger := slog.New(slog.DiscardHandler)
				p := &provider{authzMiddleware: middleware.NewAuthZ(logger, nil, authorizer), serviceAccountHandler: implserviceaccount.NewHandler(module, nil)}
				router := mux.NewRouter()
				router.Use(middleware.NewResource(logger).Wrap)
				require.NoError(t, p.addServiceAccountOIDCRoutes(router))
				r := httptest.NewRequest(route.method, "/api/v1/service_accounts/"+id.String()+"/oidc", strings.NewReader(`{"clientId":"new-client","subject":"new-subject"}`))
				if access != "anonymous" {
					r = r.WithContext(authtypes.NewContextWithClaims(r.Context(), claims))
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, r)
				switch access {
				case "anonymous":
					require.Equal(t, http.StatusUnauthorized, w.Code)
					require.Zero(t, authorizer.calls)
				case "denied":
					require.Equal(t, http.StatusForbidden, w.Code)
					require.Equal(t, 1, authorizer.calls)
				case "allowed":
					require.Equal(t, route.allowedStatus, w.Code, w.Body.String())
					require.Equal(t, 1, authorizer.calls)
				}
				if access != "allowed" {
					require.Zero(t, module.getCalls+module.setCalls+module.deleteCalls)
					require.Same(t, original, module.binding, "denial must leave the binding untouched")
					return
				}
				switch route.method {
				case http.MethodGet:
					require.Equal(t, 1, module.getCalls)
					require.Same(t, original, module.binding)
				case http.MethodPut:
					require.Equal(t, 1, module.setCalls)
					require.Equal(t, "new-client", module.binding.ClientID)
					require.Equal(t, "new-subject", module.binding.Subject)
				case http.MethodDelete:
					require.Equal(t, 1, module.deleteCalls)
					require.Nil(t, module.binding)
				}
			})
		}
	}
}
