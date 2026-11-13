package signozapiserver

import (
	"net/http"

	"github.com/SigNoz/signoz/pkg/http/handler"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/coretypes"
	"github.com/SigNoz/signoz/pkg/types/serviceaccounttypes"
	"github.com/gorilla/mux"
)

func (p *provider) addServiceAccountOIDCRoutes(router *mux.Router) error {
	for _, route := range []struct {
		method, id, summary string
		verb                coretypes.Verb
		handle              http.HandlerFunc
		request, response   any
		status              int
	}{
		{http.MethodGet, "GetServiceAccountOIDCBinding", "Get service account OIDC binding", coretypes.VerbRead, p.serviceAccountHandler.GetOIDCBinding, nil, new(serviceaccounttypes.GettableOIDCBinding), http.StatusOK},
		{http.MethodPut, "SetServiceAccountOIDCBinding", "Set service account OIDC binding", coretypes.VerbUpdate, p.serviceAccountHandler.SetOIDCBinding, new(serviceaccounttypes.PostableOIDCBinding), nil, http.StatusNoContent},
		{http.MethodDelete, "DeleteServiceAccountOIDCBinding", "Delete service account OIDC binding", coretypes.VerbUpdate, p.serviceAccountHandler.DeleteOIDCBinding, nil, nil, http.StatusNoContent},
	} {
		if err := router.Handle("/api/v1/service_accounts/{id}/oidc", handler.New(
			p.authzMiddleware.CheckResources(route.handle, authtypes.SigNozAdminRoleName),
			handler.OpenAPIDef{ID: route.id, Tags: []string{"serviceaccount"}, Summary: route.summary, Description: route.summary, Request: route.request, RequestContentType: "application/json", Response: route.response, ResponseContentType: "application/json", SuccessStatusCode: route.status, ErrorStatusCodes: []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict}, SecuritySchemes: newScopedSecuritySchemes([]string{coretypes.ResourceServiceAccount.Scope(route.verb)})},
			handler.WithResourceDefs(handler.BasicResourceDef{Resource: coretypes.ResourceServiceAccount, Verb: route.verb, Category: coretypes.ActionCategoryAccessControl, ID: coretypes.PathParam("id"), Selector: coretypes.IDSelector}),
		)).Methods(route.method).GetError(); err != nil {
			return err
		}
	}
	return nil
}
