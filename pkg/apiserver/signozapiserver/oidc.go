package signozapiserver

import (
	"net/http"

	"github.com/SigNoz/signoz/pkg/authn/oidclogin"
	"github.com/SigNoz/signoz/pkg/http/handler"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/gorilla/mux"
)

func (provider *provider) addOIDCRoutes(router *mux.Router) error {
	routes := []struct {
		path     string
		method   string
		id       string
		summary  string
		status   int
		response any
		handle   http.HandlerFunc
	}{
		{oidclogin.Route, http.MethodGet, "GetOIDCLoginConfig", "Get instance OIDC login configuration", http.StatusOK, new(oidclogin.PublicConfig), provider.sessionHandler.GetOIDCConfig},
		{oidclogin.Route + "/login", http.MethodGet, "StartOIDCLogin", "Start OIDC authorization code login with PKCE", http.StatusSeeOther, nil, provider.sessionHandler.StartOIDCLogin},
		{oidclogin.Route + "/callback", http.MethodGet, "CompleteOIDCLogin", "Verify OIDC callback and redirect to login", http.StatusSeeOther, nil, provider.sessionHandler.CompleteOIDCLogin},
		{oidclogin.Route + "/session", http.MethodPost, "CreateOIDCSession", "Exchange a browser-bound OIDC login cookie for a session", http.StatusOK, new(authtypes.GettableToken), provider.sessionHandler.CreateOIDCSession},
	}
	for _, route := range routes {
		contentType := ""
		if route.response != nil {
			contentType = "application/json"
		}
		if err := router.Handle(route.path, handler.New(provider.authzMiddleware.OpenAccess(route.handle), handler.OpenAPIDef{
			ID: route.id, Tags: []string{"sessions"}, Summary: route.summary, Description: route.summary,
			Response: route.response, ResponseContentType: contentType, SuccessStatusCode: route.status,
			ErrorStatusCodes: []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
			SecuritySchemes:  []handler.OpenAPISecurityScheme{},
		})).Methods(route.method).GetError(); err != nil {
			return err
		}
	}
	return nil
}
