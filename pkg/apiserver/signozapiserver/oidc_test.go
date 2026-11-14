package signozapiserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SigNoz/signoz/pkg/authn/oidclogin"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/http/middleware"
	"github.com/SigNoz/signoz/pkg/modules/session"
	"github.com/SigNoz/signoz/pkg/modules/session/implsession"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

type oidcRouteModule struct{ session.Module }

func (*oidcRouteModule) OIDCConfig() oidclogin.Config { return oidclogin.Config{} }
func (*oidcRouteModule) CreateOIDCSession(context.Context, oidclogin.Identity) (*authtypes.GettableToken, error) {
	panic("disabled OIDC must not create a session")
}

func TestOIDCRouteRegistration(t *testing.T) {
	p := &provider{
		authzMiddleware: middleware.NewAuthZ(slog.New(slog.DiscardHandler), nil, nil),
		sessionHandler:  implsession.NewHandler(&oidcRouteModule{}, global.Config{}),
	}
	router := mux.NewRouter()
	require.NoError(t, p.addOIDCRoutes(router))
	for _, tc := range []struct {
		path   string
		method string
		status int
	}{
		{oidclogin.Route, http.MethodGet, http.StatusOK},
		{oidclogin.Route + "/login", http.MethodGet, http.StatusNotFound},
		{oidclogin.Route + "/callback", http.MethodGet, http.StatusNotFound},
		{oidclogin.Route + "/session", http.MethodPost, http.StatusNotFound},
		{oidclogin.Route + "/session", http.MethodGet, http.StatusMethodNotAllowed},
		{oidclogin.Route + "/backchannel-logout", http.MethodPost, http.StatusNotFound},
		{oidclogin.Route + "/backchannel-logout", http.MethodGet, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			require.Equal(t, tc.status, w.Code)
			if tc.status == http.StatusOK {
				var body struct {
					Data oidclogin.PublicConfig `json:"data"`
				}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				require.False(t, body.Data.Enabled)
				require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			}
		})
	}
}
