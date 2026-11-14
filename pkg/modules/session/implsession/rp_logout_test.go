package implsession

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/SigNoz/signoz/pkg/authn/oidclogin"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/modules/session"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/stretchr/testify/require"
)

type logoutSessionModule struct {
	session.Module
	config  oidclogin.Config
	deleted string
}

func (m *logoutSessionModule) OIDCConfig() oidclogin.Config { return m.config }
func (m *logoutSessionModule) DeleteSession(_ context.Context, token string) error {
	m.deleted = token
	return nil
}

func TestDeleteSessionWithProviderLogout(t *testing.T) {
	for _, name := range []string{"manual", "automatic", "disabled", "unavailable", "missing origin"} {
		t.Run(name, func(t *testing.T) {
			var issuer string
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "unavailable" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "end_session_endpoint": issuer + "/logout"})
			}))
			defer provider.Close()
			issuer = provider.URL
			module := &logoutSessionModule{config: oidclogin.Config{Enabled: name != "disabled", Issuer: issuer, ClientID: "signoz"}}
			external, err := url.Parse("https://signoz.example.com/observe")
			require.NoError(t, err)
			handler := NewHandler(module, global.Config{ExternalURL: external})
			route := "/api/v2/sessions?logout_provider=true"
			if name == "automatic" {
				route = "/api/v2/sessions"
			}
			r := httptest.NewRequest(http.MethodDelete, route, nil)
			if name != "missing origin" {
				r.Header.Set("Origin", "https://signoz.example.com")
			}
			r = r.WithContext(authtypes.NewContextWithAccessToken(context.Background(), "local-session"))
			w := httptest.NewRecorder()
			handler.DeleteSession(w, r)
			require.Equal(t, "local-session", module.deleted)
			switch name {
			case "manual":
				require.Equal(t, http.StatusOK, w.Code)
				var body struct {
					Data oidclogin.LogoutResponse `json:"data"`
				}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				require.Contains(t, body.Data.LogoutURL, issuer+"/logout?")
				require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			case "automatic", "disabled":
				require.Equal(t, http.StatusNoContent, w.Code)
			case "unavailable":
				require.Equal(t, http.StatusInternalServerError, w.Code)
			case "missing origin":
				require.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}
