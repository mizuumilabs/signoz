package implserviceaccount

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/serviceaccounttypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func oidcBindingRequest(method, body string, orgID, id valuer.UUID) *http.Request {
	r := httptest.NewRequest(method, "/api/v1/service_accounts/"+id.String()+"/oidc", strings.NewReader(body))
	r = mux.SetURLVars(r, map[string]string{"id": id.String()})
	r = r.WithContext(authtypes.NewContextWithClaims(r.Context(), authtypes.Claims{OrgID: orgID.String(), Principal: authtypes.PrincipalUser, UserID: valuer.GenerateUUID().String()}))
	return r
}

func TestOIDCBindingHandlers(t *testing.T) {
	m, s, _ := newOIDCTestModule(t)
	sa := addOIDCTestAccount(t, m, s, "worker", valuer.GenerateUUID())
	h := NewHandler(m, nil)
	w := httptest.NewRecorder()
	h.GetOIDCBinding(w, oidcBindingRequest(http.MethodGet, "", sa.OrgID, sa.ID))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"binding":null`)
	w = httptest.NewRecorder()
	h.SetOIDCBinding(w, oidcBindingRequest(http.MethodPut, `{"clientId":"client","subject":"subject"}`, sa.OrgID, sa.ID))
	require.Equal(t, http.StatusNoContent, w.Code)
	w = httptest.NewRecorder()
	h.GetOIDCBinding(w, oidcBindingRequest(http.MethodGet, "", sa.OrgID, sa.ID))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"clientId":"client"`)
	require.Contains(t, w.Body.String(), `"subject":"subject"`)
	require.Contains(t, w.Body.String(), m.oidcConfig.Issuer)
	m.oidcConfig.Enabled = false
	w = httptest.NewRecorder()
	h.DeleteOIDCBinding(w, oidcBindingRequest(http.MethodDelete, "", sa.OrgID, sa.ID))
	require.Equal(t, http.StatusNoContent, w.Code)
	stored, err := m.GetOIDCBinding(context.Background(), sa.OrgID, sa.ID)
	require.NoError(t, err)
	require.Nil(t, stored.Binding)
}

func TestOIDCBindingHandlerInputAndIsolation(t *testing.T) {
	m, s, _ := newOIDCTestModule(t)
	sa := addOIDCTestAccount(t, m, s, "worker", valuer.GenerateUUID())
	h := NewHandler(m, nil)
	for _, body := range []string{`{`, `null`, `{}`, `{"clientId":"client","subject":"sub\nject"}`, `{"clientId":"client"}`} {
		w := httptest.NewRecorder()
		h.SetOIDCBinding(w, oidcBindingRequest(http.MethodPut, body, sa.OrgID, sa.ID))
		require.Equal(t, http.StatusBadRequest, w.Code, body)
	}
	require.NoError(t, m.SetOIDCBinding(context.Background(), sa.OrgID, sa.ID, &serviceaccounttypes.PostableOIDCBinding{ClientID: "client", Subject: "subject"}))
	otherOrg := valuer.GenerateUUID()
	for _, method := range []http.HandlerFunc{h.GetOIDCBinding, h.DeleteOIDCBinding} {
		w := httptest.NewRecorder()
		method(w, oidcBindingRequest(http.MethodGet, "", otherOrg, sa.ID))
		require.Equal(t, http.StatusNotFound, w.Code)
	}
	w := httptest.NewRecorder()
	h.SetOIDCBinding(w, oidcBindingRequest(http.MethodPut, `{"clientId":"other","subject":"other"}`, otherOrg, sa.ID))
	require.Equal(t, http.StatusNotFound, w.Code)
	w = httptest.NewRecorder()
	r := oidcBindingRequest(http.MethodGet, "", sa.OrgID, sa.ID)
	r = mux.SetURLVars(r, map[string]string{"id": "invalid"})
	h.GetOIDCBinding(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	w = httptest.NewRecorder()
	h.GetOIDCBinding(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, w.Code)
}
