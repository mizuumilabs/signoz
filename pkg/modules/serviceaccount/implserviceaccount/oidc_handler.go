package implserviceaccount

import (
	"net/http"

	"github.com/SigNoz/signoz/pkg/http/binding"
	"github.com/SigNoz/signoz/pkg/http/render"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/serviceaccounttypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/gorilla/mux"
)

func oidcServiceAccountIDs(r *http.Request) (valuer.UUID, valuer.UUID, error) {
	claims, err := authtypes.ClaimsFromContext(r.Context())
	if err != nil {
		return valuer.UUID{}, valuer.UUID{}, err
	}
	orgID, err := valuer.NewUUID(claims.OrgID)
	if err != nil {
		return valuer.UUID{}, valuer.UUID{}, err
	}
	id, err := valuer.NewUUID(mux.Vars(r)["id"])
	return orgID, id, err
}

func (h *handler) GetOIDCBinding(w http.ResponseWriter, r *http.Request) {
	orgID, id, err := oidcServiceAccountIDs(r)
	if err != nil {
		render.Error(w, err)
		return
	}
	result, err := h.module.GetOIDCBinding(r.Context(), orgID, id)
	if err != nil {
		render.Error(w, err)
		return
	}
	render.Success(w, http.StatusOK, result)
}

func (h *handler) SetOIDCBinding(w http.ResponseWriter, r *http.Request) {
	orgID, id, err := oidcServiceAccountIDs(r)
	if err != nil {
		render.Error(w, err)
		return
	}
	body := new(serviceaccounttypes.PostableOIDCBinding)
	if err := binding.JSON.BindBody(r.Body, body); err != nil {
		render.Error(w, err)
		return
	}
	if err := h.module.SetOIDCBinding(r.Context(), orgID, id, body); err != nil {
		render.Error(w, err)
		return
	}
	render.Success(w, http.StatusNoContent, nil)
}

func (h *handler) DeleteOIDCBinding(w http.ResponseWriter, r *http.Request) {
	orgID, id, err := oidcServiceAccountIDs(r)
	if err != nil {
		render.Error(w, err)
		return
	}
	if err := h.module.DeleteOIDCBinding(r.Context(), orgID, id); err != nil {
		render.Error(w, err)
		return
	}
	render.Success(w, http.StatusNoContent, nil)
}
