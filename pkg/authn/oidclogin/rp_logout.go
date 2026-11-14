package oidclogin

import (
	"context"
	"net/http"
	"net/url"
	"path"

	"github.com/SigNoz/signoz/pkg/errors"
)

const logoutCookie = "signoz_oidc_logout"

type LogoutResponse struct {
	LogoutURL string `json:"logoutURL"`
}

func (h *Handler) LogoutURL(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, error) {
	if !h.config.Enabled {
		return "", nil
	}
	if r.Header.Get("Origin") != h.external.Scheme+"://"+h.external.Host {
		return "", errors.NewForbiddenf(errors.CodeForbidden, "OIDC logout requires a same-origin request")
	}
	defer h.clearCookie(w, logoutCookie)
	h.clearCookie(w, transactionCookie)
	h.clearCookie(w, identityCookie)
	provider, _, err := h.provider(ctx)
	if err != nil {
		return "", errors.NewInternalf(errors.CodeInternal, "OIDC logout provider is unavailable")
	}
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil || metadata.EndSessionEndpoint == "" || validateURL(metadata.EndSessionEndpoint) != nil {
		return "", errors.NewInternalf(errors.CodeInternal, "OIDC provider has no secure logout endpoint")
	}
	endpoint, err := url.Parse(metadata.EndSessionEndpoint)
	if err != nil {
		return "", err
	}
	redirect := *h.external
	redirect.Path = path.Join(redirect.Path, "/login")
	redirect.RawQuery, redirect.Fragment = "", ""
	query := endpoint.Query()
	query.Set("client_id", h.config.ClientID)
	query.Set("post_logout_redirect_uri", redirect.String())
	if hint, err := h.readCookie(r, logoutCookie); err == nil && hint.IDToken != "" {
		query.Set("id_token_hint", hint.IDToken)
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}
