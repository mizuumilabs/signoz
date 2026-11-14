package oidclogin

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"time"

	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/coreos/go-oidc/v3/oidc"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

func (h *Handler) BackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.config.Enabled {
		http.NotFound(w, r)
		return
	}
	invalid := func() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || err != nil || mediaType != "application/x-www-form-urlencoded" {
		invalid()
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || len(r.PostForm["logout_token"]) != 1 || r.PostForm.Get("logout_token") == "" {
		invalid()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	provider, _, err := h.provider(ctx)
	if err != nil {
		invalid()
		return
	}
	token, err := provider.Verifier(&oidc.Config{ClientID: h.config.ClientID,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512},
	}).Verify(ctx, r.PostForm.Get("logout_token"))
	if err != nil {
		invalid()
		return
	}
	var claims struct {
		SID       string                     `json:"sid"`
		JTI       string                     `json:"jti"`
		Events    map[string]json.RawMessage `json:"events"`
		NotBefore int64                      `json:"nbf"`
	}
	var raw map[string]json.RawMessage
	if token.Claims(&claims) != nil || token.Claims(&raw) != nil {
		invalid()
		return
	}
	_, hasNonce := raw["nonce"]
	var event map[string]json.RawMessage
	eventRaw, hasEvent := claims.Events[logoutEvent]
	now := time.Now()
	if hasNonce || !hasEvent || json.Unmarshal(eventRaw, &event) != nil || event == nil || claims.JTI == "" ||
		(token.Subject == "" && claims.SID == "") || token.IssuedAt.IsZero() ||
		token.IssuedAt.Before(now.Add(-5*time.Minute)) || token.IssuedAt.After(now.Add(time.Minute)) ||
		claims.NotBefore > now.Unix() || !token.Expiry.After(now) {
		invalid()
		return
	}
	if h.revokeSessions == nil || h.revokeSessions(ctx, authtypes.OIDCSession{
		Issuer: h.config.Issuer, ClientID: h.config.ClientID, OrgID: h.config.OrgID.String(),
		Subject: token.Subject, SID: claims.SID, IssuedAt: token.IssuedAt.Unix(),
	}) != nil {
		invalid()
		return
	}
	w.WriteHeader(http.StatusOK)
}
