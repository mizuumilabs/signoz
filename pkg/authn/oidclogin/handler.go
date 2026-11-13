package oidclogin

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/global"
	"github.com/SigNoz/signoz/pkg/http/render"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const transactionCookie = "signoz_oidc_transaction"
const identityCookie = "signoz_oidc_identity"
const Route = "/api/v2/sessions/oidc"

type PublicConfig struct {
	Enabled  bool   `json:"enabled"`
	LoginURL string `json:"loginURL,omitempty"`
}

type Handler struct {
	config        Config
	external      *url.URL
	createSession func(context.Context, valuer.Email) (*authtypes.GettableToken, error)
}

func New(config Config, globalConfig global.Config, createSession func(context.Context, valuer.Email) (*authtypes.GettableToken, error)) *Handler {
	return &Handler{config: config, external: globalConfig.ExternalURL, createSession: createSession}
}

func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	config := PublicConfig{Enabled: h.config.Enabled}
	if config.Enabled {
		config.LoginURL = path.Join(h.external.Path, Route, "login")
	}
	render.Success(w, http.StatusOK, config)
}

func (h *Handler) cookiePath() string { return path.Join(h.external.Path, Route) }

func (h *Handler) provider(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, h.config.Issuer)
	if err != nil {
		return nil, nil, err
	}
	endpoint := provider.Endpoint()
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, nil, err
	}
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL, metadata.JWKSURL} {
		if err := validateURL(raw); err != nil {
			return nil, nil, err
		}
	}
	callback := *h.external
	callback.Path = path.Join(callback.Path, Route, "callback")
	return provider, &oauth2.Config{ClientID: h.config.ClientID, ClientSecret: h.config.ClientSecret, Endpoint: endpoint, RedirectURL: callback.String(), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}, nil
}

func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.config.Enabled {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	_, config, err := h.provider(ctx)
	if err != nil {
		h.fail(w, r)
		return
	}
	transaction := loginCookie{State: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(), Verifier: oauth2.GenerateVerifier()}
	if err := h.setCookie(w, transactionCookie, transaction, 5*time.Minute, http.SameSiteLaxMode); err != nil {
		h.fail(w, r)
		return
	}
	h.clearCookie(w, identityCookie)
	http.Redirect(w, r, config.AuthCodeURL(transaction.State, oauth2.S256ChallengeOption(transaction.Verifier), oidc.Nonce(transaction.Nonce)), http.StatusSeeOther)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !h.config.Enabled {
		http.NotFound(w, r)
		return
	}
	transaction, err := h.readCookie(r, transactionCookie)
	h.clearCookie(w, transactionCookie)
	h.clearCookie(w, identityCookie)
	query := r.URL.Query()
	if err != nil || transaction.State == "" || transaction.Verifier == "" || transaction.Nonce == "" || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(transaction.State)) != 1 || query.Get("error") != "" || query.Get("code") == "" {
		h.fail(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	provider, config, err := h.provider(ctx)
	if err != nil {
		h.fail(w, r)
		return
	}
	tokens, err := config.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(transaction.Verifier))
	if err != nil {
		h.fail(w, r)
		return
	}
	raw, ok := tokens.Extra("id_token").(string)
	if !ok {
		h.fail(w, r)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: h.config.ClientID}).Verify(ctx, raw)
	if err != nil || idToken.Subject == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(transaction.Nonce)) != 1 {
		h.fail(w, r)
		return
	}
	var claims struct {
		Email           string `json:"email"`
		EmailVerified   bool   `json:"email_verified"`
		AuthorizedParty string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil || !claims.EmailVerified || (claims.AuthorizedParty != "" && claims.AuthorizedParty != h.config.ClientID) || (len(idToken.Audience) > 1 && claims.AuthorizedParty == "") {
		h.fail(w, r)
		return
	}
	if _, err := valuer.NewEmail(claims.Email); err != nil {
		h.fail(w, r)
		return
	}
	if err := h.setCookie(w, identityCookie, loginCookie{Email: claims.Email}, time.Minute, http.SameSiteStrictMode); err != nil {
		h.fail(w, r)
		return
	}
	http.Redirect(w, r, path.Join(h.external.Path, "/login")+"?oidcComplete=true", http.StatusSeeOther)
}

func (h *Handler) Complete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.config.Enabled {
		http.NotFound(w, r)
		return
	}
	origin := h.external.Scheme + "://" + h.external.Host
	if r.Header.Get("Origin") != origin {
		render.Error(w, errors.New(errors.TypeForbidden, errors.CodeForbidden, "OIDC session requires a same-origin request"))
		return
	}
	identity, err := h.readCookie(r, identityCookie)
	h.clearCookie(w, identityCookie)
	if err != nil || identity.Email == "" {
		render.Error(w, errors.New(errors.TypeForbidden, errors.CodeForbidden, "OIDC login expired; sign in again"))
		return
	}
	email, err := valuer.NewEmail(identity.Email)
	if err != nil {
		h.fail(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := h.createSession(ctx, email)
	if err != nil {
		render.Error(w, errors.New(errors.TypeForbidden, errors.CodeForbidden, "OIDC user is not an active member of this organization"))
		return
	}
	render.Success(w, http.StatusOK, token)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, path.Join(h.external.Path, "/login")+"?oidcError=authentication_failed", http.StatusSeeOther)
}
