package oidclogin

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthorizedPartyValidation(t *testing.T) {
	for _, test := range []struct {
		name     string
		audience any
		party    string
		valid    bool
	}{
		{"single audience no party", "signoz", "", true},
		{"single audience matching party", "signoz", "signoz", true},
		{"single audience wrong party", "signoz", "other-client", false},
		{"multiple audiences missing party", []string{"signoz", "other-app"}, "", false},
		{"multiple audiences matching party", []string{"signoz", "other-app"}, "signoz", true},
		{"multiple audiences wrong party", []string{"signoz", "other-app"}, "other-app", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newTestProvider(t)
			h := testHandler(t, p)
			cookie, authorization := startLogin(t, h, p)
			p.claims["aud"] = test.audience
			if test.party != "" {
				p.claims["azp"] = test.party
			}
			w := callbackLogin(h, cookie, url.Values{"state": {authorization.Get("state")}, "code": {"test-code"}})
			if test.valid {
				require.Equal(t, "/observe/login?oidcComplete=true", w.Header().Get("Location"))
				responseCookie(t, w, identityCookie)
			} else {
				require.Equal(t, "/observe/login?oidcError=authentication_failed", w.Header().Get("Location"))
			}
		})
	}
}
