# Community OIDC login with Keycloak

The community server supports an opt-in, instance-wide OIDC login. Enabling it
replaces the login form with **Continue with Keycloak** and rejects password and
other callback login mechanisms on the server, including the `?password=Y`
override. Disabling it restores the existing login flow.

This implementation lives in `pkg/authn/oidclogin` and uses the existing
`go-oidc` and `oauth2` dependencies. It does not import or change the enterprise
OIDC provider. Enterprise authenticated-domain settings are a separate mechanism.

## Prepare users

Complete the normal SigNoz organization setup before enabling OIDC. Record its
organization UUID and ensure the intended users, including the root account,
are active. Alternatively, bootstrap the root account using the existing
`user.root` configuration before enabling OIDC.

Users sign in with the verified Keycloak email that exactly matches their
existing SigNoz email in the configured organization. Their SigNoz roles and
root status remain unchanged. Unknown, pending-invite, and deleted users cannot
sign in. This flow does not create users, activate invitations, or map Keycloak
groups and roles. Provision and activate users before enabling it.

Because verified email links the accounts, restrict who can assign and verify
email addresses in the Keycloak realm. Reassigning an email can transfer access
to the corresponding SigNoz account. Removing access in Keycloak prevents new
logins but does not revoke already-issued SigNoz sessions.

## Configure Keycloak

Create an OpenID Connect client with **Client authentication** enabled and
**Standard flow** enabled. Disable implicit flow and direct access grants. Use
the `openid`, `email`, and `profile` scopes and require verified user email.
Do not require consent or extra scopes for groups; this flow uses the ID token's
standard `email` and `email_verified` claims.

Set the exact Valid redirect URI to:

```text
https://signoz.example.com/api/v2/sessions/oidc/callback
```

Include any deployment path prefix, for example:

```text
https://example.com/observe/api/v2/sessions/oidc/callback
```

The client supports S256 PKCE. The client secret is used only by the backend.

## Configure SigNoz

Add this to the server YAML configuration passed with `--config`:

```yaml
global:
  external_url: https://signoz.example.com
oidc:
  enabled: true
  issuer: https://keycloak.example.com/realms/observability
  client_id: signoz
  org_id: 00000000-0000-0000-0000-000000000001 # Replace with the existing organization UUID.
```

Supply `client_secret` and `cookie_key` through secret-backed environment
variables rather than committing them to configuration. Generate `cookie_key`
with `openssl rand -base64 32`; all replicas must use the same key.

| Environment variable | YAML setting |
| --- | --- |
| `SIGNOZ_GLOBAL_EXTERNAL__URL` | `global.external_url` |
| `SIGNOZ_OIDC_ENABLED` | `oidc.enabled` |
| `SIGNOZ_OIDC_ISSUER` | `oidc.issuer` |
| `SIGNOZ_OIDC_CLIENT__ID` | `oidc.client_id` |
| `SIGNOZ_OIDC_CLIENT__SECRET` | `oidc.client_secret` |
| `SIGNOZ_OIDC_COOKIE__KEY` | `oidc.cookie_key` |
| `SIGNOZ_OIDC_ORG__ID` | `oidc.org_id` |

The double underscores represent underscores in a setting name. Restart the
server after changing these settings. Build and deploy the matching frontend
alongside the backend. HTTPS is required for the public URL, issuer, and
discovered authorization, token, and signing-key endpoints; loopback HTTP URLs
are permitted for local development. Keep the browser and server on the same
public origin so the callback completion POST passes origin validation.

## Session behavior and verification

The authorization request uses random state, nonce, and S256 PKCE. A five-minute
encrypted HttpOnly cookie binds the callback to the browser. The backend verifies
the token signature, issuer, audience, authorized party, nonce, subject, expiry,
and verified email. It then sets a one-minute encrypted HttpOnly identity cookie
and redirects to `/login?oidcComplete=true`, with no tokens in the URL. A
same-origin POST exchanges that cookie for normal SigNoz session tokens and clears
it. The encrypted identity cookie is a short-lived bearer credential; clearing
it does not invalidate a separately captured copy before its expiry.

Test in a private window: sign in as an existing active user, confirm dashboard
access and the existing role, then verify password login returns HTTP 403 and
an unknown or unverified Keycloak user cannot sign in. If Keycloak is unavailable,
the flow fails without offering password login. Logout revokes the SigNoz session;
it does not terminate the Keycloak session, so the next login can reuse Keycloak
SSO. Previously issued SigNoz sessions continue under the normal token policy.

For recovery, set `oidc.enabled: false` and restart the server. No passwords,
users, roles, or enterprise licensing records are changed by this configuration.

Protocol references: [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html),
[go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc), and
[OAuth2 PKCE helpers](https://pkg.go.dev/golang.org/x/oauth2).
