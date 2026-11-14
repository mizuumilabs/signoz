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
to the corresponding SigNoz account. To revoke existing SigNoz sessions from
Keycloak, configure back-channel logout below and terminate the user's Keycloak
sessions. Disabling a Keycloak user alone is not a logout notification.

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

Set **Valid post logout redirect URIs** on this client to the exact login URL:

```text
https://signoz.example.com/login
```

Include any deployment path prefix, for example `https://example.com/observe/login`.
Clicking **Logout** in SigNoz deletes the local session and redirects the browser
to the provider's discovered `end_session_endpoint`, then back to this login URL.
The return URL is fixed by `global.external_url`; callers cannot override it.
New logins retain the verified ID token as an encrypted, Secure, HttpOnly cookie
for up to 30 days, used only as `id_token_hint` during explicit logout. This hint
normally avoids a Keycloak confirmation screen. Existing logins, expired or
missing cookies, and ID tokens too large for a cookie fall back to `client_id`
logout; Keycloak may ask for confirmation before ending its session.

Automatic cleanup after an expired API session stays local. If Keycloak discovery
is unavailable or has no secure logout endpoint, SigNoz still deletes its local
session, but the Keycloak SSO session may remain active. Provider logout can also
log out other applications attached to that Keycloak browser session.

### Back-channel logout

In the login client's **Logout settings**, disable **Front channel logout**, set
**Backchannel logout URL** to:

```text
https://signoz.example.com/api/v2/sessions/oidc/backchannel-logout
```

Include the deployment path prefix if present. Enable **Backchannel logout
session required** so Keycloak includes `sid` in its logout tokens and ID tokens.
Keycloak must be able to POST to this URL without a browser session or proxy
login. Configure the client to use signed tokens, with RS256 (the default) or an
RSA-PSS/ECDSA algorithm; encrypted logout tokens are not supported.

This endpoint is enabled with `oidc.enabled`; no extra SigNoz setting is needed.
It validates the provider signature, issuer, client audience, `iat`, `exp`, `jti`,
logout event, and absence of `nonce`. Logout tokens must be issued within the
last five minutes, with at most one minute of future clock skew. Valid retries
and notifications for an already logged-out session return HTTP 200.

A `sid` notification revokes that Keycloak session. With only `sub`, it revokes
the subject's OIDC sessions whose ID token was issued at or before the logout.
Revocation is scoped to issuer, client, and configured SigNoz organization.
SigNoz checks persisted revocations on every OIDC session request and refresh,
including cached sessions on other replicas sharing the SQL database. Pending
browser login completions are checked too. Revocations survive restarts and
retries cannot revoke a later login with a new `sid` and a later issue time.
The revocation table retains one hashed entry per logged-out session or subject;
it is not automatically pruned.

Community OIDC login requires the default `tokenizer.provider: opaque`; startup
rejects the stateless JWT tokenizer because it cannot revoke sessions. Existing
community OIDC sessions from before this update must sign in again to acquire
the provider session metadata. Built-in service-account keys and Keycloak
client-credentials tokens are separate and are unaffected by browser logout.

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
the flow fails without offering password login. Explicit logout revokes the
SigNoz session and requests Keycloak logout through the browser. Verify that the
next login requires Keycloak authentication. Keycloak-initiated back-channel
logout revokes the corresponding SigNoz
session, but does not push changes into an idle browser tab; the next API request
or refresh fails and the frontend handles it as an expired session.

To verify back-channel logout, sign in from two private browser profiles, end
one session from Keycloak's user **Sessions** tab, and confirm its next SigNoz
request and token refresh are rejected while the other profile still works.
Sign in again and verify a fresh session works. Repeat with the user's sessions
terminated from the Keycloak admin console. Removing a role does not itself send
a logout event; SigNoz roles continue to be managed locally.

For recovery, set `oidc.enabled: false` and restart the server. No passwords,
users, roles, or enterprise licensing records are changed by this configuration.

Protocol references: [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html),
[Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html),
[RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html),
[Keycloak logout settings](https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients),
[go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc), and
[OAuth2 PKCE helpers](https://pkg.go.dev/golang.org/x/oauth2).
