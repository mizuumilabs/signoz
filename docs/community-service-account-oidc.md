# Keycloak authentication for service accounts

SigNoz community can accept short-lived Keycloak access tokens for existing
SigNoz service accounts. Keycloak handles client authentication; SigNoz roles
continue to authorize API operations. Client secrets remain with your application
and Keycloak. SigNoz does not create Keycloak clients or store their secrets.

## Enable verification

Configure the community server and restart it:

```yaml
identn:
  oidc:
    enabled: true
    issuer: https://keycloak.example.com/realms/observability
    audience: signoz-api
```

The equivalent environment variables are `SIGNOZ_IDENTN_OIDC_ENABLED`,
`SIGNOZ_IDENTN_OIDC_ISSUER`, and `SIGNOZ_IDENTN_OIDC_AUDIENCE`. These settings are
independent of the browser login settings under `oidc`. Human sessions and
existing `SIGNOZ-API-KEY` credentials continue to work.

Deploy the matching backend and frontend. The backend runs migration 148 to add
the binding table; existing service accounts, roles, and API keys are preserved.
The API audience should be distinct from the human-login client ID. HTTPS is
required for the issuer and signing-key endpoint; loopback HTTP is supported for
development. SigNoz discovers the configured issuer and caches its signing keys.

## Prepare an existing Keycloak client

1. Enable **Client authentication** and **Service accounts roles** on a dedicated
   machine client. Use the client credentials grant. Disable browser Standard
   flow, implicit flow, and direct access grants for this machine client.
2. Add an **Audience** mapper to the client's dedicated scope. Set **Included
   Custom Audience** to the configured SigNoz audience, for example `signoz-api`,
   and include it in the access token. No SigNoz roles need to be granted in
   Keycloak; authorization comes from the linked SigNoz service account.
3. Record the client ID and the **service-account user's subject** (`sub`) from a
   token obtained directly from that client's credentials. The subject is the
   service-account user's ID, not the client UUID, client ID, or username.

These settings follow Keycloak's [service-account and audience documentation](https://www.keycloak.org/docs/latest/server_admin/index.html#_service_accounts).

## Link the service account in SigNoz

Open **Settings → Service Accounts**, select an account, and use its Overview
panel's **Keycloak authentication** section. Enter the Keycloak **Client ID**
and **Service-account subject**, then save the binding. You must have permission
to read and update that SigNoz service account. Continue assigning its SigNoz
roles through the existing role controls.

Each external subject and client can be linked to only one SigNoz service
account across all organizations. A deleted account cannot authenticate. If the
configured issuer changes, the old binding does not automatically grant access
to the new realm; review and replace it explicitly.

## Obtain a token and call the API

```bash
ACCESS_TOKEN=$(curl --fail --silent --show-error \
  'https://keycloak.example.com/realms/observability/protocol/openid-connect/token' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=signoz-automation' \
  --data-urlencode 'client_secret=*****...' | jq -r '.access_token')

curl --fail --silent --show-error \
  'https://signoz.example.com/api/v1/service_accounts/me' \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Obtain a new token when the current one expires. Use **access tokens**, not ID
tokens or SigNoz browser tokens. Verification checks the signature, exact issuer,
configured audience, expiry/not-before, Keycloak access-token type, bound subject,
and authorized client (`azp`). The account and binding are read on every request;
token claims cannot assign or override SigNoz roles or organization membership.

Remove the binding to revoke this credential's access to SigNoz immediately,
including already-issued tokens. Removing a binding leaves existing API keys
unchanged. Disabling the Keycloak client stops new token issuance; already-issued
JWTs can remain valid until expiry unless the binding or account is removed.

## Binding API

All endpoints are scoped to the authenticated caller's organization:

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v1/service_accounts/{id}/oidc` | Service account read |
| PUT | `/api/v1/service_accounts/{id}/oidc` | Service account update |
| DELETE | `/api/v1/service_accounts/{id}/oidc` | Service account update |

PUT accepts `{"clientId":"signoz-automation","subject":"keycloak-service-account-user-id"}`.
GET returns the configured provider and any stored binding. PUT is disabled when
OIDC verification is disabled; DELETE remains available to remove stale bindings.
Community builds require the existing administrator role for these operations.

Before deployment, verify a real Keycloak token against the configured API,
confirm role-denied operations return 403, and verify removing the binding rejects
the same token. The automated tests cover local signed-token and database flows;
they do not configure or verify your live Keycloak realm.
