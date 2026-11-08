# Installation, diagnostics and OIDC

The setup CLI prepares a private deployment configuration; it does not change an
identity provider, import grants, initialize production SQL or open a listener.
Keycloak configurations continue to work. `oidc.enabled: true` selects a complete
provider-neutral configuration instead of inheriting credentials from Keycloak.

## Prepare an installation

Use Python 3.12 on Linux for managed production services. Install runtime
requirements into a virtual environment. Create a dedicated service identity
(`auth`, UID/GID 2000 in the production image), a private runtime directory, and
external PostgreSQL and Redis services. PostgreSQL DSNs must specify
`sslmode=verify-full`; Redis must use verified TLS. Store credentials in private
regular files owned by the service/root, mode `0600`, under trusted directories.
Restrict Windows ACLs when using local development tools.

From a trusted source checkout, review a plan first:

```sh
python scripts/isolate-setup.py init --plan --output /etc/isolate/isolate.yml \
  --provider oidc --issuer https://login.example/tenant/ --client-id isolate \
  --public-url https://access.example --data-root /var/lib/isolate \
  --dsn-file /run/isolate/secrets/postgresql-dsn \
  --redis-host redis.example --redis-ca /etc/isolate/redis-ca.pem \
  --redis-password-file /run/isolate/secrets/redis-password \
  --client-secret-file /run/isolate/secrets/oidc-client-secret \
  --admin-group access-admins
```

Run the same command without `--plan`, optionally with `--provision-keys`, to
create a new configuration and private local signing/dashboard/SSH host keys.
Existing configuration and keys are never overwritten. `wizard --output PATH`
asks for missing values interactively and never asks you to paste secrets.
For Keycloak use `--provider keycloak` and a realm issuer such as
`https://sso.example/realms/isolate`. JSON output is valid YAML too.

Register `https://access.example/auth/callback` as an exact redirect URI in the
IdP, enable authorization-code flow and PKCE S256, and map the appropriate groups
and roles. Configure the client type and token endpoint authentication method
consistently. Public clients omit the client-secret file. Generic OIDC requires
advertised PKCE S256 and an asymmetric signing algorithm; missing Device Flow
does not disable browser login. CLI Device Flow needs RFC 8628 support. Refresh
tokens/offline access, introspection and backchannel logout are capabilities of
the selected IdP, not assumptions made about every provider.

Provision the SQL schema/cutover explicitly using [STATE-RECOVERY.md](STATE-RECOVERY.md).
Populate target `known_hosts` from a trusted source and review SSH credentials,
grants, policy actions and admin groups before enabling the gateway. Wizard
defaults enable the dashboard/API; SSH ingress, remote jobs and S3 publication
remain opt-in. The wizard does not create remote target users.

```sh
python scripts/isolate-setup.py doctor --config /etc/isolate/isolate.yml --offline
python scripts/isolate-setup.py bind-identity --config /etc/isolate/isolate.yml \
  --actor platform-operator --reason 'Reviewed subjects and group grants for this issuer' \
  --reconciled-subjects --all-ingress-drained
python scripts/isolate-setup.py doctor --config /etc/isolate/isolate.yml
```

`doctor` exits nonzero on failed configuration, private-file, discovery, signing
key, SQL, Redis, audit-directory or identity-binding checks. It reports callback
and IdP capabilities without printing tokens, client secrets or SQL response
bodies. `--offline` contacts neither IdP nor stores. Run diagnostics as the
service identity so permissions match actual operation.

## Provider-neutral configuration

```yaml
oidc:
  enabled: true
  issuer: https://login.example/tenant/
  client_id: isolate
  expected_audience: isolate-api
  token_kind: access_token
  client_secret_file: /run/isolate/secrets/oidc-client-secret
  token_endpoint_auth_method: client_secret_basic
  ca_file: /etc/isolate/idp-ca.pem # omit for system trust
  scopes: [openid, profile, email, isolate.read]
  jwks_cache_path: /var/lib/isolate/cache/oidc-jwks.json
  claim_mapping:
    username: preferred_username
    groups: organization.groups
    roles: /https:~1~1example.com~1roles
```

The issuer is exact, including a trailing slash. Discovery, token and key
requests require verified HTTPS, bounded responses and no redirects. If an IdP
advertises endpoints on another origin, explicitly allow that origin in
`trusted_endpoint_origins: [https://tokens.example]`; token claims never select
an endpoint. Claim mapping accepts dotted paths, JSON Pointer, or ordered path
fallback lists. Generic roles default to `roles`; Keycloak roles retain
`realm_access.roles`. Policies continue to use the normalized groups/roles.

Use access tokens for API/workload clients and configure their actual resource
audience. Browser ID tokens are separately checked against the OIDC client ID.
When `token_kind: access_token`, its verified subject must match the ID token;
the access token supplies current API groups/roles and resource audience.
Legacy Keycloak ID-token configurations remain supported. The workload client
requires the explicit registration, signed marker, subject/client binding and
introspection described in [DELEGATION.md](DELEGATION.md); an ordinary OAuth token
does not automatically become an administrative machine identity.

Keycloak Admin membership refresh is available only through the Keycloak
adapter. Generic OIDC deployments must disable that feature; signed claims are
valid until their token expires unless configured introspection/backchannel
logout revokes them sooner. Configure short token lifetimes and only enable
lifecycle controls actually supported by your IdP. OAuth 2.0 authorization
alone is not an OIDC identity-login implementation.

## Changing an identity provider

A durable binding pins issuer, adapter, subject namespace and claim mapping to
the control store. Existing Keycloak deployments bind automatically on their
first authenticated request. Generic OIDC requires the explicit operator
binding above, including on a new install. A mismatched binding denies access.

Generic subjects use `oidc:<sha256([issuer, sub])>` in the historical
`keycloak_sub` compatibility field; `oidc_sub` retains the raw IdP subject.
The same raw subject from another issuer cannot reuse subject-bound grants,
ownership or preferences. **Group/role names can still collide:** stop/drain all
ingress, review and reconcile grants, roles, Unix mappings, workload subject
bindings, preferences and ownership before binding another provider or changing
claim mapping. The command requires those explicit acknowledgements, records a
durable operator/reason event, and rotates the authority epoch. It does not
automatically transfer users' permissions or restore old state.
`workloads.clients.<client>.sub` pins the raw signed IdP subject; subject-bound
grants and the compatibility `keycloak_sub` API field use the canonical
issuer-scoped subject in generic mode.

## Running services

```sh
python scripts/isolate-service.py dashboard --config /etc/isolate/isolate.yml --check
python scripts/isolate-service.py dashboard --config /etc/isolate/isolate.yml
python scripts/isolate-service.py gateway --config /etc/isolate/isolate.yml
```

The same launcher supports `jobs` and `recordings`. Dashboard uses Gunicorn;
put it behind verified HTTPS termination. Explicit service config ignores shell
configuration overrides. `--check` performs configuration and dependency health
checks without starting listeners. Container processes run as UID/GID 2000 with
read-only application files. See [Helm](helm/isolate/README.md) for Kubernetes and
[RELEASES.md](RELEASES.md) for staged installation and rollback.

## API and infrastructure as code

With `api.enabled`, read `/api/v1/openapi.json`, `/api/v1/openapi.yaml` and
`/api/v1/version`. The explicit OpenAPI catalogue has a route-coverage test.
Streaming SSH/WebSocket/protocol listeners and HTML pages have separate contracts.
The [Terraform provider](../terraform-provider-isolate/README.md) manages real
host/grant CRUD through this API, supports import, uses private rotating token
files, and checks revisions before updates/deletes. The provider is built from
this repository and is not published to the public Terraform Registry.
