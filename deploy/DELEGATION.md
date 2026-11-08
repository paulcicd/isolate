# Current Keycloak membership and delegated operations

The console, native SSH, Web SSH, API and workers use a verified stable subject.
Lifecycle controls remain opt-in for a compatible rollout. Once enabled, no
snapshot fallback is accepted when the configured authority is unavailable.

## Authoritative membership

JWT introspection proves token activity; a self-contained token's group claims
are not assumed to change after issuance. To apply user disablement, group
removal and current realm-role membership without waiting for JWT expiry, enable
the Keycloak Admin REST membership reader:

```yaml
identity_security:
  membership:
    enabled: true
    source: keycloak-admin
    client_id: isolate-membership-reader
    client_secret_file: /opt/auth/keys/membership-reader.secret
    # Alternatively token_file may reference an externally rotated access token.
    group_name_style: name
    include_realm_roles: true
    max_groups: 1000
    timeout_seconds: 10
```

Provision a dedicated confidential Keycloak service-account client with only
the read permissions required to inspect users, groups and effective realm role
mappings. Do not use a realm-administrator credential. Verify the minimal role
assignment against the deployed Keycloak version. Secrets must be absolute-path
regular files owned by the service user/root, with owner-only permissions.

The reader derives `/admin/realms/<realm>/users/<verified-sub>` from the trusted
HTTPS issuer. A caller cannot select another identity, URL, realm or credential.
Redirects are refused. TLS validation, response limits and timeouts are mandatory.
The current enabled flag, paginated groups and composite realm roles are fetched
on every refresh. Missing permissions, malformed data, missing users, disabled
users and network failures deny access. Set `group_name_style: path` if policies
use the full Keycloak group path rather than its display name.

Only the management client's access credential is cached, for at most 60 seconds
and within its issued lifetime; user membership decisions are not cached. A
rotated secret changes the credential cache key. An expired/rejected management
credential is removed and the next check obtains a new one. An optional static
`token_file` requires external rotation before its expiry.

The real revocation delay includes the session/worker recheck interval, the
bounded Keycloak request budget and normal processing latency. Measure that SLA
under the actual load; this configuration does not claim instantaneous changes.

## Short-lived job delegation

```yaml
identity_security:
  delegation:
    enabled: true
    max_seconds: 300
    recheck_interval: 2
```

The authenticated submission boundary supplies its actual verified bearer token
to job creation. `id_token` remains supported for the existing CLI setup when
online introspection is off. Introspection requires `token_kind: access_token`
and the confidential client already configured for that check. The accepted
audience must be the configured main API audience or, when MCP is enabled, its
configured MCP audience. No caller-supplied audience or issuer is trusted.

A job stores an opaque delegation ID, deadline and principal type in its signed
schema-v3 authorization fields. The private token is AES-GCM encrypted in a
separate `delegated_identity_<id>` authoritative record. Its encryption key is
derived with a dedicated HKDF context from the existing protected job signing
key, so encryption and authorization signing use separate derived keys. Tokens
and refresh tokens are never copied into public job records or audit payloads.
The private record is bound to the exact signed job payload and, for SQL state,
the authority generation. Configure the same signing key on authorized workers.

The deadline can only be shortened by token expiry, grant expiry, configured
delegation duration or the applicable step-up authentication freshness window.
No refresh token is retained and workers cannot renew delegation by themselves.
A retry of a delegated job requires fresh submitter authorization and receives
a new delegation reference. Stable subjects continue to bind retries after a
display username changes.

At submission and immediately before execution, the worker checks token
signature/issuer/audience/expiry, logout markers, configured online activity,
current membership, current grants, route and target account. Those checks run
again while the SSH command is active. Revocation, expiry, changed policy or an
unavailable authority closes the command transport and marks the operation
cancelled. Closing a transport does not roll back a command that already ran or
guarantee termination of a deliberately detached remote process. Permanent job
claims still prevent automatic same-ID reexecution after an unknown outcome.

Per-connection human approval gates continue to reject unattended jobs until a
separate approved job workflow is available. Delegated proxy-hop operations are
also refused until every hop has its own bound authorization. Enabling
delegation never bypasses these gates or a required human step-up policy.

## Workload identities

Workloads use an explicitly registered Keycloak service account, an access token
with a fixed audience and action scopes, and a signed
`isolate_principal_type: service` claim. Configure that marker with an
administrator-controlled protocol mapper rather than an editable user attribute.

```yaml
keycloak:
  token_kind: access_token
identity_security:
  introspection:
    enabled: true
  workloads:
    enabled: true
    clients:
      scheduled-diagnostics:
        sub: exact-keycloak-service-account-uuid
        required_scopes: [isolate.runbook]
        allowed_actions: [runbook]
        allowed_runbook_classes: [read_only]
```

Pin each client's stable service-account subject. Registered workloads without
the signed marker are rejected, and unknown service markers are rejected.
Service identities have no human groups/roles for Isolate authorization. Their
grants must explicitly use `subject: service` with the configured client ID:

```yaml
subject: service
name: scheduled-diagnostics
project: payments-stage
remote_user: observer
sudo_mode: none
allowed_actions: [runbook]
```

The workload must satisfy all of: configured allowed action, corresponding OAuth
scope, allowed runbook class where applicable, enabled execution configuration
and matching service grant. Human/group/role grants cannot authorize it. Human
MFA and approval requirements are not silently reinterpreted as machine access.
Obtain short-lived client-credentials tokens through Keycloak's standard token
endpoint and keep the client secret in the deployment secret manager. Isolate
does not expose or return that secret.

Official references: [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html),
[Keycloak OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers),
[OAuth token introspection](https://datatracker.ietf.org/doc/html/rfc7662).
