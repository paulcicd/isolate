# Keycloak session security and SSH credential providers

The existing console and service-user SSH wrapper continue to work. All new
security features are opt-in. Keep the current `keycloak.issuer`, `client_id`,
audience, group mappings and target OS users through a rolling migration.
An API or gateway does not provision or remove target Linux accounts.

## Session revocation and step-up

```yaml
keycloak:
  issuer: https://id.example.org/realms/company
  client_id: isolate-bastion
  expected_audience: isolate-bastion
  verify_tokens: true
  tls_verify: true
  token_kind: id_token

identity_security:
  backchannel_logout:
    enabled: true
    max_logout_age_seconds: 300
    max_token_lifetime_seconds: 86400
  introspection:
    enabled: false
  step_up:
    enabled: true
    require_privileged: true
    required_projects: [payments-prod]
    required_project_globs: []
    all_connections: false
    acr_values: ["2"]
    required_amr: []
    max_age_seconds: 300
```

The ACR string `"2"` is an example, not an inherent proof of MFA. Configure
Keycloak's authentication flow and ACR/LoA mapping so that this signed claim
requires the intended extra factor. If `required_amr` is configured, ensure
Keycloak emits the AMR claim. Required AMR values are all required; ACR values
are accepted alternatives. A fresh, signed `auth_time` is also required.
Requesting `acr_values` or `max_age` alone never satisfies the resource check.

Configure Keycloak's backchannel logout URL to `/auth/backchannel-logout` on the
dashboard/API origin and enable
session IDs in logout events. The callback accepts form-encoded `logout_token`;
its signature authenticates the IdP. It checks issuer, client audience, issue
time, event type, subject/session ID and replay ID, and rejects nonce-bearing
tokens. A logout token cannot authenticate as a user. A `sid` event revokes the
specified IdP session; a subject-only event revokes sessions authenticated at or
before the logout cutoff. Revocation and replay markers are committed together
in Redis. Every live-session recheck reads authoritative revocation state.

Tokens must contain `iat` and have a lifetime no longer than
`max_token_lifetime_seconds`; set this above the actual Keycloak token lifetime.
Revocation markers are retained beyond that lifetime. Persist Redis state and
include these markers in recovery procedures; loss of authoritative revocation
state must not be treated as a safe continuation of pre-failure sessions.
Subject-wide checks use signed `auth_time` when present, so refreshing an old
session's token does not count as a new authentication.

Backchannel logout reacts to events actually emitted by Keycloak. For checking
IdP session status on every authorization/recheck, enable introspection and use
`keycloak.token_kind: access_token`. Configure the Keycloak audience mapper to
include `expected_audience` in access tokens and supply the confidential
client's secret through trusted server configuration. Keycloak introspects
access tokens; ID-token compatibility mode must keep introspection disabled.
Introspection is uncached and fails closed when Keycloak is unavailable.

The API, legacy SSH authorization, verified CLI cache and live-session rechecks
must all call `assert_identity_active`; otherwise that ingress cannot enforce
central revocation. `load_verified_identity` does so automatically when logout
or introspection is enabled. The service checks require verified HTTPS, a
validated token signature, and a configured audience.

## Credentials

The default `legacy` provider reads the existing trusted OpenSSH config,
including its `IdentityFile`. Known-host verification is always explicit.
These providers are used by the gateway session engine. The compatibility Unix
wrapper keeps its current OpenSSH config until that console is switched to API
client mode; configure both paths during an overlap period.

```yaml
credentials:
  default: legacy
  known_hosts: /opt/auth/known_hosts
  targets:
    "10001": prod-certificate
    "10002": rotating-key
  providers:
    prod-certificate:
      type: vault-ssh
      address: https://vault.example.org:8200
      token_file: /opt/auth/keys/vault-token
      ca_file: /etc/isolate/vault-tls-ca.pem
      mount: ssh
      role: isolate-support
      allowed_paths: [ssh/sign/isolate-support]
      ca_public_key_file: /opt/auth/keys/ssh-user-ca.pub
      ttl_seconds: 300
    rotating-key:
      type: vault-kv
      address: https://vault.example.org:8200
      token_file: /opt/auth/keys/vault-token
      mount: secret
      path: isolate/target-10002
      field: private_key
      allowed_paths: [secret/data/isolate/target-10002]
```

Vault and OpenBao use the same supported HTTP API. The KV provider supports KV
version 2. Provider names, URLs, mounts, paths, roles and local files are selected
only by server-owned configuration, never by a client request or descriptive
inventory metadata. HTTP, disabled TLS verification, redirects and paths outside
the exact allowlist are rejected. Vault tokens are read from protected files
(root/service-owned `0600` on Unix). A Vault Agent can maintain the token file;
this module does not renew the Vault login itself.

For certificate authentication, configure the Vault/OpenBao SSH signing role
with the exact allowed target accounts, user-certificate signing, the intended
extensions (for example `permit-pty`), an appropriate maximum TTL and permission
to supply the attribution key ID. Target sshd must trust the configured signing
CA through `TrustedUserCAKeys`. Existing target OS accounts and sudo rules still
determine execution privileges. A certificate does not create an OS account.

Each certificate request uses a new Ed25519 key and a key ID binding the stable
Keycloak subject to the connection ID. The returned certificate is checked for
the expected CA, matching public key, user-certificate type, selected target
principal, attribution ID and bounded validity before use. Expiry controls
authentication of a new SSH connection; an already open session is terminated
by the session authorization deadline/recheck, not by certificate expiry alone.

File providers are also supported:

```yaml
credentials:
  default: service-key
  known_hosts: /opt/auth/known_hosts
  providers:
    service-key:
      type: file
      private_key_file: /opt/auth/keys/service_ed25519
      # certificate_file: /opt/auth/keys/service_ed25519-cert.pub
      # ca_public_key_file: /opt/auth/keys/ssh-user-ca.pub
```

File credentials are read on each new connection, allowing externally managed
rotation. Publish complete files atomically and preserve private-key ownership
and permissions. Rotation changes subsequent connections; it does not silently
replace a key in an existing SSH transport.

Vault key/certificate material lives in a per-connection `0700` temporary
directory with `0600` files and is removed on disconnect, cancellation and
connection failure. Keep the `ssh_credentials(...)` context open for the whole
outbound connection. No secret value is returned by the public API or logged.

## Validation performed in this checkout

Automated tests use real signed RSA JWTs and Ed25519 SSH certificates to cover
logout signature/claim validation, replay prevention, session/subject revocation,
freshness/assurance checks, KV key validation, certificate bindings and cleanup.
Vault HTTP behavior is simulated. Production Keycloak flows, Vault policies and
target sshd trust must additionally be exercised in the deployment environment.

References: [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html),
[Keycloak authentication flows](https://www.keycloak.org/docs/latest/server_admin/),
[RFC 9470 step-up challenge](https://www.rfc-editor.org/rfc/rfc9470.html),
[Vault SSH API](https://developer.hashicorp.com/vault/api-docs/secret/ssh),
[Vault KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2),
[AsyncSSH options](https://asyncssh.readthedocs.io/en/latest/api.html).
