# API and gateway migration

The wrapper, Redis inventory/grants, target Unix accounts, Keycloak login and
`s/g/p/f` remain available. New listeners, identity lifecycle controls, protocol
adapters and SQL indexing are opt-in. An upgrade does not enable them or migrate
inventory into SQL.

The API is the control plane. The gateway terminates native SSH and WebSocket
streams and opens a separately authenticated target connection. Both legs check
SSH host keys. This ingress does not require personal Unix accounts on the
bastion. `auth` remains the process identity; policy chooses the target
`remote_user`. The wrapper retains its Unix/Keycloak binding during rollout.

## Server setup

1. Install `requirements.txt` into the service Python environment. Preserve the
   current Keycloak client, role bindings, Redis ACL/TLS, grants and recordings.
   The legacy wrapper also requires the OS `acl` package (`setfacl`); the Docker
   images include it.
2. Generate a gateway host key as `auth` at
   `/opt/auth/keys/gateway_ed25519`. Distribute its verified public key to clients.
   Keep `/opt/auth/known_hosts` populated with trusted target keys.
3. Merge `configs/gateway.example.yml` into the trusted configuration, using the
   current HTTPS Keycloak issuer and audience. Default `id_token` stays
   compatible. Online introspection requires `access_token`, an audience mapper
   and confidential-client credentials; see `IDENTITY-CREDENTIALS.md`.
4. Run `isolate config validate --check-paths`. Install the gateway systemd unit
   and check its `ExecStart` uses the same Python environment. Enabling listeners
   is an explicit deployment step.
5. Include `nginx/isolate-gateway.conf` in the existing HTTPS virtual host.
   Configure exact `gateway.allowed_origins`. Tickets travel in the first
   WebSocket frame and never in URLs. The API runs on the existing dashboard.
6. Verify an ordinary no-sudo resource, then approvals and privileged resources.
   Policy, maintenance, windows and Keycloak are rechecked before and during
   sessions. A failed check closes the stream.

The catalogue exposes **Web SSH** when enabled. It uses the verified dashboard
session and CSRF. Bearer credentials stay in private Redis records rather than
signed Flask cookies. Share a strong dashboard secret across dashboard nodes.

The gateway supports shell/exec, PTY resize and recording. Forwarding, agent
forwarding, SFTP/subsystems and proxy hops are denied. Use the existing wrapper
for supported legacy proxy hops. The restricted `command_audit.mode: managed`
profile remains on its existing console; the gateway refuses an unrestricted
shell for it. Terminal recordings do not prove every executed command.

## Client console

Clients need no Redis credentials or target SSH keys. Example client config:

```yaml
api:
  client_url: https://bastion.example.org
  gateway_known_hosts: /home/alice/.ssh/isolate_known_hosts
keycloak:
  issuer: https://identity.example.org/realms/company
  client_id: isolate-bastion
  expected_audience: isolate-bastion
  token_kind: id_token
```

Run `isolate login`, then use `s/g/p/f` and completion. Search uses API inventory
and the existing renderer; `g` uses a one-use ticket; `f` fetches the caller's
history with the existing filters. `isolate connect HOST_ID [--command COMMAND]`
is also available. Clients verify the gateway's host key. Server policy controls
the target account; arbitrary wrapper/target/user options are refused in API mode.
Administrative/delegated CLI workflows remain on the bastion or dashboard.

`isolate login --step-up` requests the configured assurance level. Authorization
checks signed `acr/amr/auth_time`; configure the matching Keycloak flow. Freshness
is checked during sessions, so its expiry may require a reconnect. Backchannel
logout callback: `/auth/backchannel-logout`.

Unattended jobs/runbooks currently carry signed rights snapshots rather than
live IdP credentials. They are refused at submission/execution when lifecycle
controls or their applicable step-up policy require unsupported reauthentication.
This prevents those paths from bypassing the new controls.

## API

Resource routes verify bearer issuer, signature, audience and expiry. Browser
ticket creation additionally accepts the verified session plus `X-CSRF-Token`.
Caller-supplied identity, route and credential fields are rejected.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/me` | Caller profile |
| `GET /api/v1/resources?offset=0&limit=100` | Authorized SSH inventory |
| `POST /api/v1/connections` | `{host_id, protocol}` -> one-use ticket |
| `GET /api/v1/history` | Own connection history and filters |
| `GET /api/v1/audit` | Own events and permitted projects in SQL |
| `GET /ready` | Control-store and admission/drain readiness |

SQL visibility is applied before cursor pagination. API/terminal responses use
`Cache-Control: no-store`. Reverse-proxied source addresses currently identify
the proxy; untrusted forwarded headers never override identity or route.

## Indexed audit

JSONL and PTY recordings remain the evidence files. SQL is a derived searchable
index, not a second authority for grants. SQLite is available for one node;
PostgreSQL supports a shared index. Keep its DSN in a protected file.

```yaml
audit_index:
  enabled: true
  driver: postgresql
  dsn_file: /opt/auth/keys/audit_postgres.dsn
logging:
  sinks:
    - type: sql
      driver: postgresql
      dsn_file: /opt/auth/keys/audit_postgres.dsn
```

Initialize explicitly, then add the sink and enable search:

```bash
python3 /opt/auth/scripts/isolate-audit-index.py init
python3 /opt/auth/scripts/isolate-audit-index.py import /opt/auth/spool/audit.jsonl
```

Imports deduplicate `event_id` and reject conflicting content. Search is available
at `/audit/search`. Keep a durable JSONL sink alongside SQL to replay an index
outage. Sink failures follow `logging.fail_closed`; gateway session-start audit
is durable and fails closed. Search indexes metadata and recorded command events
without pretending terminal output is an executed-command stream.

Read `PROTOCOL-ADAPTERS.md` for HTTP/Kubernetes and native-auth database tunnels,
and `CLUSTER.md` for ownership/recovery/persistence constraints.

## Verification

Install `requirements-dev.txt` and run `python -m unittest discover -s tests`.
Run Linux-only Unix/PTY/permission tests on Linux too. The isolated real HTTPS
Keycloak/Redis/PostgreSQL/SSH suite is documented in
`tests/integration/gateway/README.md`. It does not prove a separate production
installation's IdP flow, host keys, network rules or failover configuration.
