# Additional protocol adapters

The gateway's optional aiohttp listener serves HTTP/Kubernetes requests and
PostgreSQL/MySQL transport. Configure HTTPS termination for that listener. Direct
unencrypted requests are accepted only from a loopback peer, allowing a local
reverse proxy. Forwarded headers do not establish peer identity. Expose only the
reverse proxy externally. Each resource must exist in inventory and have an
explicit grant for its protocol action; an `ssh` grant does not grant database,
HTTP or Kubernetes access. Keep `protocols.enabled: false` until configured.

An example trusted server configuration:

```yaml
protocols:
  enabled: true
  max_connections: 100
  allowed_origins: []
  targets:
    '10042':
      protocol: http
      project: payments-prod
      upstream: https://api.internal.example:8443
      ca_file: /etc/isolate/ca/internal.pem
      bearer_token_file: /etc/isolate/credentials/payments-api-token
      allowed_methods: [GET, HEAD]
      allowed_paths: ['/health', '/api/status/*']
      max_request_bytes: 1048576
      max_response_bytes: 8388608
      timeout_seconds: 60
    '10043':
      protocol: kubernetes
      project: payments-prod
      upstream: https://kube.internal.example:6443
      ca_file: /etc/isolate/ca/kubernetes.pem
      bearer_token_file: /etc/isolate/credentials/kubernetes-sa-token
      impersonation: true
      impersonation_user_prefix: 'isolate:'
      impersonation_group_prefix: 'isolate:'
      allowed_methods: [GET, HEAD]
      allowed_paths:
        - /api
        - /api/v1
        - /api/v1/namespaces/payments/pods
        - /api/v1/namespaces/payments/pods/*
      allow_watch: false
    '10044':
      protocol: postgresql
      project: payments-prod
      upstream: postgresql://postgres.internal.example:5432
      database_native_auth: true
      require_native_tls: true
    '10045':
      protocol: mysql
      project: payments-prod
      upstream: mysql://mysql.internal.example:3306
      database_native_auth: true
      require_native_tls: true
```

The `project` must match the inventory record. The inventory `server_ip` pins the
actual network destination, while the trusted `upstream` hostname supplies HTTP
Host and TLS certificate validation. Changing public DNS cannot redirect the
HTTP proxy. An upstream literal IP must match inventory. The `upstream` URL may
not contain credentials, a query or fragment. HTTP base paths are supported.
Request paths cannot traverse out of them. Upstream HTTPS verification cannot be
disabled; loopback-only HTTP requires an explicit `allow_loopback_http: true`
and is unavailable for Kubernetes.

## HTTP APIs

`/protocols/http/<host-id>/<upstream-path>` accepts the caller's Keycloak bearer
token in the Authorization header. The proxy validates policy and session
requirements for every request, then forwards only allowlisted request headers.
Caller cookies, credentials, forwarded identity and impersonation headers are
discarded. An optional trusted token file supplies upstream authentication.
Responses discard cookies and redirects; HTML is sandboxed. This is an API
proxy, not transparent hosting of arbitrary browser applications. Cookies,
interactive login redirects and WebSocket upgrades are unsupported.

Default methods are GET/HEAD. Configure mutations and allowed paths explicitly.
Bodies, timeouts and concurrent requests are bounded. Long responses are streamed
with periodic revocation checks. Exceeding a response limit or revoking the
session closes an already-started response. Request audit records contain
method, path, response status and size; they do not include bodies, query values,
Authorization headers or cookies.

## Kubernetes

`/protocols/kubernetes/<host-id>/...` uses the same bearer-token boundary. The
proxy authenticates upstream with a dedicated service-account token and always
impersonates the verified Keycloak subject (`isolate:<sub>`) and its signed
groups (`isolate:<group>`). Callers cannot set impersonation headers. Configure
Kubernetes RBAC for these prefixed users/groups. Grant the proxy service account
only the required `impersonate` privileges; Kubernetes RBAC remains authoritative
for actual object actions. Do not grant wildcard administrative impersonation
without reviewing the resulting Kubernetes permissions.

Use a kubeconfig `server` ending in `/protocols/kubernetes/<host-id>` with the
gateway HTTPS CA configured. The API token can be provided by kubectl's exec
plugin, which reads the existing `isolate login` cache:

```yaml
users:
- name: isolate
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: python3
      args:
      - /opt/isolate/scripts/isolate-protocol-proxy.py
      - credential
      interactiveMode: Never
```

The helper does not automatically refresh an expired login; run `isolate login`
again. Allow API discovery paths required by your kubectl version, as well as
the intended resources. `exec`, `attach`, `portforward` and API `proxy`
subresources require different stream semantics and are denied. `watch` is
opt-in and remains bounded by request time/response byte/session limits.

## PostgreSQL and MySQL

These adapters are an authenticated network gate. They **do not replace database
authentication**, inject credentials, enforce a database username from an SSH
grant, parse SQL, or provide SQL query audit. Configure database accounts, grants
and database-native auditing separately. `database_native_auth: true` explicitly
acknowledges that boundary. The audit profile is `connection`: subject, resource,
session lifecycle and transfer sizes, never database payloads/passwords.

The gateway accepts `/protocols/database` WebSockets. A first JSON frame carries
an opaque, one-time ticket and protocol. The ticket must have been issued for
that exact resource/protocol through the authenticated API. Later frames carry
binary database bytes. Tokens and tickets are not query-string parameters.

The local helper obtains a fresh ticket for each standard client connection:

```bash
python3 scripts/isolate-protocol-proxy.py database \
  --api-url https://isolate.example \
  --gateway-url wss://gateway.example \
  --host-id 10044 --protocol postgresql --listen-port 15432
```

The listener is always `127.0.0.1`. Gateway TLS validation is mandatory; supply `--ca-file` for a
private gateway CA. `--allow-loopback-http` is only for explicit loopback tests.

PostgreSQL must begin with the conventional SSLRequest and the server must
accept it; MySQL must advertise TLS and the client must send SSLRequest before
authentication. Plaintext startup/authentication packets are rejected. TLS then
continues end to end between the native database client and database server.
The database client must validate the database certificate and intended hostname.
For PostgreSQL, preserve the certificate hostname separately from the tunnel IP:

```bash
psql 'host=postgres.internal.example hostaddr=127.0.0.1 port=15432 sslmode=verify-full sslrootcert=/path/database-ca.pem dbname=payments user=analyst'
```

For MySQL use `--ssl-mode=VERIFY_IDENTITY` and a local DNS/hosts mapping that routes
the database certificate hostname to the loopback listener. Configure that
mapping deliberately; using `127.0.0.1` as the TLS hostname will fail unless it is
covered by the database certificate. Direct-TLS PostgreSQL negotiation,
unencrypted cancellation requests and non-TLS database configurations are not
supported by this adapter.

Official references: [aiohttp client](https://docs.aiohttp.org/en/stable/client_reference.html),
[Kubernetes impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation),
[PostgreSQL TLS](https://www.postgresql.org/docs/current/libpq-ssl.html),
[MySQL TLS](https://dev.mysql.com/doc/refman/8.4/en/using-encrypted-connections.html).
