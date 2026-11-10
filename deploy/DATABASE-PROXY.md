# Native PostgreSQL and MySQL mediation

This opt-in mode adds policy-selected database credentials and SQL lifecycle
audit to the existing gateway. The original TLS transport mode remains available
when `database_proxy.enabled` is absent. No database accounts are provisioned by
this feature; the operator supplies least-privilege database identities.

## Server configuration

Enable the API, HTTPS gateway and `protocols.enabled`. Create an inventory record
whose IP is the actual database endpoint and whose project matches the target:

```yaml
protocols:
  enabled: true
  targets:
    '10044':
      protocol: postgresql
      project: payments-prod
      upstream: postgresql://postgres.internal.example:5432
      ca_file: /etc/isolate/ca/database.pem
      database_proxy:
        enabled: true
        frontend_cert_file: /etc/isolate/credentials/db-client.pem
        frontend_key_file: /etc/isolate/credentials/db-client.key
        databases: [payments]
        default_database: payments
        audit_statement_text: false
        max_packet_bytes: 16777216
        identities:
          analyst:
            type: file
            username: analyst
            password_file: /etc/isolate/credentials/analyst-password
```

MySQL uses the same options with `protocol: mysql` and
`upstream: mysql://mysql.internal.example:3306`. A single `credentials` object may
replace `identities` when there is only one database identity. Grants must include
the matching `postgresql` or `mysql` action, exact `remote_user: analyst`, and
`sudo_mode: none`. The native client's supplied username cannot override policy.

The frontend certificate covers the hostname used by the native client. The
gateway validates the real upstream certificate separately, using the trusted
upstream hostname and CA, while connecting to the inventory IP. TLS verification
is mandatory on both legs. Private keys/password files must have protected
absolute paths and owner-only permissions readable by the service account.
Run the usual configuration check before enabling the listener.

Credential profiles also accept `type: vault-kv` or `type: vault-database` with
`address`, protected `token_file`, optional `ca_file`/`namespace`, `path`, and
`allowed_paths`. KV supports both plain data and the KV-v2 `data.data` envelope.
Vault database leases bound session duration and are revoked on exit, including
identity mismatch. Allowlist `sys/leases/revoke` (or explicit `revoke_path`) too.
The returned username must equal the policy-selected user; arbitrary randomized
Vault usernames are not implicitly mapped to another identity. Use a suitable
Vault username template/role or a static KV identity for that configuration.

## Native clients

After `isolate login`, start the local helper. Its independent random password
prevents another local user from using the helper owner's authorized DB identity:

```bash
python3 scripts/isolate-protocol-proxy.py database \
  --api-url https://access.example.com \
  --gateway-url wss://gateway.example.com \
  --host-id 10044 --protocol postgresql --listen-port 15432 \
  --database-proxy \
  --frontend-password-file /home/alice/.config/isolate/db-client-password \
  --create-frontend-password
```

Prepare the private parent directory first. Creation is exclusive and never
overwrites a file; omit `--create-frontend-password` on later runs. The helper
binds only `127.0.0.1`, validates gateway TLS and gets a fresh one-use API ticket
for every native connection. Use `--ca-file` for a private gateway CA and
`--config` for the client OIDC configuration, including `token_kind: access_token`.
It does not refresh an expired login automatically.

Configure the native client's password from this local file through its private
password facility or interactive prompt. This is **not** the real database
password. Do not place passwords in process arguments or shared connection URLs.
For PostgreSQL, preserve the frontend certificate hostname separately from the
loopback address:

```bash
psql 'host=db-access.example.net hostaddr=127.0.0.1 port=15432 dbname=payments user=analyst sslmode=verify-full sslrootcert=/path/frontend-ca.pem'
```

For MySQL, deliberately map the frontend certificate hostname to loopback and
use `--ssl-mode=VERIFY_IDENTITY` (or MariaDB's `--ssl-verify-server-cert`) with its
CA. The web resource details page supplies the corresponding helper command.

## Semantics, evidence and limits

Wire forwarding preserves transactions, prepared/bound statements, binary
results and PostgreSQL COPY in both directions. PostgreSQL uses SSLRequest and
protocol 3.0 with verified TLS upstream SCRAM-SHA-256, MD5 or TLS password auth.
The helper recognizes libpq's separate native cancellation connection, obtains
new authorization and uses an owner-bound synthetic cancellation key. A foreign
subject, changed route/policy/epoch, ended lease or revoked approval cannot cancel
another session. Cross-node cancellation has a separate durable audit stream
linked by `parent_connection_id`, preserving the owner's archive.

MySQL uses protocol 4.1/TLS and supports upstream `caching_sha2_password`,
`mysql_native_password` and TLS `sha256_password`. Native `KILL QUERY` uses the
database connection ID and the database's own privileges. User switching,
LOCAL INFILE, negotiated compression, legacy PostgreSQL fast-path calls and
direct-TLS PostgreSQL startup are unsupported. Use explicit TLS, not GSSAPI
encryption negotiation, for PostgreSQL clients.

The `sql-query` audit profile records statement hashes/kinds, prepared operations,
completion/error metadata and SQLSTATE. It excludes passwords, bound values,
rows and COPY payloads. `audit_statement_text: true` explicitly adds up to 4096
characters of SQL, which may contain sensitive literals. A simple-query packet
containing multiple statements is audited as one packet lifecycle through
ReadyForQuery, including a later error and completed-command count; this is not
a semantic SQL firewall. Database grants remain authoritative for SET ROLE,
fully-qualified cross-database access and SQL effects; the configured database
allowlist bounds startup/default database and MySQL COM_INIT_DB.

Signed identity rechecks, single-use approvals, connection ownership, session
deadlines and administrator termination apply throughout. This mode terminates
native TLS at the gateway so it can mediate credentials and audit SQL; restrict
direct network access to the real database appropriately.

Verification: [real database clients](../tests/integration/databases/README.md),
[PostgreSQL wire protocol](https://www.postgresql.org/docs/17/protocol-flow.html).
