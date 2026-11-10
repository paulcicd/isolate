# Native database protocol integration

From the repository root, after building the gateway integration runner:

```bash
docker build -t isolate-v2-demo-bastion:latest -f demo/Dockerfile.bastion .
docker compose -f tests/integration/gateway/docker-compose.yml build runner
docker compose -f tests/integration/databases/docker-compose.yml run --build --rm runner
docker compose -f tests/integration/databases/docker-compose.yml down --volumes --remove-orphans
```

The independent `isolate-database-integration` project publishes no host ports.
It uses synthetic passwords and one-day TLS certificates in its own volume,
PostgreSQL 17/SCRAM and MySQL 8/caching_sha2_password. Delete its volume to renew
expired fixture certificates. Setup is idempotent while the same servers run.

The production local helper, WSS listener, native TLS mediation and credential
selection are exercised with actual psql, libpq/psycopg, MariaDB mysql CLI and
mysql.connector clients. Checks cover policy identity overriding a client name,
transactions, prepared/binary statements, failed pipeline recovery and skipped
operation evidence, late errors in multi-statement packets, PostgreSQL COPY both ways, libpq
cancellation followed by continued use of that same connection, and content-free
SQL lifecycle audit. Cancellation runs in a separate client process because
some libpq builds hold the GIL in synchronous PQcancel.

The runtime adapter in this fixture uses fake Redis tickets/leases to isolate
wire compatibility; signed authorization, ownership fencing, cross-node cancel
evidence, approvals and live policy revocation have separate runtime/network
tests. The Keycloak integration suite checks actual IdP login/logout and policy
lifecycle. This suite does not mutate or access a deployed product database.
