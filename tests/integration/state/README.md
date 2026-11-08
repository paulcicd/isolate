# Authoritative PostgreSQL state integration tests

This Compose project exposes no host ports. It creates its own PostgreSQL and
Redis containers, uses synthetic records, and never contacts the demo or a
production service. The runner reuses the existing `isolate-v2-demo-bastion`
image and installs the current PostgreSQL driver/test fixtures.

```powershell
docker compose -f tests/integration/state/docker-compose.yml run --build --rm runner
docker compose -f tests/integration/state/docker-compose.yml down --volumes --remove-orphans
```

Coverage includes real PostgreSQL advisory locks, concurrent NX/GETDEL/counters,
WATCH revisions and absent-key ABA, expiry conflicts, rollback, atomic access
approval/grant/revoke, one-time session approvals, job claims, Redis loss without
resurrecting durable state, factory/CLI reads, atomic Redis 7 migration snapshots,
frozen import/checksum/cutover, and inactive restore with epoch rotation.

The database connection is restricted to the private isolated test network.
Production PostgreSQL must use a protected DSN, verified TLS across hosts, durable
WAL and a separately tested replication/failover/PITR configuration. The tests
do not claim to provision such infrastructure or guarantee zero RPO.
