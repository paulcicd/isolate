# Authoritative state and recovery

`state.backend: postgresql` makes PostgreSQL the single authority for inventory,
grants, approvals, revocations, one-use tickets, job records/claims, delegated
credentials, recording publication heads and counters. Values retain the
existing byte/JSON domain format. SQL transactions, versioned tombstones and
advisory locks implement the existing WATCH/MULTI semantics, including absent
keys and expiry. New domain keys are durable by default. Transactions spanning
SQL and Redis are rejected before execution.

Redis remains the disposable session registry, ownership/node leases, health and
completion cache, and admission counters. Loss of a lease closes its session;
SQL failure denies authorization, with no fallback to old Redis grants. SQL is
not provisioned automatically. SQLite is available for development/single-node
tests, not multi-node production.

```yaml
state:
  backend: postgresql
  dsn_file: /opt/auth/keys/state_postgres.dsn
  require_tls: true
  migration_guard: true
```

Keep the DSN in a root/service-owned file with mode 0600, outside source control.
For a network connection include `sslmode=verify-full` and the trusted CA path
in the DSN. Every application node and worker must use the same SQL authority.
Use a separate least-privilege database account for the audit index if desired.
Application accounts need the state tables after explicit initialization;
reserve schema creation for an installation role. The repository does not set
up replication, PITR or synchronous replicas. Test that infrastructure's RPO,
failover fencing and backup restoration independently.

## New installation

Only for an empty installation, with the config above:

```bash
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml init --empty-installation --yes
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml status
```

## Migrating existing Redis state

Use a maintenance window. Deploy the upgraded guard-aware code first, but keep
all application ingress/writers stopped during the migration. Stop discovery,
GitOps, background jobs, dashboard/MCP mutations, legacy wrappers and scheduled
tasks. Fence obsolete Redis clients with Redis ACLs/network access and drain
existing sessions. CLI acknowledgement flags attest these external actions;
the script cannot stop an old binary or revoke its credentials for you.

The migration config must point to the original Redis and the new PostgreSQL.
Use Redis 7 or later. Take an independent backup of both services first.

```bash
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml init --yes
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml plan
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml freeze --actor operator --yes --writers-stopped --legacy-acl-fenced --all-ingress-drained
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml import --yes --writers-stopped --legacy-acl-fenced --all-ingress-drained
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml verify
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml cutover --actor operator --yes --writers-stopped --legacy-acl-fenced --all-ingress-drained
```

The frozen source is captured atomically, including absolute expiry timestamps.
Import/verify compare checksums. Outstanding connection tickets are excluded;
cutover creates a new authority epoch. The SQL target stays inactive until
cutover. There is no dual-write window. After cutover deploy the SQL config on
every reader/writer, then reopen ingress. Retired Redis domain data must never
be used as a fallback. Before cutover, `abort` with the same fence flags can
unfreeze the source; it deliberately refuses automatic rollback after cutover.

## Backup and restore

Use native PostgreSQL backups/WAL/PITR for production recovery, together with
protected configuration, job/delegation keys and recording signing keys. The
legacy Redis `isolate backup` format is not a SQL backup and rejects SQL state.
An explicit portable snapshot is also available:

```bash
python3 /opt/auth/scripts/isolate-state.py --config /opt/auth/configs/isolate.yml export --output /secure-backups/state.json
```

The output is created exclusively with private permissions and includes
credentials, revisions, expiry and tombstones. Encrypt and access-control it.
Its checksum detects corruption, not a maliciously replaced backup. Keep backup
storage and integrity evidence outside an application writer's permissions.

Restore into a new empty inactive target while all ingress and old writers are
externally fenced. Run `init --yes`, then `restore --input /secure-backups/state.json`
with `--yes --writers-stopped --legacy-acl-fenced --all-ingress-drained`.
Restore does not activate the target. Reconcile policy/revocation changes since
the backup and inspect remote outcomes before using `activate-restored --actor
operator --reason 'reconciled backup recovery'` with those same fence flags.
Activation atomically rotates the authority epoch and quarantines all restored
queued/claimed/running jobs as `recovery_required`, including older job schemas.
It never automatically re-executes them. Submit a new job only after checking
what happened on the target.

For native database/PITR recovery also keep ingress fenced, reconcile pending
jobs and unknown remote effects, and run `rotate-epoch --actor operator --reason
'reconciled database recovery' --yes` before reopening. Unlike portable restore,
epoch rotation alone does not quarantine old-schema jobs. Never infer an
exactly-once remote execution guarantee from a database commit or restored claim.
Old tickets, delegated jobs and active gateway/wrapper contexts fail their epoch
checks. Redis registries/leases can be cleared or allowed to expire while drained.

`isolate health --json` checks active SQL metadata and Redis availability without
returning DSNs. The isolated real PostgreSQL/Redis migration and concurrency
suite is described in `tests/integration/state/README.md`.
