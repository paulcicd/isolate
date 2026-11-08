# Operating several Isolate gateway nodes

The gateway can use several application nodes with a shared control-state
authority and PostgreSQL audit index. Redis is the compatible default authority;
optional PostgreSQL authority makes domain state durable in SQL while Redis
holds disposable registries, leases and caches. Optional S3 recording archives
publish evidence across nodes. This repository supplies session ownership,
revocation checks, readiness/draining and durable job claims. It does not
provision highly available databases or storage, configure the load balancer,
or guarantee zero data loss during infrastructure failover.

## Shared and node-local state

All nodes must use the same Keycloak issuer/audience, control-state authority,
dashboard signing secret, SSH gateway host identity, trust roots, credential
provider configuration, and audit index schema. Give each node a distinct
`cluster.node_id`. Configure Keycloak backchannel logout to reach the shared
callback endpoint, not an individual worker process.

With `state.backend: redis`, Redis remains authoritative for inventory, grants,
access/session approvals, revocations, connection tickets and job records. With
`state.backend: postgresql`, those records, job claims, private delegated
credentials and recording publication heads use one SQL authority; SQL failure
denies access without falling back to retired Redis state. The audit index is
still a separate derived search store. Do not write policy changes separately
to SQL and Redis. Every node and worker must select the same authority. Follow
[STATE-RECOVERY.md](STATE-RECOVERY.md) for explicit initialization, fenced
migration and recovery; changing configuration alone does not migrate records.
Redis must be private, authenticated, and use verified TLS when crossing hosts.

For Redis authority, use durable storage and a policy such as
`maxmemory-policy noeviction`.
An eviction of an access decision, logout marker, consumed ticket, or execution
claim is not a harmless cache miss. Size memory and monitor persistence errors,
replication lag, disk usage and backups before exposing several nodes.

Under Redis authority, AOF with `appendfsync everysec` can still lose
approximately the most recent second of writes after a crash. Redis replication
is asynchronous; a failover
can lose acknowledged writes. AOF, replicas, Sentinel, and `WAIT` do not by
themselves make revocation and one-use consumption strongly consistent. Select
and validate the infrastructure durability contract explicitly. After a restore
or a failover with uncertain writes, drain new connections, reconcile approvals
and execution claims, and invalidate outstanding tickets before reopening.
See the official [persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)
and [replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/)
documentation.

Use PostgreSQL for a shared audit index; initialize its versioned schema before
enabling the sink. SQLite state/index databases are intended for one installation
and must not be placed on a shared network filesystem as a substitute for a
database server. PTY/JSONL recordings remain the evidence source. The optional
S3 archive requires SQL authority and publishes signed manifests and immutable
chunks through a durable node-local outbox; history, replay and live tails can
read the latest published revision from another node. See
[RECORDINGS.md](RECORDINGS.md) for private capture paths, worker setup, keys,
retention and outage behavior. Publication has lag, and loss of a node's disk
can lose its unpublished tail. Without the archive, provide shared durable log
storage with tested filesystem semantics or route reads to the recording node.
A shared SQL index alone does not expose local recordings across nodes. There
is no cross-node owning-session stream router or transparent session resume.
Protect PostgreSQL DSN files and never put credentials in browser responses,
command arguments, or source control.

## Session ownership and shutdown

Each gateway session acquires a Redis lease with a random owner token. Its
periodic check revalidates identity, policy, route, approval, administrator
termination and ownership. Losing Redis connectivity or the lease closes the
local connection. A second node never resumes an unknown SSH stream. Active
terminal sessions are not migrated between nodes and can be interrupted by a
node failure or deployment.

Place HTTP/WebSocket ingress behind a TLS reverse proxy and configure exact
allowed browser origins. Keep the unencrypted gateway WebSocket listener on
loopback, or configure its TLS certificate/key for an external bind. Never pass
connection tickets in query strings. Configure native SSH load balancing as
encrypted TCP, with the same provisioned gateway SSH host key on the nodes.
Each ticket is consumed atomically once per authenticated transport. Single-channel
operation is the default. Optional multiplexing, SFTP/SCP and allowlisted TCP
channels share its revalidated identity/ownership lifecycle; losing authorization
closes all of them. Proxy hops have independent grants, credentials, trust and
human approvals. See [SSH-WORKSPACE.md](SSH-WORKSPACE.md) for explicit opt-in setup.

Use the API `/ready` and gateway `/healthz` endpoints for readiness, and remove a
draining node from new-connection load balancing. `cluster.draining: true` stops
new ingress on that node; the shared `isolate_cluster_draining` control-state
marker stops new ingress cluster-wide. Drain before sending SIGTERM. The service then
closes native SSH and WebSocket channels, finalizes session records and releases
ownership. Treat an interrupted session as disconnected, not transparently
recoverable. Verify Keycloak login, logout, step-up and live-session termination
through every ingress during staging rollout.

## Background command execution

The worker uses a random owner token for its temporary lock. Before spawning
SSH it atomically changes `queued` to `claimed` and writes a permanent
`job_execution_claim_<id>` marker. This marker intentionally has no expiry.
The existing local `.job-<id>.claimed` file remains an additional guard.
Do not prune claim records separately from the corresponding job lifecycle.

If a worker disappears after claiming a job, another worker records
`recovery_required` and does not execute the same ID again. A remote command
may already have run even if its result was not recorded. Inspect the remote
outcome before explicitly submitting a new job, and make operational runbooks
idempotent where possible. This is duplicate suppression under the selected
authority's durability contract, not an exactly-once remote execution guarantee. Recovery
state is excluded from ordinary failed-job retry.

Optional short-lived job delegation permits command jobs and runbooks under
the verified Keycloak lifecycle. The submission boundary supplies its verified
token; signed jobs contain an opaque reference and bounded deadline, while a
separate private record encrypts the credential. Workers recheck token activity,
logout, configured live membership, current grants and route before and during
execution. Revocation, expiry or authority failure closes the command transport.
Applicable step-up freshness bounds the delegation lifetime; human session
approval gates and delegated proxy hops remain refused. Without enabled valid
delegation, lifecycle-protected jobs continue to fail closed. See
[DELEGATION.md](DELEGATION.md) for setup and workload identities. Closing a
transport does not undo a completed command or guarantee termination of a
deliberately detached remote process.

## Staged rollout

The API, gateway, protocol adapters, audit index, SQL authority, S3 archive and
job delegation are opt-in.
Keep the existing personal bastion accounts and `s/g/p/f` path during staging.
Add the shared service dependencies, initialize the audit index, provision the
gateway host key and upstream known-hosts file, configure Keycloak, then enable
one ingress on an isolated node. Test allowed and denied access, wrong audience,
expired/tampered tokens, logout, membership removal, approval revocation, Redis
and SQL loss, archive outage, node drain, credential-provider outage, and worker
crash before routing production users. Validate database/storage failover and
recovery against the deployment's durability contract.
Remove any legacy entry path only after its compatibility and authorization
checks pass in the actual deployment.
