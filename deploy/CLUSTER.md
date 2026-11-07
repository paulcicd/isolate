# Operating several Isolate gateway nodes

The gateway can use several application nodes with one authoritative Redis
deployment and a shared PostgreSQL audit index. This repository supplies session
ownership, revocation checks, node readiness/draining, and durable job claims.
It does not provision a Redis/PostgreSQL cluster, configure the load balancer,
or guarantee zero data loss during infrastructure failover.

## Shared and node-local state

All nodes must use the same Keycloak issuer/audience, policy/catalog Redis,
dashboard signing secret, SSH gateway host identity, trust roots, credential
provider configuration, and audit index schema. Give each node a distinct
`cluster.node_id`. Configure Keycloak backchannel logout to reach the shared
callback endpoint, not an individual worker process.

Redis remains authoritative for inventory, grants, access/session approvals,
revocations, connection tickets and job records. SQL is the audit search index;
it is not a second independent source of access decisions. Do not write policy
changes separately to SQL and Redis. Redis must be private, authenticated, and
use verified TLS when crossing hosts.

Use durable Redis storage and a policy such as `maxmemory-policy noeviction`.
An eviction of an access decision, logout marker, consumed ticket, or execution
claim is not a harmless cache miss. Size memory and monitor persistence errors,
replication lag, disk usage and backups before exposing several nodes.

AOF with `appendfsync everysec` can still lose approximately the most recent
second of writes after a crash. Redis replication is asynchronous; a failover
can lose acknowledged writes. AOF, replicas, Sentinel, and `WAIT` do not by
themselves make revocation and one-use consumption strongly consistent. Select
and validate the infrastructure durability contract explicitly. After a restore
or a failover with uncertain writes, drain new connections, reconcile approvals
and execution claims, and invalidate outstanding tickets before reopening.
See the official [persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)
and [replication](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/)
documentation.

Use PostgreSQL for a shared audit index; initialize its versioned schema before
enabling the sink. SQLite is intended for one installation and must not be
placed on a shared network filesystem as a substitute for a database server.
PTY/JSONL recordings remain the evidence source. Provide shared durable log
storage with tested filesystem semantics, or export node recordings into a
central archive and route replay/live-view requests to the owning node. The
current release does not implement an S3 recording backend or a cross-node live
stream router. A shared SQL index alone does not make local recordings visible
on another node. Protect the PostgreSQL DSN file and never put credentials in
browser responses, command arguments, or source control.

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
Each ticket is consumed atomically once; opening a second SSH session channel
on that connection is refused. Forwarding, SFTP, and proxy-hop SSH are not
enabled by this gateway.

Use the API `/ready` and gateway `/healthz` endpoints for readiness, and remove a
draining node from new-connection load balancing. `cluster.draining: true` stops
new ingress on that node; the shared `isolate_cluster_draining` Redis marker
stops new ingress cluster-wide. Drain before sending SIGTERM. The service then
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
idempotent where possible. This is duplicate suppression under the stated Redis
durability contract, not an exactly-once remote execution guarantee. Recovery
state is excluded from ordinary failed-job retry.

Queued jobs currently carry signed authorization snapshots rather than a live
delegated Keycloak token. Consequently command jobs and runbooks fail closed
when centralized backchannel revocation or online introspection is enabled.
They also fail closed for targets requiring fresh step-up or human session
approval. Disabling these identity controls to make a job run changes the access
policy and must not be used as an automatic workaround. Interactive ingress
uses the verified live identity lifecycle.

## Staged rollout

The API, gateway, protocol adapters and audit index are disabled by default.
Keep the existing personal bastion accounts and `s/g/p/f` path during staging.
Add the shared service dependencies, initialize the audit index, provision the
gateway host key and upstream known-hosts file, configure Keycloak, then enable
one ingress on an isolated node. Test allowed and denied access, wrong audience,
expired/tampered tokens, logout, approval revocation, Redis loss, node drain,
credential-provider outage, and worker crash before routing production users.
Remove any legacy entry path only after its compatibility and authorization
checks pass in the actual deployment.
