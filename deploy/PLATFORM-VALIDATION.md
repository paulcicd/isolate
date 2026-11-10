# Platform foundation validation

This change completes the first roadmap block (1–4): optional SQL authority and
explicit recovery, shared recording evidence, live identity/delegated job
lifecycle, and automated regression/integration/supply-chain checks. Subsequent
blocks were agreed in the order **5–7 and 11 → 8–10 → 13–15**. The 5–7 implementation
and its validation are now documented in [SSH-WORKSPACE.md](SSH-WORKSPACE.md).
Item 11 is implemented in [SETUP.md](SETUP.md), [RELEASES.md](RELEASES.md), the
[Helm chart](helm/isolate/README.md) and the
[Terraform provider](../terraform-provider-isolate/README.md). Infrastructure HA
provisioning is not implied by the foundation.

Block 8–10 is implemented in [DATABASE-PROXY.md](DATABASE-PROXY.md),
[WEB-APPLICATIONS.md](WEB-APPLICATIONS.md) and [KUBERNETES.md](KUBERNETES.md).
It adds optional database credential mediation/SQL lifecycle audit, isolated
browser application origins, and channel-aware Kubernetes operations. Block
13–15 is implemented in [ACCESS-EXPLAIN.md](ACCESS-EXPLAIN.md),
[ACCESS-GOVERNANCE.md](ACCESS-GOVERNANCE.md),
[INVESTIGATIONS.md](INVESTIGATIONS.md) and [SAFE-OPERATIONS.md](SAFE-OPERATIONS.md).
It adds access explanations and policy impact previews, owner reviews and
expiring assignments, durable offboarding, correlated investigations, and
canary-first runbook campaigns. Optional RDP/VNC support remains separate work.

Local verification on 2026-11-10:

| Check | Result |
| --- | --- |
| Python 3.12 Windows full suite | 676 tests, 12 Unix-only skips, no failures |
| Python 3.12 Linux full suite | 676 tests, no skips or failures |
| Real PostgreSQL 17 / Redis 7.4 state suite | 14 integration tests passed |
| Real HTTPS MinIO / PostgreSQL archive | All checks passed |
| Real HTTPS Keycloak / PostgreSQL / Redis / SSH | Login/logout, membership revocation, staged OpenSSH runbooks, signed worker results, scoped timeline and live offboarding passed |
| PostgreSQL audit reference indexes | Partial indexes, scoped person filters and JSON correlation queries passed |
| Native PostgreSQL 17 / MySQL 8 clients | psql/mysql CLI, policy identity, verified TLS/SCRAM/caching_sha2, prepared/binary statements, COPY, cancellation, pipeline recovery and SQL audit passed |
| Kubernetes TLS API fixture / unmodified kubectl 1.31.3 | exec, attach, logs, watch, port-forward, channel bounds, namespace/port scopes and live revocation passed |
| Generic OIDC verified HTTPS / real Authlib browser code flow | PKCE S256, state/nonce, custom claims, separate access/ID audiences, subject mismatch and issuer/binding fences passed |
| Helm 3.17.2 | Strict lint, optional application TLS ingress/affinity, default/optional-component renders, security and migration guards passed |
| Terraform provider / Go 1.26 (unchanged, block 11 validation) | Build, real TLS lifecycle fixtures, framework schema and Terraform 1.9.8 validate passed |
| Production Python 3.12 image | Build, launcher smoke, UID2000 and read-only source checks passed |
| Browser workspace / JS | Real Playwright/Edge catalogue, terminal, replay, access explanations, policy impact, owner review, canary confirmation/cancellation, investigation, mobile layout, isolated application POST/cookies/redirects/WebSocket/logout and JavaScript invariants passed |
| Runtime dependency audit | No known vulnerabilities reported |
| Compile / workflow YAML / whitespace | Passed |

The Windows-only skips were exercised in the Linux run. Linux tests run from a
writable temporary source copy inside the test container because Unix path and
permission tests create temporary directories beneath the checkout. The source
workspace itself is mounted read-only. Unit fixtures use SQLite/fake Redis where
appropriate; the four separate Compose integration suites exercise actual networked
services. Test Compose projects expose no host ports, use synthetic credentials
and are removed with their volumes afterwards. The running demo is untouched.

Installer tests cover reviewed source/dependency inventories, concurrent-safe
selection, failed preflight, source/dependency tampering, schema/authority/issuer
and key incompatibilities, upgrade/rollback without restoring state, service-file
ownership and immutable launch paths. Setup tests cover private exclusive
configuration/key creation, dry-run behavior, credential rotation, explicit
provider binding/epoch rotation and API clients with no Redis dependency.
Administration tests use authoritative SQLite transactions and signed workload
tokens; they cover concurrent idempotent creation, revision conflicts, project
boundaries, scoped automation, CSRF, managed/GitOps grants and credential
redaction. Provider fixture tests use real TLS HTTP, while the separate SQL
integration suite exercises actual PostgreSQL locking and failure behavior.

Critical checks include SQL concurrency/ABA/expiry/transaction rollback, one-use
tickets and approvals, frozen migration/checksum/cutover, inactive backup restore,
epoch races during slow authorization, restored-job quarantine, permanent
termination requests, atomic admission limits and bounded HTTP parsing. Archive
checks cover conditional immutable publication, private capture, tampering and
rollback detection, restart/outage retries, cross-node replay after origin loss,
scope filtering before content download, and history/profile continuity.

The Keycloak integration uses its real authorization-code form and production
Authlib callback over verified TLS; password grants are disabled. It exercises
native SSH, browser CSRF, WebSocket I/O/resize, command job idempotency and actual
OpenSSH execution. Removing the real group invalidates stale JWT membership for
queued/running work and new connections. Real signed backchannel logout closes
active SSH and rejects token reuse and logout replay.

The same real Keycloak token drives a canary and subsequent runbook stage through
OpenSSH; signed terminal worker receipts are required before promotion. A fresh
Keycloak browser session is then offboarded inside Isolate: active SSH closes and
new tickets are denied while the IdP identity remains valid. Lifecycle tests also
cover project boundaries, revision-bound owner decisions, expiry, self-review
restrictions, imported grants, and preissued protocol tickets. Campaign tests
cover concurrent cancellation/promotion, changed or unsigned results, lost worker
ownership, fixed delegation deadlines and uncertain remote outcomes. Workflow
events commit with their source changes and retry publication without repeating
the underlying action; timeline tests enforce visibility before correlation and
exclude raw commands, parameters and credentials.

New protocol checks cover private policy-selected database identities and local
client capabilities, audit exclusion of passwords/parameters/rows/COPY contents,
multi-statement late errors, skipped pipelined operations, cancellation ownership
and separate cross-node evidence. Application checks cover SQL-backed one-use
POST launches, CSRF, domain/Host isolation, verified upstream TLS, compressed
requests, cookie filtering, redirects, WebSocket, real single-use approval,
recovery fencing, ownership loss and control logout. A real browser check caught
and verifies the strict-origin handoff policy needed for cross-site POST Origin.
Kubernetes tests inspect real SPDY port-forward frames, v4/v5 channel directions,
resize/half-close, exact exec argument preservation and operation revocation.
The upstream is a deterministic TLS API fixture, not a provisioned Kubernetes
cluster; actual API-server/version/RBAC/ingress compatibility needs staging.

## Repeatable checks

Install `requirements-dev.txt`, then run:

```bash
python -m compileall -q shared scripts wrappers tests
python -m unittest discover -s tests -v
python -m pip_audit -r requirements.txt --strict
```

Use the commands and prerequisites in each integration suite's README:

- `tests/integration/state/README.md`
- `tests/integration/recordings/README.md`
- `tests/integration/gateway/README.md`
- `tests/integration/databases/README.md`
- `tests/integration/ui/README.md`

`.github/workflows/ci.yml` runs Windows/Linux unit suites, the four Compose integration
suites, browser checks, Helm/Go/production-image builds and a runtime dependency
audit with CycloneDX SBOM output. Actions are
pinned to commit IDs; workflow permissions default to read-only.
`.github/workflows/release-integrity.yml` is manual: it bundles tracked source,
computes SHA-256 and attaches a GitHub OIDC provenance attestation. These newly
added workflows were validated locally; they have not been run on GitHub by this
change. Dependencies still resolve within the repository's version ranges; a
source attestation is not a frozen runtime dependency lock or an independent
security certification.

## Deployment limits

Features remain opt-in. No production database migration, Keycloak change or
listener activation is performed by the tests. Follow `STATE-RECOVERY.md`,
`RECORDINGS.md` and `DELEGATION.md` before enabling them. Validate actual database
TLS, replication/PITR, storage retention, service permissions, IdP flows and
failover fencing in staging. The private integration network explicitly disables
PostgreSQL TLS for the control-state fixture; native database protocol fixtures
use verified TLS, and Keycloak and S3 use verified HTTPS. Test success does not
establish zero RPO, transparent SSH failover or exactly-once remote commands.

Application sessions require sticky routing and a fresh launch after owner loss.
Browser applications need dedicated DNS/TLS and external-URL configuration.
Kubernetes requires WebSocket-capable clients; native HTTP/SPDY is unsupported.
SQL text recording is explicitly opt-in and database-native permissions remain
authoritative. These boundaries are detailed in the three protocol guides.

Policy impact previews evaluate explicit principal scenarios; they are not a
complete census of IdP membership. Review schedules and reminders identify due
reviews, while owners explicitly start and decide them. Offboarding blocks
Isolate access and does not delete or disable the external IdP account.

Campaigns require explicit enablement, upgraded workers and a fixed short-lived
delegation window. They stop on uncertain remote outcomes and do not resume or
retry automatically. Sites without job workers must arrange workflow outbox
publication using the documented audit-index maintenance command. Review audit
index creation, retention and actual deployment recovery behavior before rollout.

The dependency audit above concerns runtime requirements, not every developer
tool already installed in the local virtual environment. It reports the known
advisories available at execution time.
