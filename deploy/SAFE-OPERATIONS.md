# Canary-first runbook campaigns

Campaigns run an explicitly reviewed target list through a small canary, then
bounded batches. Every child remains a normal signed Isolate job with current
policy, exact remote identity, encrypted short-lived delegation and the existing
worker execution claim. Direct command fleets and ordinary runbook jobs retain
their existing behavior.

## Enable and submit

Configure the existing runbook classes, permitted groups/scopes, job signing key
and worker, then enable:

```yaml
campaigns:
  enabled: true
  max_hosts: 100
  max_batch_size: 50
identity_security:
  delegation:
    enabled: true
    max_seconds: 300
    recheck_interval: 2
```

Keep the protected signing/encryption key and control-store setup from
[DELEGATION.md](DELEGATION.md). Campaigns require the configured OIDC bearer
token, existing `isolate.runbook`/operational scope and group/target permissions.
Workload identities must have the corresponding registered action and class.
Human per-session approval requirements are not bypassed: targets requiring such
approval remain unavailable to unattended runbooks.

Open **Staged operations** at `/operations/campaigns`, select a permitted runbook,
enter target IDs and typed parameters, then review the selected policy identities
and stop conditions. **Start canary** requires explicit confirmation. The page
shows current stage/children, provides investigation links and an explicit stop
action. Browser mutations require the signed session's CSRF value.

API clients first POST `/api/v1/runbook-campaigns/preview`:

```json
{
  "runbook_id": "uptime",
  "host_ids": ["10001", "10002", "10003", "10004"],
  "parameters": {},
  "canary_count": 1,
  "batch_size": 2,
  "failure_budget": 0,
  "max_failure_percent": 100
}
```

Submit the same body to POST `/api/v1/runbook-campaigns`, adding the returned
`preview_digest`, literal `confirm: true`, and a fresh `Idempotency-Key` header
(16–128 printable non-space characters). Current policy, routes, runbook
definition, parameters, target ordering and recovery epoch must still match the
preview. An identical repeated request returns the original campaign; changing
the request under the same key is refused. Preview/create are separate so a
resource change cannot silently alter a reviewed operation.

GET `/api/v1/runbook-campaigns` and `/<id>` expose the caller's history;
platform administrators can inspect all campaigns. POST `/<id>/cancel` requires
`{"confirm":true}`. Public campaign data excludes bearer tokens, ciphertext,
upstream credentials, raw command text and runbook parameter values.

## Execution and stop conditions

The existing job worker reconciles active campaigns; no extra worker service is
required. With the managed launcher, run the jobs component using the same
configuration and control authority as the API:

```bash
python3 scripts/isolate-service.py jobs --config /run/isolate/secrets/isolate.yml
```

Creation atomically publishes the campaign, its first queued canary and all later
children as `held`. The entire canary must complete successfully before any
later stage becomes eligible. A batch finishes before the next batch is queued.
Multiple workers use transactional state comparison and durable execution claims
to avoid duplicate promotions/executions. The default canary is one target,
later batches are five targets, and the default allowed failure count is zero.

After the canary, `failure_budget` is the total allowed known remote failures
(nonzero command exit codes 1–254). `max_failure_percent` limits that count relative to terminal
children. Exceeding either stops expansion. Both conditions are cumulative.
Any missing child, damaged signature, lost worker with an uncertain outcome or
`recovery_required` child always stops the campaign, regardless of failure
budget. SSH transport exit 255, a timeout or a local failure without a known
remote exit code also requires review; killing a local SSH process does not prove
the remote command stopped. Cancelling any child stops future expansion even
when a failure budget remains. No automatic retries occur. A child cannot be retried independently;
review outcomes and submit a fresh reviewed campaign if another attempt is safe.

Stopping requests cancellation of active jobs, cancels queued/held jobs and
prevents future promotion. Workers check campaign state before and during the
actual SSH process. Current grant/group/IdP changes, offboarding, delegation
expiry, disabled campaign configuration and recovery epoch changes stop work.
An administrator stop cannot undo commands that have already taken effect;
ordinary remote-operation uncertainty still applies.

## Durability and audit

Signed immutable plans and signed progress prevent editing a stage to skip its
canary. Schema-4 jobs bind campaign ID, stage and slot before their encrypted
delegation is sealed. Earlier job schemas remain compatible. An older worker
cannot validate the additional signature fields, so drain/upgrade workers
before enabling campaigns in a mixed-version deployment.

Terminal child results carry a signed worker receipt binding their outcome to
the campaign, stage, job authorization, recovery epoch and durable execution
owner. An unsigned or altered result cannot authorize another batch. Worker
updates compare the active lease and permanent execution claim transactionally;
a delayed former owner cannot overwrite a completed or quarantined job.

Parent/child state and transition evidence commit in one control-store
transaction. The retained workflow event and pending publication record
survive a publisher failure. The normal job-worker poll retries publication to
JSONL/sinks and the optional audit index; publication never repeats a remote
command. Per-project events and child job audit include campaign/grant/request
references and hashed IdP-session identity for investigation. Parameters and
output remain governed by normal job output permissions, not workflow metadata.

Enable `logging.integrity.enabled` with its protected key to sign these workflow
audit records. This optional audit setting is independent of the mandatory
campaign plan, progress and worker-result signatures above.

Use SQL authority and its normal backup/recovery procedure for durable rollout
state. Redis-only persistence has the same durability limits as other jobs.
Restore activation must rotate the authority epoch; stale campaigns then stop
and claimed/running outcomes remain quarantined. A missing or damaged campaign
never authorizes a held child. Investigate evidence before creating a new plan.

Delegation has a fixed bounded deadline, capped by token/grant/step-up expiry.
Campaigns do not retain refresh tokens or extend deadlines between stages. Size
the canary/batches/timeouts to fit that authorization window; long maintenance
work requires a fresh reviewed campaign. There is no automatic resumption after
expired authorization, uncertain remote outcomes or recovery fencing.

Verification includes authoritative SQLite concurrency/idempotency, promotion
versus cancellation races, stale previews, current-authority and offboarding
revocation, signature tampering, actual worker subprocesses, live cancellation,
and real Flask browser/bearer/CSRF boundaries. Real Keycloak and SSH lifecycle
compatibility is additionally covered by the platform integration suite.
