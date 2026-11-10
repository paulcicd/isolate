# Correlated investigation and committed workflow evidence

Open **Investigation** in the portal or `/investigations`. The shared audit index
must be enabled and initialized explicitly. Employees see their own events;
auditors and project owners additionally see evidence in projects permitted by
their current `audit.read` role. Platform administrators can investigate across
projects. Visibility is applied in SQL before correlation, limits and pagination.
An entity ID or navigation link never grants access to its evidence.

## Follow a workflow

Choose a session, access request, session approval, job, runbook campaign, grant
or sign-in session hash. Alternatively filter by a person, project, resource or
UTC date range. The person filter includes authorized decisions **about** that
stable subject as well as their own actions. It does not expand visibility to
another actor's otherwise private records.

Rows show the six lifecycle stages: sign-in, access, approval, session, command
and result. IDs link recorded requests/approvals to sessions, commands and jobs;
worker events also link campaigns and their children. The UI orders each latest
page chronologically and its **Earlier events** link moves backwards. Explicitly
unobserved stages remain visible as gaps; the product does not fabricate a login
or command from a nearby timestamp. An older source event without `ts` uses its
index-ingestion timestamp and is labelled accordingly.

Correlation uses only explicit producer identifiers. It does not infer causality
from usernames or timing. Shared sign-in-session hashes can relate multiple
sessions, so a related view can contain several activities from that sign-in.
Group grant IDs are not followed automatically into unrelated sessions; choose
the grant explicitly for that investigation. Expansion is limited to three
passes, 200 events per pass and 64 identifiers per reference field. A bounded
result is labelled; narrow the object/time range to review more evidence.

The view excludes raw commands, SQL text, parameters, outputs, reasons, cookies,
tokens and claims. It includes command/statement hashes, scope, actor, status and
safe relationship metadata. Session/job detail links apply their own current
authorization. Original JSONL and archived recordings remain the evidence source;
this timeline is a searchable projection, not independent verification of a
complete capture or a replacement for recording integrity checks.

## Setup and API

Configure `audit_index.enabled` with the existing SQLite or PostgreSQL options
and a SQL audit sink matching that index, as in `GATEWAY-MIGRATION.md`. Initialize
or add the reference indexes through the trusted operator command:

```bash
isolate config validate --check-paths
python3 scripts/isolate-audit-index.py init
```

Index initialization adds partial reference indexes without changing schema
version 1. Existing event payloads/signatures are not rewritten. Plan production
index creation for the size and maintenance budget of the deployment; it is not
performed by a search request or by this implementation's tests on a live service.

`GET /api/v1/investigations/timeline` supports `kind`, `id`, `subject`, `project`,
`host_id`, `since`, `until`, `before`, `limit` (1–200), `related` and `q`.
The response declares page order, observed/unobserved stages and whether
expansion reached a bound. API timestamps are epoch seconds; browser filters are
labelled UTC. The API authenticates a signed bearer or the existing browser
session and performs the same fresh lifecycle checks as the control API.

## Transactional evidence and delivery

Access requests, approval transitions, governance decisions and campaign stage
changes commit retained workflow evidence in the same control-store transaction
as the domain change. `workflow_event_<id>` is retained; its
`workflow_pending_<id>` counterpart queues publication. Enable
`logging.integrity.enabled` and configure its protected key to cryptographically
sign workflow audit records. Without this option, transactional retention and
retry still work, but the records are unsigned. When signing is enabled, a
signing failure aborts the transaction. A rolled-back transaction cannot publish
an applied decision. Mandatory campaign plan/result signatures use the separate
job-signing mechanism and do not depend on this audit setting.

Publication fsyncs `logging.base_path/workflows/audit.jsonl`, dispatches configured
sinks and ingests the configured SQL index. It clears the pending key only after
success. The event ID/payload remain stable across retry; concurrent publishers
can duplicate JSONL delivery but the SQL index deduplicates identical event IDs.
It never repeats the access mutation or remote command to retry delivery.

The jobs worker retries pending publication on each poll; governance/campaign
operations and timeline reads also trigger bounded publication. An installation
without a running worker should invoke the trusted maintenance command regularly:

```bash
python3 scripts/isolate-audit-index.py publish
```

This command processes up to 1000 pending events, reports failures and exits
nonzero when delivery remains unavailable. Configure monitoring for its results
and apply an operator-reviewed retention policy to retained workflow evidence.
Publication failure preserves a committed operation and its outbox; retry the
publication, not the access action. Existing Redis backups now include governance,
campaign and workflow namespaces; SQL recovery retains the existing epoch fences.

Tests cover scope before joins/pagination, identifier injection, historical
timestamp gaps, HTML escaping, transactional rollback, unavailable sinks,
concurrent publication and retained-source tampering. The real HTTPS Keycloak /
PostgreSQL / OpenSSH integration includes staged runbooks, signed worker receipts,
scoped timeline and live offboarding. Browser checks exercise explanation,
impact preview, owner review, canary confirmation/cancellation and investigation.
