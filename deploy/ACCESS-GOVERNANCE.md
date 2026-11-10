# Access lifecycle and owner reviews

The access-lifecycle workspace at `/workspace/governance` supports owner reviews,
time-limited contractor/temporary assignments, due reminders, review candidates
and durable offboarding. It uses the same authenticated OIDC subject and SQL or
Redis-shaped authority as the rest of the product. No separate scheduler database
or external identity directory is required.

## Roles and scope

Reading lifecycle information requires current `access.read` for the exact
project. Mutation requires both `access.approve` and `inventory.write`, as supplied
by the existing `project-owner` role, or platform administration. An approver,
auditor or inventory operator alone cannot create assignments or offboard users.
Service identities cannot act as lifecycle reviewers. Global offboarding
(`project: '*'`) requires a human platform administrator.

The workspace and API filter project data before returning records. Project
owners cannot inspect another project's assignments, reviews or candidate rules.
Subject identifiers are the **provider-bound internal `keycloak_sub` identity**,
including the generic OIDC provider binding when applicable; editable usernames
are only display labels. Use the identity returned by the signed control API or
existing trusted records. Do not enter an unverified username as a subject ID.

## Periodic reviews

Start a review for an exact project with a reason and a due date. The default due
date is 14 days; the maximum is 90 days. The creating owner is the default assigned
reviewer; API callers may explicitly assign another stable owner subject. That
person must still have current owner permissions when deciding. A platform
administrator can reconcile a review whose owner is no longer available.

A review snapshots grant IDs and revisions, including matching broad/managed
rules. Up to 1000 rules may be included in one review. For each item:

- **Keep** records a business decision without extending or recreating the grant.
- **Revoke** retains a precedence-bearing denial rule, avoiding accidental access
  through a broader fallback. The configured normal protocol actions are removed.
- **Confirm externally removed** is valid only when the original grant is absent.

Review revocation preserves the original rule's expiry. It does not permanently
deny independent or future assignments; use offboarding for that subject-wide
boundary.

A changed grant returns a conflict and needs a fresh review. A person cannot
confirm their own stable-bound direct user rule. Owners can revoke only exact
project rules; broader selectors require platform administration. Managed/GitOps
grants require remediation through their original owner and are not rewritten by
the review API. Remove or change those rules in the policy source, reconcile it,
and record the appropriate new review.

When every item is decided, the next review due date defaults to 90 days after
completion. Set `governance.review_interval_days` (integer 1–365) to change it.
Open overdue reviews, projects without a completed review and upcoming periodic
reviews are visible in the workspace/API. **Reminders are evaluated on reads;
the product does not silently send email or create an external scheduled task.**
Owners start the next campaign explicitly. Empty reviews contain no decisions;
they do not certify grants that may be introduced later.

## Contractor and temporary assignments

Assignments bind an exact project, immutable target subject, display username,
non-root target account, explicitly chosen connection actions and start/expiry.
They always use `sudo_mode: none`, cannot target the acting owner, and expire
within 90 days. Supported actions cover SSH/Web SSH, SFTP/SCP, HTTP, databases,
Kubernetes and its individual stream operations. They do not grant arbitrary
command/job administration. Select the smallest suitable account and actions.

The generated direct-user grant uses existing policy time-window checks, so
expiry works even without a background cleanup job. Assignment expiry/revocation
does not remove independently granted group/role access. Use offboarding to deny
the subject across those other grants. Upcoming expiry within seven days is
shown in reminders; it does not automatically renew the assignment.

Creation requires an `Idempotency-Key`; concurrent retries create one assignment
and one linked grant. Revocation checks ownership and the exact grant revision.
An independently edited/replaced grant returns a conflict requiring reconciliation
instead of deleting someone else's policy. A new owner review can assess it.

## Excess privilege candidates

Findings identify concrete review prompts such as no expiry, privileged accounts,
broad project selectors and username-only user bindings. They are **candidates**,
not proof that access is unused or unnecessary. The product does not infer live
group membership from past sessions, claim to know every directory user, or
automatically remove permissions based on these heuristics.

## Offboarding

Offboarding writes a permanent exact-project or global deny marker for the
stable subject. Common identity/authorization and live recheck boundaries enforce
it for new and existing protocol sessions and delegated work. Renaming a user,
renewing their token, restoring a group grant or reconciling GitOps policy does
not remove that deny marker. A project marker affects that project's access;
a global marker also prevents use of the control identity.

Missing markers preserve normal policy behavior. Malformed markers, mismatched
subject/scope records and unavailable evidence fail closed. The marker has no
TTL and no UI enable switch that can silently reactivate access. This interface
does not provide a one-click reboarding action: restoring access requires an
independently reviewed operational process and audit evidence.

Offboarding does **not** delete/disable an IdP account or remove group membership
in Keycloak/another provider. The resulting record reminds the operator to
complete directory offboarding and reconcile externally managed grants. It
does not rewrite broad group rules that may still be needed by other employees.
Historical review, assignment, session and audit records remain available under
their ordinary scoped audit permissions and retention controls.

## API and evidence

All mutations require JSON `confirm: true`, a reason and a current verified
human identity. Browser API mutations additionally require `X-CSRF-Token`.
Browser forms use signed-session CSRF and explicit confirmation. Main routes:

| Method / route | Action |
| --- | --- |
| `GET /api/v1/governance?project=stage` | Scoped reviews, assignments, reminders, findings and offboarding |
| `POST /api/v1/governance/reviews` | Create a revision-frozen owner review; `Idempotency-Key` required |
| `POST /api/v1/governance/reviews/{review_id}/decisions` | Decide one grant item |
| `POST /api/v1/governance/assignments` | Create a subject-bound expiring assignment; `Idempotency-Key` required |
| `POST /api/v1/governance/assignments/{assignment_id}/revoke` | Revoke its unchanged linked rule |
| `POST /api/v1/governance/offboarding` | Permanently deny a subject in the exact project or globally |

The OpenAPI document contains field schemas and response envelopes. Domain
changes, retained governance/workflow events and pending publication
records commit in the same authoritative transaction. Events correlate explicit
review/assignment/offboarding/grant IDs, the actor and target subject. Private
free-text reasons remain in scoped lifecycle records and are excluded from the
timeline event payload.

Workflow audit signatures require `logging.integrity.enabled` and its protected
key, as described in [INVESTIGATIONS.md](INVESTIGATIONS.md). Without that option,
events remain transactionally retained but are unsigned.

The shared workflow publisher appends local durable audit JSONL, configured
sinks and optional SQL index after commit. A failed publication remains pending
and is retried without repeating the access mutation. Consumers deduplicate the
stable event ID. A rolled-back WATCH attempt has no committed event/outbox.
Retained source records remain evidence even while a sink is unavailable.
