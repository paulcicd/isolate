# Access explanations and policy impact preview

Access explanations are read-only snapshots of the current caller's permissions.
They never mint a ticket, consume an approval, open an upstream connection or
replace authorization when an operation starts. Signed OIDC identity, live
lifecycle controls and the existing grant resolver remain authoritative.

## Employee and administrator diagnostics

The resource, terminal and workspace surfaces link to **Why this access?**.
The expanded panel lazily fetches the current explanation and shows the selected
rule, a reason, required steps and a next action. The standalone page is
`/workspace/access/<host-id>?protocol=ssh`; API clients use:

```text
GET /api/v1/access/explain/10042?protocol=kubernetes&action=kubernetes-exec
Authorization: Bearer <private-token>
```

`protocol` defaults to `ssh` and accepts `ssh`, `webssh`, `http`, `kubernetes`,
`postgresql` and `mysql`. Optional `action` asks about a specific operation such
as `sftp`, `forward`, `kubernetes-exec`, `command` or `runbook`. The result
distinguishes the policy decision from runtime requirements: missing action,
remote identity, maintenance, service/target configuration, lifecycle restriction,
MFA/step-up and separate session approval. Operation-specific namespace, forwarding
destination, command parameters and submission checks still apply when it starts.

The resolver first selects the most specific active matching rule and then
checks its allowed actions. An omitted action is denied even if a lower-priority
rule permits it. Explanations preserve this behavior; actions from separate rules
are never combined. Future or expired assignments are not treated as active.

A caller may inspect a resource only through its own active matching assignment
or project-scoped `inventory.read` permission. Unknown and hidden resources have
the same 404 response. Caller parameters cannot simulate another identity.
Employee responses omit grant subject/selector details; administrator responses
may show sanitized policy fields. Inventory passwords, upstream credentials,
secret paths, raw claims and tokens are excluded. Project offboarding exposes a
safe lifecycle reason without private HR/operator notes. Responses use
`Cache-Control: no-store`, and HTML/JavaScript render untrusted values as text.

## Previewing an assignment change

Human platform administrators can open `/policy/impact`, or use
`/policy/impact?grant_id=123` from a current assignment. The form supports:

1. Adding a proposed assignment.
2. Replacing an existing assignment with a full or partial JSON object.
3. Previewing removal of an existing assignment.

Optional exact-project filtering narrows the result. The table shows gained,
lost and changed policy decisions, principal scenarios, actions, resources,
before/after identities and selected rules. Expiry changes are included. A
replacement retains the original position for equal-priority rules, matching
the real resolver's tie behavior. Previewing does not save or remove anything;
perform the separately authorized policy edit only after review.

The corresponding API is:

```text
POST /api/v1/admin/policy/impact
Authorization: Bearer <private-token>
Content-Type: application/json

{
  "replace_grant_id": "123",
  "grant": {"allowed_actions": ["ssh", "sftp"]},
  "project": "stage",
  "max_entries": 500
}
```

To preview deletion, supply `replace_grant_id` and `"remove": true` instead of
`grant`. The bearer caller needs a platform-administrator role and explicit
`isolate.policy.write` scope. Browser callers use the signed session and CSRF.
Workload identities cannot enumerate this human administrative preview.

## Interpreting coverage

Group and role rows model **policy principals**, not a complete list of people
in the IdP. An explicit stable-subject user assignment is evaluated with that
subject binding. Combined group memberships and current IdP membership require
separate review. Counts describe policy scenarios; they are not a claim that all
affected humans have been enumerated or that runtime MFA, lifecycle, approvals
and target requirements will pass. The response states this coverage explicitly.

Output is limited to 1–1000 rows (500 by default), with complete counts for the
evaluated snapshot and a truncation flag. Inventory, rule and estimated work
limits reject excessively large previews instead of tying up the control API.
Use an exact-project filter to inspect a smaller change. The source policy is
not locked while the preview is computed: re-evaluate after concurrent changes
and use normal revision-checked mutations when saving.

Focused verification in `tests/test_access_explain.py` covers signed identities,
scoped visibility, selected-rule precedence, lifecycle/MFA/approval diagnostics,
no session capability creation, secret redaction, bound subjects, expiry impact,
equal-priority replacement order, bounded results, bearer scopes, browser CSRF,
safe HTML and preview-without-apply behavior.
