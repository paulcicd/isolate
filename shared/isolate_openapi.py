"""Central, deliberately explicit OpenAPI contract for the control listener.

Flask's registered routes are the source of truth for operation coverage.  A new
API route must receive a real contract here; silently manufacturing a generic
operation would hide contract drift.  Browser pages and the separate streaming
protocol listeners are not JSON control API operations.
"""

import copy
import re


HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
PUBLIC_PATHS = frozenset({"/health", "/ready", "/auth/backchannel-logout"})
BEARER = [{"BearerAuth": []}]
BROWSER = [{"BearerAuth": []}, {"BrowserSession": []}]
MUTATION = [{"BearerAuth": []}, {"BrowserSession": [], "CSRFToken": []}]


def ref(name):
    return {"$ref": "#/components/schemas/" + name}


def obj(properties=None, required=(), **extra):
    value = {"type": "object", "properties": properties or {}}
    if required:
        value["required"] = list(required)
    value.update(extra)
    return value


def array(items):
    return {"type": "array", "items": items}


STRING = {"type": "string"}
BOOLEAN = {"type": "boolean"}
INTEGER = {"type": "integer"}
NUMERIC_ID = {"type": "string", "pattern": "^[0-9]{1,20}$"}
REVISION = {"type": "string", "pattern": "^[a-f0-9]{64}$", "readOnly": True}
PROTOCOL = {"type": "string", "enum": ["ssh", "webssh", "http", "kubernetes", "postgresql", "mysql"]}
NEXT_OFFSET = {"type": ["integer", "null"], "minimum": 0}


def schemas():
    terminal = obj({
        "font_size": {"type": "integer", "minimum": 10, "maximum": 24},
        "font_family": {"type": "string", "enum": ["monospace", "ui-monospace", "Menlo", "Consolas"]},
        "theme": {"type": "string", "enum": ["dark", "light"]},
        "scrollback": {"type": "integer", "minimum": 1000, "maximum": 20000},
        "paste_threshold": {"type": "integer", "minimum": 100, "maximum": 10000},
    }, additionalProperties=False)
    host_fields = {
        "project_name": STRING, "server_name": STRING, "server_ip": STRING,
        "server_user": STRING, "server_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "server_nosudo": BOOLEAN, "server_note": STRING, "server_services": STRING,
        "proxy_id": {"type": ["string", "null"], "description": "Existing inventory jump host ID, or empty/null for none."},
        "resource_owner": STRING, "environment": STRING,
        "tags": {"type": "object", "additionalProperties": STRING},
    }
    grant_fields = {
        "subject": {"type": "string", "enum": ["user", "group", "role", "service"]},
        "name": STRING, "project": STRING, "remote_user": STRING,
        "sudo_mode": {"type": "string", "enum": ["none", "sudo-i"]},
        "allowed_actions": {"type": "array", "items": STRING, "minItems": 1, "uniqueItems": True},
        "host": STRING, "keycloak_sub": {"type": "string", "description": "Compatibility field for an optional stable user subject binding."},
    }
    definitions = {
        "Error": obj({"error": STRING, "message": STRING, "retry_after": {"type": "number"},
            "acr_values": STRING, "max_age": INTEGER, "reauthenticate_url": STRING}, additionalProperties=True),
        "Identity": obj({"keycloak_sub": STRING, "subject": STRING, "issuer": STRING,
            "username": STRING, "email": {"type": ["string", "null"]},
            "groups": array(STRING), "roles": array(STRING), "exp": INTEGER}),
        "HostInput": obj(host_fields, additionalProperties=False),
        "Host": obj(dict(host_fields, server_id=NUMERIC_ID, _revision=REVISION), ["server_id", "_revision"]),
        "GrantInput": obj(grant_fields, additionalProperties=False),
        "Grant": obj(dict(grant_fields, id=NUMERIC_ID, _revision=REVISION), ["id", "_revision"]),
        "Resource": obj({"host_id": NUMERIC_ID, "server_id": NUMERIC_ID, "server_name": STRING,
            "project_name": STRING}, additionalProperties=True),
        "WorkspaceResource": obj({"resource_id": STRING, "host_id": NUMERIC_ID, "name": STRING,
            "project": STRING, "protocol": PROTOCOL, "owner": STRING, "environment": STRING,
            "tags": {"type": "object", "additionalProperties": STRING},
            "access": obj({"state": STRING, "reason": STRING, "next_action": STRING, "url": STRING}),
            "connect_url": {"type": ["string", "null"]}, "details_url": STRING}, additionalProperties=True),
        "ConnectionRequest": obj({"host_id": NUMERIC_ID, "protocol": PROTOCOL}, ["host_id"], additionalProperties=False),
        "Connection": obj({"ticket": {"type": "string", "description": "Secret, short-lived, single-use credential. Never log or persist."},
            "connection_id": STRING, "expires_at": {"type": "number"}, "host_id": NUMERIC_ID,
            "protocol": PROTOCOL, "approval_required": BOOLEAN, "gateway_host": STRING,
            "gateway_port": INTEGER, "websocket_url": STRING, "audit_profile": STRING},
            ["ticket", "connection_id", "expires_at", "host_id", "protocol"]),
        "JobRequest": obj({"type": {"type": "string", "enum": ["command", "runbook"]},
            "host_id": NUMERIC_ID, "command": STRING, "runbook_id": STRING,
            "parameters": obj(additionalProperties=True), "timeout": {"type": "integer", "minimum": 1},
            "confirm": {"const": True}}, ["type", "host_id", "confirm"], additionalProperties=False),
        "Job": obj({"job_id": STRING, "id": STRING, "status": STRING}, additionalProperties=True),
        "TerminalPreferences": terminal,
        "Preferences": obj({"favorites": array(STRING), "recent": array(STRING), "terminal": ref("TerminalPreferences")},
            ["favorites", "recent", "terminal"]),
        "PreferencesPatch": obj({"favorites": array(STRING), "terminal": ref("TerminalPreferences")}, additionalProperties=False),
        "BookmarkInput": obj({"seconds": {"type": "number", "minimum": 0, "maximum": 604800},
            "label": {"type": "string", "minLength": 1, "maxLength": 160}}, ["seconds", "label"], additionalProperties=False),
        "Bookmark": obj({"id": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
            "seconds": {"type": "number"}, "label": STRING, "created_at": {"type": "number"}},
            ["id", "seconds", "label", "created_at"]),
        "Bookmarks": obj({"bookmarks": array(ref("Bookmark"))}, ["bookmarks"]),
        "AuditPage": obj({"events": array(obj(additionalProperties=True)),
            "next": {"description": "Opaque JSON cursor; send its JSON encoding as before.", "type": ["array", "null"], "items": {}}},
            ["events", "next"]),
        "Health": obj({"ok": BOOLEAN, "status": STRING,
            "checks": {"type": "object", "additionalProperties": obj({"ok": BOOLEAN}, ["ok"])}}, ["ok", "checks"]),
        "Ready": obj({"ready": BOOLEAN}, ["ready"]),
        "Version": obj({"schema_version": INTEGER, "version": STRING, "revision": {"type": ["string", "null"]}}, additionalProperties=True),
        "Confirmation": obj({"confirm": {"const": True}}, ["confirm"], additionalProperties=False),
    }
    definitions.update(lifecycle_schemas())
    return definitions


def lifecycle_schemas():
    identifier = {"type": "string", "pattern": "^[a-f0-9]{32}$"}
    subject = {"type": "string", "minLength": 1, "maxLength": 1024,
        "description": "Immutable provider-bound internal keycloak_sub, never an editable username."}
    project = {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,47}$"}
    reason = {"type": "string", "minLength": 3, "maxLength": 2048}
    nullable_time = {"type": ["integer", "null"]}
    confirm = {"const": True}
    grant_view = obj({"grant_id": NUMERIC_ID, "revision": REVISION, "subject": STRING, "name": STRING,
        "keycloak_sub": subject, "remote_user": STRING, "sudo_mode": STRING, "allowed_actions": array(STRING),
        "starts_at": nullable_time, "expires_at": nullable_time, "temporary": BOOLEAN, "managed_by": STRING,
        "exact_project": BOOLEAN, "decision": {"type": ["string", "null"], "enum": ["keep", "revoke", "removed", None]},
        "decided_at": INTEGER, "decided_by": subject, "reason": reason}, ["grant_id", "revision", "exact_project"])
    review = obj({"schema_version": {"const": 1}, "id": identifier, "project": project, "owner_subject": subject,
        "created_by": subject, "created_at": INTEGER, "due_at": INTEGER, "reason": reason,
        "status": {"type": "string", "enum": ["open", "completed"]}, "completed_at": INTEGER,
        "items": array(ref("ReviewGrant"))}, ["id", "project", "owner_subject", "due_at", "status", "items"])
    actions = {"type": "array", "minItems": 1, "uniqueItems": True, "items": {"type": "string", "enum": [
        "ssh", "webssh", "http", "postgresql", "mysql", "kubernetes", "kubernetes-exec", "kubernetes-attach",
        "kubernetes-logs", "kubernetes-watch", "kubernetes-portforward", "sftp", "scp"]}}
    assignment_fields = {"project": project, "subject_id": subject,
        "username": {"type": "string", "pattern": "^[A-Za-z0-9_.@-]{1,128}$"},
        "remote_user": {"type": "string", "pattern": "^[a-z_][a-z0-9_-]{0,31}$", "not": {"const": "root"}},
        "expires_at": {"type": "integer", "description": "Future Unix seconds, within 90 days of creation and after starts_at."},
        "starts_at": {"type": ["integer", "null"], "description": "Unix seconds; omitted/null means now."},
        "allowed_actions": actions, "category": {"type": "string", "enum": ["contractor", "temporary"], "default": "contractor"},
        "reason": reason}
    assignment = obj(dict(assignment_fields, id=identifier, grant_id=NUMERIC_ID, grant_revision=REVISION,
        owner_subject=subject, created_at=INTEGER, schema_version={"const": 1},
        status={"type": "string", "enum": ["active", "revoked"]},
        effective_status={"type": "string", "enum": ["scheduled", "active", "expired"]},
        revoked_at=INTEGER, revoked_by=subject, revoke_reason=reason),
        ["id", "project", "subject_id", "grant_id", "expires_at", "status"])
    offboard = obj({"schema_version": {"const": 1}, "id": identifier, "subject_id": subject,
        "project": {"oneOf": [project, {"const": "*"}]}, "status": {"const": "blocked"},
        "created_at": INTEGER, "created_by": subject, "reason": reason, "next_step": STRING},
        ["id", "subject_id", "project", "status", "created_at", "next_step"])
    delivery = obj({"status": {"const": "retained"}, "publication": {"const": "retryable_outbox"}},
        ["status", "publication"], additionalProperties=False)
    selected = obj({"id": STRING, "temporary": BOOLEAN, "starts_at": nullable_time, "expires_at": nullable_time,
        "specificity": INTEGER, "precedence": STRING, "allowed_actions": array(STRING)}, additionalProperties=True)
    policy = obj({"allowed": BOOLEAN, "reason_code": STRING, "missing_actions": array(STRING),
        "selected_grant": {"oneOf": [selected, {"type": "null"}]}, "precedence_note": STRING,
        "remote_user": STRING, "sudo_mode": STRING}, ["allowed", "reason_code", "missing_actions", "selected_grant", "precedence_note"])
    campaign_fields = {"runbook_id": {"type": "string", "minLength": 1},
        "host_ids": {"type": "array", "minItems": 1, "uniqueItems": True, "maxItems": 1000,
            "items": {"oneOf": [NUMERIC_ID, {"type": "integer", "minimum": 0}]}},
        "parameters": obj(additionalProperties=True), "timeout": {"type": "integer", "minimum": 1},
        "canary_count": {"type": "integer", "minimum": 1, "maximum": 10, "default": 1},
        "batch_size": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5},
        "failure_budget": {"type": "integer", "minimum": 0, "default": 0},
        "max_failure_percent": {"type": "integer", "minimum": 0, "maximum": 100, "default": 100}}
    return {
        "AccessPolicyExplanation": policy,
        "AccessExplanation": obj({"resource": obj({"host_id": NUMERIC_ID, "name": STRING, "project": STRING, "protocol": PROTOCOL}, ["host_id", "name", "project", "protocol"]),
            "action": STRING, "policy": ref("AccessPolicyExplanation"), "state": STRING,
            "checks": array(obj({"code": STRING, "status": {"type": "string", "enum": ["passed", "failed", "required"]}, "message": STRING}, ["code", "status", "message"])),
            "evaluated_at": {"type": "number"}, "snapshot_only": {"const": True},
            "next_action": {"oneOf": [obj({"label": STRING, "url": STRING}, ["label", "url"]), {"type": "null"}]},
            "summary": STRING, "notice": STRING}, ["resource", "action", "policy", "state", "checks", "evaluated_at", "snapshot_only", "next_action", "summary", "notice"]),
        "PolicyImpactGrantInput": obj({"subject": {"type": "string", "enum": ["user", "group", "role", "service"]},
            "name": STRING, "keycloak_sub": subject, "project": STRING, "project_glob": STRING, "project_set": STRING,
            "host": STRING, "remote_user": STRING, "sudo_mode": {"type": "string", "enum": ["none", "sudo-i"]},
            "allowed_actions": {"type": "array", "items": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"}},
            "starts_at": nullable_time, "expires_at": nullable_time}, additionalProperties=False),
        "PolicyImpactRequest": obj({"grant": ref("PolicyImpactGrantInput"), "replace_grant_id": NUMERIC_ID,
            "remove": {"type": "boolean", "default": False}, "project": project,
            "max_entries": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 500}},
            additionalProperties=False, oneOf=[{"required": ["grant"], "properties": {"remove": {"const": False}}},
                {"required": ["replace_grant_id", "remove"], "properties": {"remove": {"const": True}}}]),
        "PolicyImpact": obj({"counts": obj({"gained": INTEGER, "lost": INTEGER, "changed": INTEGER}, ["gained", "lost", "changed"]),
            "impacts": array(obj({"change": {"type": "string", "enum": ["gained", "lost", "changed"]}, "subject": STRING, "name": STRING, "subject_id": {"type": ["string", "null"]},
                "host_id": NUMERIC_ID, "resource_name": STRING, "project": STRING, "action": STRING,
                "before": ref("AccessPolicyExplanation"), "after": ref("AccessPolicyExplanation")}, ["change", "host_id", "project", "action", "before", "after"])),
            "truncated": BOOLEAN, "evaluated_hosts": INTEGER, "evaluated_scenarios": INTEGER, "evaluated_actions": INTEGER,
            "coverage": {"const": "grant-principal-scenarios"}, "snapshot_only": {"const": True},
            "evaluated_at": {"type": "number"}, "evaluation_scope": STRING, "membership_notice": STRING, "candidate_sha256": REVISION},
            ["counts", "impacts", "truncated", "evaluated_hosts", "evaluated_scenarios", "evaluated_actions", "coverage", "snapshot_only", "evaluated_at", "evaluation_scope", "membership_notice", "candidate_sha256"]),
        "ReviewGrant": grant_view, "AccessReview": review, "AccessAssignment": assignment, "Offboarding": offboard,
        "AuditDelivery": delivery,
        "ReviewCreateRequest": obj({"project": project, "reason": reason, "owner_subject": subject,
            "due_at": {"type": ["integer", "null"], "description": "Future Unix seconds within 90 days; omitted/null defaults to 14 days."}, "confirm": confirm},
            ["project", "reason", "confirm"], additionalProperties=False),
        "ReviewDecisionRequest": obj({"grant_id": NUMERIC_ID, "decision": {"type": "string", "enum": ["keep", "revoke", "removed"]},
            "reason": reason, "confirm": confirm}, ["grant_id", "decision", "reason", "confirm"], additionalProperties=False),
        "AssignmentCreateRequest": obj(dict(assignment_fields, confirm=confirm),
            ["project", "subject_id", "username", "remote_user", "expires_at", "reason", "confirm"], additionalProperties=False),
        "GovernanceReasonRequest": obj({"reason": reason, "confirm": confirm}, ["reason", "confirm"], additionalProperties=False),
        "OffboardingRequest": obj({"subject_id": subject, "project": {"oneOf": [project, {"const": "*"}]}, "reason": reason, "confirm": confirm},
            ["subject_id", "project", "reason", "confirm"], additionalProperties=False),
        "GovernanceDashboard": obj({"projects": array(project), "reviews": array(ref("AccessReview")), "assignments": array(ref("AccessAssignment")),
            "offboardings": array(ref("Offboarding")),
            "review_schedule": array(obj({"project": project, "last_completed_at": nullable_time, "next_due_at": INTEGER,
                "review_id": {"type": ["string", "null"]}}, ["project", "last_completed_at", "next_due_at", "review_id"])),
            "reminders": array(obj({"kind": {"type": "string", "enum": ["assignment_expiring", "review_overdue", "periodic_review_due"]},
                "project": project, "due_at": INTEGER, "review_id": identifier, "assignment_id": identifier, "subject_id": subject}, ["kind", "project", "due_at"])),
            "findings": array(obj({"grant_id": NUMERIC_ID, "project": project, "reasons": array(STRING),
                "assessment": {"const": "review_candidate_not_proof_of_excess_access"}}, ["grant_id", "project", "reasons", "assessment"], additionalProperties=True)),
            "generated_at": INTEGER}, ["projects", "reviews", "assignments", "offboardings", "review_schedule", "reminders", "findings", "generated_at"]),
        "CampaignPreviewRequest": obj(campaign_fields, ["runbook_id", "host_ids"], additionalProperties=False),
        "CampaignCreateRequest": obj(dict(campaign_fields, preview_digest={"type": "string", "pattern": "^[a-f0-9]{64}$"}, confirm=confirm),
            ["runbook_id", "host_ids", "preview_digest", "confirm"], additionalProperties=False),
        "CampaignPreview": obj({"preview_digest": REVISION, "runbook_id": STRING, "runbook_title": STRING,
            "canary_count": INTEGER, "batch_size": INTEGER, "failure_budget": INTEGER, "max_failure_percent": INTEGER,
            "targets": array(obj({"id": NUMERIC_ID, "name": STRING, "project": STRING, "remote_user": STRING, "sudo_mode": STRING}, ["id", "name", "project", "remote_user", "sudo_mode"])),
            "stop_on_unknown": {"const": True}, "automatic_retries": {"const": False}},
            ["preview_digest", "runbook_id", "runbook_title", "canary_count", "batch_size", "failure_budget", "max_failure_percent", "targets", "stop_on_unknown", "automatic_retries"]),
        "RunbookCampaign": obj({"id": identifier, "subject": subject, "username": STRING, "projects": array(STRING),
            "runbook_id": STRING, "created_at": INTEGER, "expires_at": INTEGER, "updated_at": {"type": ["integer", "null"]},
            "status": {"type": "string", "enum": ["active", "completed", "stopped", "cancelled", "recovery_required"]},
            "stop_reason": {"type": ["string", "null"]}, "current_stage": INTEGER, "failure_budget": INTEGER, "max_failure_percent": INTEGER,
            "events": array(obj(additionalProperties=True)),
            "stages": array(obj({"index": INTEGER, "kind": {"type": "string", "enum": ["canary", "batch"]}, "job_ids": array(NUMERIC_ID)}, ["index", "kind", "job_ids"])),
            "jobs": array(obj({"id": NUMERIC_ID, "host_id": NUMERIC_ID, "project": STRING, "stage": INTEGER, "slot": INTEGER,
                "status": STRING, "exit_code": {"type": ["integer", "null"]}, "cancel_requested": BOOLEAN}, ["id", "host_id", "project", "stage", "slot", "status"]))},
            ["id", "subject", "projects", "runbook_id", "status", "current_stage", "stages", "jobs"]),
    }


def response(description, schema=None, media="application/json"):
    value = {"description": description}
    if schema is not None:
        value["content"] = {media: {"schema": schema}}
    return value


def query(name, schema=STRING, description=None):
    value = {"name": name, "in": "query", "required": False, "schema": schema}
    if description:
        value["description"] = description
    return value


def body(schema, maximum=None):
    value = {"required": True, "content": {"application/json": {"schema": schema}}}
    if maximum:
        value["description"] = "JSON object; maximum {} bytes.".format(maximum)
        value["x-max-body-bytes"] = maximum
    return value


def operation(name, summary, schema=None, *, security=BEARER, parameters=(), request_body=None,
              success="200", description="", errors=(400, 401, 403, 404, 503)):
    value = {"operationId": name, "summary": summary, "description": description,
        "security": security, "responses": {success: response("Success", schema)}}
    for status in errors:
        value["responses"][str(status)] = {"$ref": "#/components/responses/Error"}
    if parameters:
        value["parameters"] = list(parameters)
    if request_body:
        value["requestBody"] = request_body
    return value


def catalogue():
    paging = [query("q"), query("project"), query("offset", {"type": "integer", "minimum": 0}),
        query("limit", {"type": "integer", "minimum": 1, "maximum": 500, "default": 100})]
    history = [query(name) for name in ("query", "project", "host", "since", "until", "result", "limit")]
    audit = [query(name) for name in ("q", "event", "host_id", "connection_id", "since", "until", "before", "limit")]
    paths = {
        "/api/v1/me": {"get": operation("getIdentity", "Inspect the verified bearer identity", ref("Identity"))},
        "/api/v1/resources": {"get": operation("listResources", "List authorized SSH resources",
            obj({"resources": array(ref("Resource")), "next_offset": NEXT_OFFSET}, ["resources", "next_offset"]), parameters=paging)},
        "/api/v1/connections": {"post": operation("createConnection", "Issue a single-use protocol connection ticket", ref("Connection"),
            security=MUTATION, request_body=body(ref("ConnectionRequest"), 4096), success="201",
            description="Rechecks protocol grants, admission, approval and step-up policy. Browser sessions require X-CSRF-Token. Tickets are credentials; do not put them in Terraform state.",
            errors=(400, 401, 403, 404, 413, 415, 429, 503))},
        "/api/v1/web-apps/{host_id}/launch": {"post": operation("launchWebApplication", "Issue an isolated-origin application launch code",
            obj({"launch_url": STRING, "code": STRING, "expires_at": {"type": "number"}}, ["launch_url", "code", "expires_at"]),
            security=MUTATION, request_body=body(ref("Confirmation"), 1024), success="201",
            description="Requires the HTTP resource grant and enabled isolated application mode. POST the short-lived code to launch_url as a form body. Never put codes in URLs, logs or browser storage; browser mutations require CSRF.",
            errors=(400, 401, 403, 404, 413, 415, 429, 503))},
        "/api/v1/history": {"get": operation("getHistory", "Read the caller's connection history", obj({"history": array(obj(additionalProperties=True))}, ["history"]),
            parameters=history)},
        "/api/v1/jobs": {"post": operation("createJob", "Submit an explicitly confirmed command or runbook", ref("Job"),
            security=MUTATION, request_body=body(ref("JobRequest"), 65536), success="201", parameters=[{"$ref": "#/components/parameters/IdempotencyKey"}],
            description="Requires the configured submitter action and matching OAuth scope. Idempotent replay returns 200; conflicting or uncertain submissions return 409. Does not execute a shell on the API listener.",
            errors=(400, 401, 403, 404, 409, 413, 415, 429, 503))},
        "/api/v1/jobs/{job_id}": {"get": operation("getJob", "Read an owned job or a job visible to a platform administrator",
            obj({"job": ref("Job")}, ["job"]))},
        "/api/v1/audit": {"get": operation("searchAudit", "Search the scoped audit index", ref("AuditPage"), security=BROWSER,
            parameters=audit, description="The SQL index is derived from audit evidence; this API does not expose the control store. Disabled indexes return 404.")},
        "/api/v1/investigations/timeline": {"get": operation("getInvestigationTimeline", "Follow explicitly correlated evidence within current audit scope",
            obj({"events": array(obj(additionalProperties=True)), "next": {"type": ["array", "null"]}, "coverage": obj(additionalProperties=True),
                 "order": STRING, "page_direction": STRING, "correlation": STRING, "expansion_bounded": BOOLEAN, "evidence": STRING, "generated_at": {"type": "number"}},
                ["events", "next", "coverage", "order", "page_direction", "correlation", "expansion_bounded", "evidence", "generated_at"]), security=BROWSER,
            parameters=[query("kind", {"type": "string", "enum": ["connection", "request", "approval", "job", "campaign", "grant", "identity-session"]}),
                query("id", STRING), query("subject", STRING), query("project", STRING), query("host_id", STRING), query("since", {"type": "number"}),
                query("until", {"type": "number"}), query("before", STRING), query("limit", {"type": "integer", "minimum": 1, "maximum": 200}),
                query("related", BOOLEAN), query("q", STRING)], errors=(400, 401, 403, 404, 503),
            description="Visibility is applied before correlation and pagination. Events are chronological within each latest page; next selects earlier evidence. Correlation is bounded and never inferred from usernames. Missing stages remain explicitly unobserved.")},
        "/api/v1/workspace/preferences": {
            "get": operation("getPreferences", "Read preferences bound to the stable verified subject", ref("Preferences"), security=BROWSER),
            "patch": operation("updatePreferences", "Update favorites and terminal preferences", ref("Preferences"), security=MUTATION,
                request_body=body(ref("PreferencesPatch"), 16384), errors=(400, 401, 403, 404, 413, 415, 503))},
        "/api/v1/workspace/resources": {"get": operation("listWorkspaceResources", "List protocol resources and access guidance",
            obj({"resources": array(ref("WorkspaceResource")), "total": INTEGER, "next_offset": NEXT_OFFSET}, ["resources", "total", "next_offset"]),
            security=BROWSER, parameters=paging[:3] + [query("limit", {"type": "integer", "minimum": 1, "maximum": 100, "default": 48}),
                query("protocol", PROTOCOL), query("view", {"type": "string", "enum": ["all", "favorites", "recent"], "default": "all"})])},
        "/api/v1/recordings/{connection_id}/bookmarks": {
            "get": operation("listBookmarks", "Read subject-private recording bookmarks", ref("Bookmarks"), security=BROWSER,
                description="Recording ownership or project-scoped audit permission is checked on every request."),
            "post": operation("createBookmark", "Add a subject-private bookmark", ref("Bookmarks"), security=MUTATION,
                request_body=body(ref("BookmarkInput"), 2048), success="201", errors=(400, 401, 403, 404, 409, 413, 415, 503),
                description="At most 100 bookmarks per subject/recording. The audit intent is persisted before the mutation.")},
        "/api/v1/recordings/{connection_id}/bookmarks/{bookmark_id}": {
            "delete": operation("deleteBookmark", "Delete a subject-private recording bookmark", ref("Bookmarks"), security=MUTATION,
                errors=(400, 401, 403, 404, 409, 503))},
        "/auth/backchannel-logout": {"post": operation("backchannelLogout", "Receive a signed OIDC backchannel logout token", security=[],
            request_body={"required": True, "content": {"application/x-www-form-urlencoded": {"schema":
                obj({"logout_token": STRING}, ["logout_token"], additionalProperties=False)}}},
            description="Authenticates the IdP-signed logout_token, including issuer, audience, event and replay checks. No browser CSRF applies. Enabled only by explicit identity-security configuration; maximum 65536 bytes.",
            errors=(400, 404, 413, 503))},
        "/health": {"get": operation("getHealth", "Read reduced dependency health", ref("Health"), security=[], errors=(503,))},
        "/ready": {"get": operation("getReadiness", "Check control-store and cluster readiness", ref("Ready"), security=[], errors=(404, 503))},
        "/api/v1/version": {"get": operation("getVersion", "Read build and control schema versions", ref("Version"), security=[], errors=(404,))},
        "/api/v1/openapi.json": {"get": operation("getOpenAPIJSON", "Read this OpenAPI contract", obj(additionalProperties=True), security=[], errors=(404,))},
        "/api/v1/openapi.yaml": {"get": operation("getOpenAPIYAML", "Read this OpenAPI contract as YAML", STRING, security=[], errors=(404,))},
    }
    paths.update(lifecycle_operations())
    paths["/api/v1/jobs"]["post"]["responses"]["200"] = response("Previously completed submission with the same idempotency key", ref("Job"))
    paths["/api/v1/openapi.yaml"]["get"]["responses"]["200"] = response("OpenAPI YAML", STRING, "application/yaml")
    for kind, plural, scope in (("host", "hosts", "isolate.inventory.write"), ("grant", "grants", "isolate.policy.write")):
        title = kind.title()
        envelope = obj({kind: ref(title)}, [kind])
        input_envelope = obj({kind: ref(title + "Input"), "confirm": {"const": True}}, [kind, "confirm"], additionalProperties=False)
        description = ("Requires an explicitly authorized administrative identity and OAuth scope {}. "
            "Browser administrators require a CSRF header and confirm=true. Workload identities require explicit allowed_actions "
            "and admin_projects configuration; no human groups are inherited. Reads and mutations are constrained to administrative projects. "
            "Returned records omit SSH credentials. Broader grant selectors require explicit global administration.").format(scope)
        collection = "/api/v1/admin/" + plural
        paths[collection] = {
            "get": operation("listAdmin" + plural.title(), "List administratively visible " + plural,
                obj({plural: array(ref(title))}, [plural]), security=BROWSER, description=description),
            "post": operation("createAdmin" + title, "Create a confirmed " + kind, envelope, security=MUTATION, success="201",
                parameters=[{"$ref": "#/components/parameters/IdempotencyKey"}], request_body=body(input_envelope, 65536),
                description=description + " Idempotent replay returns 200; uncertain or conflicting create returns 409.",
                errors=(400, 401, 403, 404, 409, 413, 415, 429, 503)),
        }
        paths[collection]["post"]["responses"]["200"] = response("Previously completed idempotent create", envelope)
        paths[collection + "/{" + kind + "_id}"] = {
            "get": operation("getAdmin" + title, "Read a " + kind + " with its revision", envelope, security=BROWSER, description=description),
            "put": operation("updateAdmin" + title, "Update a confirmed " + kind + " at its current revision", envelope,
                security=MUTATION, parameters=[{"$ref": "#/components/parameters/IfMatch"}], request_body=body(input_envelope, 65536),
                description=description + " PUT accepts a partial record. Terraform sends the complete set of its managed fields. Missing If-Match returns 428; stale revision returns 409.",
                errors=(400, 401, 403, 404, 409, 413, 415, 428, 429, 503)),
            "delete": operation("deleteAdmin" + title, "Delete a confirmed " + kind + " at its current revision",
                security=MUTATION, success="204", parameters=[{"$ref": "#/components/parameters/IfMatch"}],
                request_body=body(ref("Confirmation"), 65536), description=description + " Missing If-Match returns 428; stale revision returns 409.",
                errors=(400, 401, 403, 404, 409, 413, 415, 428, 429, 503)),
        }
        for item in paths[collection].values():
            item["x-required-oauth-scopes"] = [scope]
        for item in paths[collection + "/{" + kind + "_id}"].values():
            item["x-required-oauth-scopes"] = [scope]
    for route, methods in paths.items():
        parameters = []
        for name in re.findall(r"\{([^}]+)\}", route):
            schema = (NUMERIC_ID if name in ("host_id", "grant_id", "job_id") else
                {"type": "string", "pattern": "^[a-f0-9]{32}$"} if name in ("review_id", "assignment_id", "identifier") else STRING)
            parameters.append({"name": name, "in": "path", "required": True, "schema": schema})
        for method in methods.values():
            method.setdefault("parameters", []).extend(parameters)
    return paths


def lifecycle_operations():
    mutation_errors = (400, 401, 403, 404, 409, 413, 415, 503)
    idempotency = [{"$ref": "#/components/parameters/IdempotencyKey"}]
    def governance_result(name):
        return obj({"result": ref(name), "audit_delivery": ref("AuditDelivery")}, ["result", "audit_delivery"])
    campaign_envelope = obj({"campaign": ref("RunbookCampaign")}, ["campaign"])
    paths = {
        "/api/v1/access/explain/{host_id}": {"get": operation("explainResourceAccess", "Explain current visible resource access without issuing a capability",
            ref("AccessExplanation"), security=BROWSER,
            parameters=[query("protocol", dict(PROTOCOL, default="ssh")),
                query("action", {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"}), query("lang", STRING)],
            description="Returns 200 for a visible allowed or denied resource. Hidden and unknown inventory both return 404. Reflects selected-rule precedence, missing actions and current runtime requirements. It does not consume approvals or mint tickets; every connection reauthorizes.")},
        "/api/v1/admin/policy/impact": {"post": operation("previewPolicyImpact", "Compare a candidate policy change with existing grant-principal scenarios",
            ref("PolicyImpact"), security=MUTATION, request_body=body(ref("PolicyImpactRequest"), 32768),
            description="Read-only preview, not a policy mutation. Requires a human platform administrator and isolate.policy.write bearer scope, or administrator browser plus CSRF. Supports add, partial replacement and removal. Group/role rows are scenarios, not a full IdP membership census; current MFA/lifecycle/target checks still apply.",
            errors=mutation_errors)},
        "/api/v1/governance": {"get": operation("getAccessLifecycle", "Read currently scoped reviews, assignments, due schedules and review candidates",
            ref("GovernanceDashboard"), security=BROWSER, parameters=[query("project", {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,47}$"})],
            description="Requires human access.read within every returned project. Findings are prompts for review, never automatic excess-access judgments. Reminders are read-time evaluation, not external scheduled notifications.")},
        "/api/v1/governance/reviews": {"post": operation("createAccessReview", "Snapshot project grants for an assigned owner's periodic review",
            governance_result("AccessReview"), security=MUTATION, parameters=idempotency, request_body=body(ref("ReviewCreateRequest"), 8192), success="201",
            description="Requires current project-owner permissions (access.approve plus inventory.write) or platform admin. Snapshots up to 1000 grant revisions. Keeping a grant never extends it. Reusing the same creation intent returns that review without another mutation.", errors=mutation_errors)},
        "/api/v1/governance/reviews/{review_id}/decisions": {"post": operation("decideAccessReview", "Record an owner decision against the snapshotted grant revision",
            governance_result("AccessReview"), security=MUTATION, request_body=body(ref("ReviewDecisionRequest"), 8192),
            description="Assigned owner must still have current project-owner permissions; platform admins may reconcile. Own stable-bound direct access cannot be kept by self-review. Changed grants return 409. Managed grants need external owner remediation; broader selectors require platform administration. Revoke retains a precedence-bearing denial rule.", errors=mutation_errors)},
        "/api/v1/governance/assignments": {"post": operation("createAccessAssignment", "Create a subject-bound nonprivileged contractor or temporary assignment",
            governance_result("AccessAssignment"), security=MUTATION, parameters=idempotency, request_body=body(ref("AssignmentCreateRequest"), 8192), success="201",
            description="Requires exact-project owner permissions. Expiry must be within 90 days and after starts_at. Cannot target the operator or root; sudo is always none. Existing independent group/role access is unaffected. A repeated identical creation intent returns the same assignment.", errors=mutation_errors)},
        "/api/v1/governance/assignments/{assignment_id}/revoke": {"post": operation("revokeAccessAssignment", "Revoke an unchanged linked temporary assignment rule",
            governance_result("AccessAssignment"), security=MUTATION, request_body=body(ref("GovernanceReasonRequest"), 8192),
            description="Rechecks current project-owner permissions and linked grant ownership/revision. Changed/replaced grants return a reconciliation conflict. Repeated revocation does not replay the mutation. Independent group grants require separate offboarding when all subject access must end.", errors=mutation_errors)},
        "/api/v1/governance/offboarding": {"post": operation("offboardAccessSubject", "Persist an exact-project or global stable-subject access denial",
            governance_result("Offboarding"), security=MUTATION, request_body=body(ref("OffboardingRequest"), 8192),
            description="Exact-project owners may end project access; only a human platform administrator may use project='*'. The deny overlay survives renamed users and reimported group/GitOps grants. It has no TTL or enable-switch bypass, and this API does not delete IdP accounts or offer blind reboarding. Self-offboarding requires a different operator.", errors=mutation_errors)},
        "/api/v1/runbook-campaigns/preview": {"post": operation("previewRunbookCampaign", "Review targets and bounded canary/batch stop conditions before submission",
            ref("CampaignPreview"), security=MUTATION, request_body=body(ref("CampaignPreviewRequest"), 65536),
            description="Does not execute jobs. Requires enabled campaigns and bounded job delegation, current runbook submitter groups/OAuth scopes and all target grants. Preview digest binds definition, parameters, selected identities, routes, epoch and stop conditions. Configured target/batch limits may be smaller than schema maxima.", errors=mutation_errors)},
        "/api/v1/runbook-campaigns": {
            "get": operation("listRunbookCampaigns", "List campaigns owned by the current identity or visible to platform administration",
                obj({"campaigns": array(ref("RunbookCampaign"))}, ["campaigns"]), security=BROWSER,
                parameters=[query("limit", {"type": "integer", "minimum": 1, "maximum": 100, "default": 50})]),
            "post": operation("createRunbookCampaign", "Start a reviewed canary and hold later runbook batches",
                campaign_envelope, security=MUTATION, parameters=idempotency, request_body=body(ref("CampaignCreateRequest"), 65536), success="201",
                description="Requires confirm=true, an unchanged fresh preview_digest and an idempotency key. Only the canary is queued initially. Canary failures, unknown/recovery outcomes, revoked/expired authorization and configured failure thresholds prevent expansion. No automatic retries; idempotent replay returns 200.", errors=(400, 401, 403, 404, 409, 413, 415, 429, 503))},
        "/api/v1/runbook-campaigns/{identifier}": {"get": operation("getRunbookCampaign", "Read an owned campaign and its child job/stage states",
            campaign_envelope, security=BROWSER, description="Unknown and not-owned campaigns both return 404 unless current platform administration permits visibility.")},
        "/api/v1/runbook-campaigns/{identifier}/cancel": {"post": operation("cancelRunbookCampaign", "Stop future batches and request cancellation of active child jobs",
            campaign_envelope, security=MUTATION, request_body=body(ref("Confirmation"), 1024),
            description="Requires ownership or platform administration and confirm=true. Cancellation is a request; already completed remote side effects are not rolled back and unknown outcomes are not retried.", errors=mutation_errors)},
    }
    paths["/api/v1/admin/policy/impact"]["post"]["x-required-oauth-scopes"] = ["isolate.policy.write"]
    paths["/api/v1/runbook-campaigns"]["post"]["responses"]["200"] = response("Previously completed identical campaign submission", campaign_envelope)
    return paths


def registered_operations(app):
    """Return only actual HTTP control operations, excluding implicit HEAD/OPTIONS."""
    operations = set()
    for rule in app.url_map.iter_rules():
        if not (rule.rule.startswith("/api/") or rule.rule in PUBLIC_PATHS):
            continue
        path = re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", r"{\1}", rule.rule)
        operations.update((path, method.lower()) for method in rule.methods if method.lower() in HTTP_METHODS)
    return operations


def undocumented_operations(app):
    documented = {(path, method) for path, operations in catalogue().items() for method in operations}
    return sorted(registered_operations(app) - documented)


def build_openapi(app=None):
    paths = catalogue()
    if app is not None:
        missing = undocumented_operations(app)
        if missing:
            raise ValueError("OpenAPI contract missing registered operations: " + repr(missing))
        active = registered_operations(app)
        paths = {path: {method: value for method, value in operations.items() if (path, method) in active}
                 for path, operations in paths.items() if any((path, method) in active for method in operations)}
    document = {
        "openapi": "3.1.1",
        "info": {"title": "Isolate Control API", "version": "1.0.0", "description":
            "Versioned control-plane API. The configured SQL or legacy Redis control store remains private. "
            "Use verified OIDC tokens matching the configured token_kind and audience; Keycloak remains supported. "
            "The browser login redirects and HTML management pages are not control API operations. "
            "SSH/WebSocket/database/HTTP/Kubernetes streaming listeners have separate transport contracts."},
        "servers": [{"url": "/", "description": "Same trusted HTTPS control origin"}],
        "security": BEARER,
        "paths": paths,
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "OIDC JWT", "description":
                    "Verified token from the configured issuer with expected audience and explicit scopes. Use access_token for workload/API clients; legacy id_token configurations remain supported. Session tickets are not bearer tokens."},
                "BrowserSession": {"type": "apiKey", "in": "cookie", "name": "session", "description":
                    "Existing verified browser session. Only operations explicitly listing this alternative accept it."},
                "CSRFToken": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token", "description":
                    "Session-bound CSRF value required together with browser authentication on mutations; not required with a bearer access token."},
            },
            "parameters": {
                "IdempotencyKey": {"name": "Idempotency-Key", "in": "header", "required": True,
                    "schema": {"type": "string", "minLength": 16, "maxLength": 128},
                    "description": "Unique opaque printable key for one create intent; reuse only with the identical request."},
                "IfMatch": {"name": "If-Match", "in": "header", "required": True,
                    "schema": {"type": "string"}, "description": "Current opaque _revision, raw or double-quoted. No wildcard/blind writes."},
            },
            "schemas": schemas(),
            "responses": {"Error": {"description":
                "Request rejected. 401: missing/malformed authentication; 403: policy, scope, CSRF or step-up; "
                "404: disabled/unavailable/not visible; 409: conflict or uncertain outcome; 428: revision missing; "
                "429: admission limit; 503: required dependency or evidence unavailable. "
                "Flask request-validation errors can use HTML rather than JSON.",
                "headers": {"Retry-After": {"schema": STRING}, "WWW-Authenticate": {"schema": STRING}},
                "content": {"application/json": {"schema": ref("Error")}, "text/html": {"schema": STRING}}}},
        },
    }
    return copy.deepcopy(document)


def register_openapi_routes(app, config):
    """Register public read-only contract endpoints, gated by api.enabled."""
    from flask import abort, jsonify, Response

    def enabled():
        if not config.get("api", {}).get("enabled", False):
            abort(404)

    @app.get("/api/v1/version")
    def api_version():
        enabled()
        from isolate_state import SCHEMA_VERSION
        from isolate_build import get_build_info
        build = get_build_info(config)
        return jsonify(version=build.get("version"), revision=build.get("revision"), schema_version=SCHEMA_VERSION)

    @app.get("/api/v1/openapi.json")
    def api_openapi_json():
        enabled()
        return jsonify(build_openapi(app))

    @app.get("/api/v1/openapi.yaml")
    def api_openapi_yaml():
        enabled()
        import yaml
        return Response(yaml.safe_dump(build_openapi(app), sort_keys=False, allow_unicode=True), mimetype="application/yaml")
