"""Owner access reviews, expiring assignments and durable subject offboarding.

Review decisions never renew a grant. Offboarding is a separate deny overlay,
so deleting/reimporting a group or GitOps grant cannot undo it. Every mutation
commits its evidence beside the domain record in the authoritative state store.
"""
import hashlib
import json
import re
import time
import uuid

from isolate_identity import IdentityError
from isolate_permissions import has_permission, is_platform_admin

PROJECT = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
IDENTIFIER = re.compile(r"[a-f0-9]{32}\Z")
GRANT_ID = re.compile(r"[0-9]{1,20}\Z")


class GovernanceError(ValueError):
    def __init__(self, error, status=400):
        self.error, self.status = error, status
        super().__init__(error)


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _load(raw):
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError):
        raise GovernanceError("governance_record_unavailable", 503) from None


def _subject(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise GovernanceError("stable_subject_required")
    return value


def _project(value, global_allowed=False):
    if global_allowed and value == "*":
        return value
    if not isinstance(value, str) or not PROJECT.fullmatch(value):
        raise GovernanceError("exact_project_required")
    return value


def _reason(value):
    if not isinstance(value, str) or not 3 <= len(value.strip()) <= 2048 or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise GovernanceError("reason_required")
    return value.strip()


def _human(identity):
    if identity.get("principal_type") == "service":
        raise GovernanceError("human_governance_operator_required", 403)
    return _subject(identity.get("keycloak_sub"))


def _require(identity, config, project, mutation=False):
    _human(identity)
    if project == "*":
        allowed = is_platform_admin(identity, config)
    elif mutation:
        # Together these capabilities identify a current project owner, unlike
        # an access approver or inventory-only operator acting alone.
        allowed = (has_permission(identity, config, "access.approve", project)
                   and has_permission(identity, config, "inventory.write", project))
    else:
        allowed = has_permission(identity, config, "access.read", project)
    if not allowed:
        raise GovernanceError("governance_project_not_allowed", 403)


def _revision(record):
    return hashlib.sha256(_encode(record).encode()).hexdigest()


def _offboard_key(subject, project):
    return "governance_offboard_" + hashlib.sha256(_encode([subject, project]).encode()).hexdigest()


def check_governance_access(redis, identity, project=None):
    """Check permanent global/project deny markers on every live authorization.

    This intentionally has no enable switch. Existing markers survive optional
    UI/config changes and grant reimports. The subject is the provider-bound
    internal identity, not an editable username or unverified request parameter.
    """
    subject = identity.get("keycloak_sub")
    if not subject:
        return  # Real identity verification requires a stable subject upstream.
    try:
        _subject(subject)
        if project is not None and (not isinstance(project, str) or not project or len(project) > 512
                or any(ord(c) < 32 or ord(c) == 127 for c in project)):
            raise IdentityError('access project is unavailable')
        # Existing inventory may use legacy project spellings. Do not impose a
        # new creation regex on reads; match the policy resolver's case folding.
        scopes = ("*",) if project is None else ("*", project.lower())
        for scope in scopes:
            raw = redis.get(_offboard_key(subject, scope))
            if raw is None:
                continue
            record = _load(raw)
            if (record.get("schema_version") != 1 or record.get("subject_id") != subject
                    or record.get("project") != scope or record.get("status") != "blocked"):
                raise IdentityError("access lifecycle evidence is unavailable")
            raise IdentityError("access has been ended by an access lifecycle decision")
    except IdentityError:
        raise
    except Exception:
        raise IdentityError("access lifecycle evidence is unavailable") from None


def _event(config, identity, operation, project, event_id, **refs):
    from isolate_audit import prepare_and_dispatch
    record = dict(ts=int(time.time()), event="governance_" + operation, event_id=event_id,
        keycloak_sub=identity["keycloak_sub"], username=identity.get("username"), project=project,
        action=operation, result="committed", outcome="committed", source="isolate-workflow", **refs)
    # Sign now, but expose committed evidence to external sinks only after the
    # transaction succeeds. A WATCH retry must not publish a fictional commit.
    return prepare_and_dispatch(record, dict(config.get("logging", {}), sinks=[], fail_closed=True))


def _transaction(store, keys, mutation):
    from redis.exceptions import WatchError
    for _ in range(12):
        with store.pipeline(transaction=True) as pipe:
            try:
                if keys:
                    pipe.watch(*keys)
                result, writes = mutation(pipe)
                if not writes:
                    return result
                for key, value in list(writes.items()):
                    if key.startswith('governance_event_'):
                        identifier = key[len('governance_event_'):]
                        writes['workflow_event_' + identifier] = value
                        writes['workflow_pending_' + identifier] = value
                pipe.multi()
                for key, value in writes.items():
                    if value is None:
                        pipe.delete(key)
                    else:
                        pipe.set(key, _encode(value))
                pipe.execute()
                return result
            except WatchError:
                continue
    raise GovernanceError("governance_changed_concurrently", 409)


def publish_pending(store, config, limit=100):
    from isolate_workflow_audit import publish_pending as publish
    try:
        return publish(store, config, limit)
    except Exception:
        # The access mutation and source evidence have already committed. An
        # unavailable publisher/store after commit must not imply rollback.
        return {'published': 0, 'pending': None, 'failed': 1}


def _intent(identity, kind, key, payload):
    if not isinstance(key, str) or not 16 <= len(key) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise GovernanceError("idempotency_key_required")
    intent = "governance_intent_" + hashlib.sha256(_encode([identity["keycloak_sub"], kind, key]).encode()).hexdigest()
    return intent, _revision(payload)


def _existing(pipe, intent, digest, prefix):
    raw = pipe.get(intent)
    if raw is None:
        return None
    record = _load(raw)
    if record.get("digest") != digest:
        raise GovernanceError("idempotency_conflict", 409)
    current = pipe.get(prefix + record["id"])
    if current is None:
        raise GovernanceError("governance_object_requires_reconciliation", 409)
    return _load(current)


def _keys(store, prefix):
    rows = []
    for key in store.keys(prefix + "*"):
        key = key.decode() if isinstance(key, bytes) else key
        if isinstance(key, str) and key.startswith(prefix):
            rows.append(key)
    return sorted(rows)


def visible_projects(store, config, identity):
    _human(identity)
    projects = set()
    for key in _keys(store, "server_"):
        if not GRANT_ID.fullmatch(key[7:]):
            continue
        raw = store.get(key)
        if raw is not None:
            project = _load(raw).get("project_name")
            if isinstance(project, str) and PROJECT.fullmatch(project) and has_permission(identity, config, "access.read", project):
                projects.add(project)
    for prefix in ("governance_review_", "governance_assignment_"):
        for key in _keys(store, prefix):
            raw = store.get(key)
            if raw is not None:
                project = _load(raw).get("project")
                if project and has_permission(identity, config, "access.read", project):
                    projects.add(project)
    return sorted(projects)


def _grants(store, project):
    from isolate_policy import _project_matches
    sets = {}
    for key in _keys(store, "project_set_"):
        raw = store.get(key)
        if raw is not None:
            sets[key[len("project_set_"):]] = _load(raw)
    result = []
    for key in _keys(store, "grant_"):
        if not GRANT_ID.fullmatch(key[6:]):
            continue
        raw = store.get(key)
        if raw is None:
            continue
        grant = _load(raw)
        if _project_matches(grant, project, sets):
            result.append((key[6:], grant))
    return result


def _grant_view(grant_id, grant):
    value = {key: grant.get(key) for key in ("subject", "name", "keycloak_sub", "remote_user", "sudo_mode", "allowed_actions", "starts_at", "expires_at", "temporary", "managed_by") if key in grant}
    value.update(grant_id=grant_id, revision=_revision(grant), exact_project=bool(isinstance(grant.get("project"), str) and grant.get("project") != "*" and not grant.get("project_set") and not grant.get("project_glob")))
    return value


def create_review(store, config, identity, project, reason, *, idempotency_key, due_at=None, owner_subject=None):
    project, reason = _project(project), _reason(reason)
    _require(identity, config, project, True)
    owner = _subject(owner_subject or identity["keycloak_sub"])
    now = int(time.time())
    requested_due = due_at
    due_at = now + 14 * 86400 if due_at is None else due_at
    if type(due_at) is not int or not now < due_at <= now + 90 * 86400:
        raise GovernanceError("review_due_within_90_days_required")
    identifier = uuid.uuid4().hex
    payload = dict(project=project, reason=reason, owner_subject=owner, due_at=due_at)
    intent, digest = _intent(identity, "review", idempotency_key, dict(payload, due_at=requested_due))
    snapshot_counter = store.get('offset_grant_id')
    grants = _grants(store, project)
    if len(grants) > 1000:
        raise GovernanceError("review_scope_too_large", 409)
    keys = [intent, "offset_grant_id"] + ["grant_" + key for key, _ in grants]
    def mutation(pipe):
        _require(identity, config, project, True)
        existing = _existing(pipe, intent, digest, "governance_review_")
        if existing:
            return existing, {}
        if pipe.get('offset_grant_id') != snapshot_counter:
            raise GovernanceError('grant_snapshot_changed_retry_review', 409)
        items = []
        for grant_id, _ in grants:
            raw = pipe.get("grant_" + grant_id)
            if raw is not None:
                grant = _load(raw)
                from isolate_policy import _project_matches
                sets = {}
                if grant.get('project_set'):
                    set_key = 'project_set_' + grant['project_set']
                    pipe.watch(set_key)
                    set_raw = pipe.get(set_key)
                    if set_raw is not None:
                        sets[grant['project_set']] = _load(set_raw)
                if not _project_matches(grant, project, sets):
                    continue
                items.append(dict(_grant_view(grant_id, grant), decision=None))
        record = dict(schema_version=1, id=identifier, project=project, owner_subject=owner,
            created_by=identity["keycloak_sub"], created_at=now, due_at=due_at, reason=reason,
            status="open" if items else "completed", items=items)
        event = _event(config, identity, "review_created", project, identifier, review_id=identifier)
        return record, {"governance_review_" + identifier: record, intent: {"digest": digest, "id": identifier},
                        "governance_event_" + identifier: event}
    return _transaction(store, keys, mutation)


def decide_review(store, config, identity, review_id, grant_id, decision, reason):
    if not IDENTIFIER.fullmatch(str(review_id)) or not GRANT_ID.fullmatch(str(grant_id)) or decision not in ("keep", "revoke", "removed"):
        raise GovernanceError("invalid_review_decision")
    reason = _reason(reason)
    key, grant_key = "governance_review_" + review_id, "grant_" + grant_id
    event_id = uuid.uuid4().hex
    def mutation(pipe):
        raw = pipe.get(key)
        if raw is None:
            raise GovernanceError("review_not_found", 404)
        record = _load(raw)
        project = record["project"]
        _require(identity, config, project, True)
        if identity["keycloak_sub"] != record["owner_subject"] and not is_platform_admin(identity, config):
            raise GovernanceError("assigned_review_owner_required", 403)
        if record["status"] != "open":
            raise GovernanceError("review_already_completed", 409)
        item = next((item for item in record["items"] if item["grant_id"] == grant_id), None)
        if item is None:
            raise GovernanceError("review_item_not_found", 404)
        if item.get("decision"):
            raise GovernanceError("review_item_already_decided", 409)
        current_raw = pipe.get(grant_key)
        current = _load(current_raw) if current_raw is not None else None
        if decision == "removed":
            if current is not None:
                raise GovernanceError("grant_still_exists", 409)
        else:
            if current is None or _revision(current) != item["revision"]:
                raise GovernanceError("review_snapshot_stale_create_new_review", 409)
            own_user = (current.get('keycloak_sub') == identity['keycloak_sub']
                or not current.get('keycloak_sub') and current.get('name') == identity.get('username'))
            if decision == "keep" and current.get("subject") == "user" and own_user:
                raise GovernanceError("independent_review_of_own_access_required", 403)
        writes = {}
        if decision == "revoke":
            if current.get("managed_by"):
                raise GovernanceError("managed_grant_requires_owner_remediation", 409)
            if not item["exact_project"] and not is_platform_admin(identity, config):
                raise GovernanceError("broader_grant_requires_platform_administrator", 403)
            # Retain the precedence-bearing rule as a denial rather than delete
            # it and accidentally reveal a broader fallback grant. A later
            # explicit administrative change can restore it with CAS evidence.
            current.update(allowed_actions=["governance-denied"], governance_revoked_at=int(time.time()),
                           governance_review_id=review_id)
            writes[grant_key] = current
        item.update(decision=decision, decided_at=int(time.time()), decided_by=identity["keycloak_sub"], reason=reason)
        if all(item.get("decision") for item in record["items"]):
            record.update(status="completed", completed_at=int(time.time()))
            interval = config.get("governance", {}).get("review_interval_days", 90)
            if type(interval) is not int or not 1 <= interval <= 365:
                raise GovernanceError("invalid_review_interval", 503)
            writes["governance_schedule_" + project] = {"project": project, "review_id": review_id,
                "last_completed_at": record["completed_at"], "next_due_at": record["completed_at"] + interval * 86400}
        event = _event(config, identity, "review_decided", project, event_id, review_id=review_id,
            grant_id=grant_id, decision=decision, target_subject=item.get("keycloak_sub"))
        writes.update({key: record, "governance_event_" + event_id: event})
        return record, writes
    return _transaction(store, [key, grant_key], mutation)


def create_assignment(store, config, identity, *, project, subject_id, username, remote_user, expires_at,
                      reason, idempotency_key, allowed_actions=None, starts_at=None, category="contractor"):
    project, subject_id, reason = _project(project), _subject(subject_id), _reason(reason)
    _require(identity, config, project, True)
    if subject_id == identity["keycloak_sub"]:
        raise GovernanceError("self_assignment_not_allowed", 403)
    now = int(time.time())
    requested_start = starts_at
    starts_at = now if starts_at is None else starts_at
    if (type(starts_at) is not int or type(expires_at) is not int or starts_at < now - 60
            or not max(now, starts_at) < expires_at <= now + 90 * 86400):
        raise GovernanceError("assignment_window_within_90_days_required")
    if category not in ("contractor", "temporary"):
        raise GovernanceError("invalid_assignment_category")
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", username):
        raise GovernanceError("invalid_assignment_username")
    if not isinstance(remote_user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", remote_user) or remote_user == "root":
        raise GovernanceError("nonprivileged_assignment_identity_required")
    actions = ["ssh"] if allowed_actions is None else allowed_actions
    permitted = {"ssh", "webssh", "http", "postgresql", "mysql", "kubernetes", "kubernetes-exec", "kubernetes-attach", "kubernetes-logs", "kubernetes-watch", "kubernetes-portforward", "sftp", "scp"}
    if not isinstance(actions, list) or not actions or any(not isinstance(a, str) or a not in permitted for a in actions) or len(set(actions)) != len(actions):
        raise GovernanceError("explicit_connection_actions_required")
    actions = sorted(actions)
    payload = dict(project=project, subject_id=subject_id, username=username, remote_user=remote_user,
        starts_at=starts_at, expires_at=expires_at, allowed_actions=actions, category=category, reason=reason)
    intent, digest = _intent(identity, "assignment", idempotency_key, dict(payload, starts_at=requested_start))
    assignment_id = uuid.uuid4().hex
    def mutation(pipe):
        _require(identity, config, project, True)
        existing = _existing(pipe, intent, digest, "governance_assignment_")
        if existing:
            return existing, {}
        counter = int(pipe.get("offset_grant_id") or 0)
        while True:
            counter += 1
            grant_id = str(counter)
            grant_key = "grant_" + grant_id
            pipe.watch(grant_key)
            if pipe.get(grant_key) is None:
                break
            if counter > 10**20:
                raise GovernanceError("assignment_identifier_exhausted", 503)
        grant = {"schema_version": 2, "subject": "user", "name": username, "keycloak_sub": subject_id,
            "project": project, "remote_user": remote_user, "sudo_mode": "none", "allowed_actions": actions,
            "temporary": True, "starts_at": starts_at, "expires_at": expires_at,
            "governance_assignment_id": assignment_id}
        record = dict(payload, schema_version=1, id=assignment_id, grant_id=grant_id, grant_revision=_revision(grant),
            status="active", owner_subject=identity["keycloak_sub"], created_at=now)
        event = _event(config, identity, "assignment_created", project, assignment_id,
            assignment_id=assignment_id, grant_id=grant_id, target_subject=subject_id, expires_at=expires_at)
        return record, {"offset_grant_id": counter, grant_key: grant, "governance_assignment_" + assignment_id: record,
            "governance_event_" + assignment_id: event, intent: {"id": assignment_id, "digest": digest}}
    return _transaction(store, [intent, "offset_grant_id"], mutation)


def revoke_assignment(store, config, identity, assignment_id, reason):
    if not IDENTIFIER.fullmatch(str(assignment_id)):
        raise GovernanceError("assignment_not_found", 404)
    reason = _reason(reason)
    key, event_id = "governance_assignment_" + assignment_id, uuid.uuid4().hex
    def mutation(pipe):
        raw = pipe.get(key)
        if raw is None:
            raise GovernanceError("assignment_not_found", 404)
        record = _load(raw)
        _require(identity, config, record["project"], True)
        if record["status"] == "revoked":
            return record, {}
        grant_key = "grant_" + record["grant_id"]
        pipe.watch(grant_key)
        raw = pipe.get(grant_key)
        if raw is not None:
            grant = _load(raw)
            if grant.get("governance_assignment_id") != assignment_id or _revision(grant) != record["grant_revision"]:
                raise GovernanceError("assignment_grant_changed_reconciliation_required", 409)
            grant.update(allowed_actions=["governance-denied"], governance_revoked_at=int(time.time()))
        else:
            grant = None
        record.update(status="revoked", revoked_at=int(time.time()), revoked_by=identity["keycloak_sub"], revoke_reason=reason)
        event = _event(config, identity, "assignment_revoked", record["project"], event_id,
            assignment_id=assignment_id, grant_id=record["grant_id"], target_subject=record["subject_id"])
        writes = {key: record, "governance_event_" + event_id: event}
        if grant is not None:
            writes[grant_key] = grant
        return record, writes
    return _transaction(store, [key], mutation)


def offboard(store, config, identity, subject_id, project, reason):
    subject_id, project, reason = _subject(subject_id), _project(project, True), _reason(reason)
    _require(identity, config, project, True)
    if subject_id == identity["keycloak_sub"]:
        raise GovernanceError("independent_offboarding_operator_required", 403)
    key, identifier = _offboard_key(subject_id, project), uuid.uuid4().hex
    def mutation(pipe):
        _require(identity, config, project, True)
        raw = pipe.get(key)
        if raw is not None:
            record = _load(raw)
            if record.get("subject_id") != subject_id or record.get("project") != project or record.get("status") != "blocked":
                raise GovernanceError("offboarding_record_unavailable", 503)
            return record, {}
        record = dict(schema_version=1, id=identifier, subject_id=subject_id, project=project, status="blocked",
            created_at=int(time.time()), created_by=identity["keycloak_sub"], reason=reason,
            next_step="Remove IdP memberships and reconcile externally managed grants; denial remains until an independently reviewed reboarding process.")
        event = _event(config, identity, "offboarded", project, identifier, offboarding_id=identifier, target_subject=subject_id)
        return record, {key: record, "governance_event_" + identifier: event}
    return _transaction(store, [key], mutation)


def dashboard(store, config, identity, project=None):
    projects = [_project(project)] if project else visible_projects(store, config, identity)
    for value in projects:
        _require(identity, config, value)
    if not projects and not has_permission(identity, config, "access.read"):
        raise GovernanceError("governance_project_not_allowed", 403)
    now, reviews, assignments, offboardings, reminders, findings, schedules = int(time.time()), [], [], [], [], [], []
    for prefix, result in (("governance_review_", reviews), ("governance_assignment_", assignments), ("governance_offboard_", offboardings)):
        for key in _keys(store, prefix):
            raw = store.get(key)
            if raw is None:
                continue
            row = _load(raw)
            if row.get("project") not in projects and not (row.get("project") == "*" and is_platform_admin(identity, config)):
                continue
            if prefix == "governance_assignment_" and row.get("status") == "active":
                row["effective_status"] = "expired" if row["expires_at"] <= now else "scheduled" if row["starts_at"] > now else "active"
                if now < row["expires_at"] <= now + 7 * 86400:
                    reminders.append({"kind": "assignment_expiring", "project": row["project"], "assignment_id": row["id"], "due_at": row["expires_at"], "subject_id": row["subject_id"]})
            if prefix == "governance_review_" and row.get("status") == "open" and row["due_at"] <= now:
                reminders.append({"kind": "review_overdue", "project": row["project"], "review_id": row["id"], "due_at": row["due_at"]})
            result.append(row)
    for scope in projects:
        schedule_raw = store.get("governance_schedule_" + scope)
        schedule = _load(schedule_raw) if schedule_raw is not None else None
        schedules.append(schedule or {'project': scope, 'last_completed_at': None, 'next_due_at': now, 'review_id': None})
        if schedule is None or schedule["next_due_at"] <= now:
            reminders.append({"kind": "periodic_review_due", "project": scope, "due_at": schedule["next_due_at"] if schedule else now})
        for grant_id, grant in _grants(store, scope):
            if (grant.get("expires_at") is not None and int(grant["expires_at"]) <= now
                    or grant.get("allowed_actions") == ['governance-denied']):
                continue
            reasons = []
            if grant.get("expires_at") is None:
                reasons.append("no_expiry")
            if grant.get("sudo_mode") == "sudo-i" or grant.get("remote_user") == "root":
                reasons.append("privileged_identity")
            if grant.get("project") == "*" or grant.get("project_glob") or grant.get("project_set"):
                reasons.append("broad_project_scope")
            if grant.get("subject") == "user" and not grant.get("keycloak_sub"):
                reasons.append("username_only_binding")
            if reasons:
                findings.append(dict(_grant_view(grant_id, grant), project=scope, reasons=reasons,
                    assessment="review_candidate_not_proof_of_excess_access"))
    return dict(projects=projects, reviews=reviews, assignments=assignments, offboardings=offboardings,
                reminders=reminders, findings=findings, review_schedule=schedules, generated_at=now)
