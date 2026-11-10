"""Single-use, project-scoped approval of an already authorized SSH connection."""

import fnmatch
import copy
import hashlib
import json
import re
import time
import uuid


class SessionApprovalDenied(ValueError):
    pass


def _now():
    return int(time.time())


def _settings(config):
    raw = (config or {}).get("session_approval", {}) or {}
    if not isinstance(raw, dict):
        raise SessionApprovalDenied("invalid session approval configuration")
    defaults = {"minimum_approvals": 1, "privileged_minimum_approvals": 2,
                "request_timeout_seconds": 300, "approval_ttl_seconds": 300,
                "max_session_seconds": 3600, "poll_interval_seconds": 2}
    settings = dict(raw)
    for name in ("enabled", "require_privileged"):
        if not isinstance(raw.get(name, False), bool):
            raise SessionApprovalDenied("invalid session approval {}".format(name))
    for name, default in defaults.items():
        value = raw.get(name, default)
        maximum = 10 if "approvals" in name else 86400
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= value <= maximum or int(value) != value:
            raise SessionApprovalDenied("invalid session approval {}".format(name))
        settings[name] = int(value)
    for name in ("required_projects", "required_project_globs"):
        value = raw.get(name, [])
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
            raise SessionApprovalDenied("invalid session approval {}".format(name))
        settings[name] = value
    return settings


def _privileged(decision):
    return decision.get("remote_user") == "root" or decision.get("sudo_mode") == "sudo-i"


def session_approval_required(config, host, decision):
    settings = _settings(config)
    if settings.get("enabled", False) is not True:
        return False
    project = str(host.get("project_name") or "").lower()
    return (project in [item.lower() for item in settings["required_projects"]]
            or any(fnmatch.fnmatchcase(project, pattern.lower()) for pattern in settings["required_project_globs"])
            or (settings.get("require_privileged", False) is True and _privileged(decision)))


def _quorum(config, decision):
    settings = _settings(config)
    count = settings["minimum_approvals"]
    return max(count, settings["privileged_minimum_approvals"]) if _privileged(decision) else count


def _binding(identity, host, decision, connection_id, source_ip=None):
    subject = identity.get("keycloak_sub")
    if not isinstance(subject, str) or not subject:
        raise SessionApprovalDenied("a stable verified requester subject is required")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", str(connection_id or "")):
        raise SessionApprovalDenied("a valid connection ID is required")
    grant = decision.get("matched_rule")
    if not isinstance(grant, dict):
        raise SessionApprovalDenied("session approval requires an existing policy decision")
    if not host.get("project_name") or not host.get("server_id") or not decision.get("remote_user"):
        raise SessionApprovalDenied("session approval requires an inventory project, host and remote identity")
    # Preserve the exact grant as evidence, including action/expiry changes.
    grant_hash = hashlib.sha256(json.dumps(grant, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"requester_sub": subject, "host_id": str(host.get("server_id") or ""),
            "project": host.get("project_name"), "target_host": host.get("server_ip"),
            "target_port": int(host.get("server_port") or 22), "proxy_id": host.get("proxy_id"),
            "remote_user": decision.get("remote_user"), "sudo_mode": decision.get("sudo_mode") or "none",
            "grant_sha256": grant_hash, "connection_id": str(connection_id), "source_ip": source_ip}


def _key(request_id):
    if re.fullmatch(r"[a-f0-9]{32}", str(request_id or "")) is None:
        raise SessionApprovalDenied("invalid session approval ID")
    return "session_approval_{}".format(request_id)


def _load(redis, key):
    raw = redis.get(key)
    return json.loads(raw.decode() if isinstance(raw, bytes) else raw) if raw is not None else None


def _effective_status(record, now=None):
    now = _now() if now is None else int(now)
    status = record.get("status")
    deadline = {"pending": "request_expires_at", "approved": "approval_expires_at", "active": "session_expires_at"}.get(status)
    return "expired" if deadline and int(record.get(deadline) or 0) <= now else status


def _tighten_deadlines(record, config):
    """Configuration may shorten an observed lifetime, never extend it again."""
    settings = _settings(config)
    for deadline, timestamp, duration in (
        ("request_expires_at", "requested_at", "request_timeout_seconds"),
        ("approval_expires_at", "approved_at", "approval_ttl_seconds"),
        ("session_expires_at", "consumed_at", "max_session_seconds"),
    ):
        if record.get(deadline) is not None:
            record[deadline] = min(int(record[deadline]), int(record.get(timestamp) or 0) + settings[duration])
    record["status"] = _effective_status(record)


def get_session_approval(redis, request_id, config=None):
    if config is not None:
        return _mutate(redis, request_id, lambda record: None, config=config)
    record = _load(redis, _key(request_id))
    if record is not None:
        record["status"] = _effective_status(record)
    return record


def list_session_approvals(redis, status=None, project=None):
    rows = []
    for key in redis.keys("session_approval_*"):
        key_name = key.decode() if isinstance(key, bytes) else str(key)
        if re.fullmatch(r"session_approval_[a-f0-9]{32}", key_name) is None:
            continue
        record = _load(redis, key)
        if record is None:
            continue
        record["status"] = _effective_status(record)
        if (not status or record["status"] == status) and (not project or record.get("project") == project):
            rows.append(record)
    return sorted(rows, key=lambda row: row.get("requested_at") or 0, reverse=True)


def _mutate(redis, request_id, change, config=None, actor=None, event=None):
    key = _key(request_id)

    def apply(reader, transaction=None):
        record = _load(reader, key)
        if record is None:
            raise SessionApprovalDenied("session approval was not found")
        if config is not None:
            _tighten_deadlines(record, config)
        record["status"] = _effective_status(record)
        baseline = copy.deepcopy(record)
        failure = None
        try:
            change(record)
        except SessionApprovalDenied as exc:
            # Persist a shortened/expired lifetime even when a transition is
            # refused. Never persist a partially attempted decision or vote.
            record = baseline
            failure = exc
        target = transaction if transaction is not None else redis
        if transaction is not None:
            transaction.multi()
        target.set(key, json.dumps(record, sort_keys=True))
        if event and failure is None:
            from isolate_workflow_audit import stage_event
            stage_event(target, config, event, actor, record.get('project'), session_approval_id=record['id'],
                connection_id=record.get('connection_id'), grant_id=record.get('grant_id'),
                requester_sub=record.get('requester_sub'), status=record.get('status'))
        if transaction is not None:
            transaction.execute()
        if failure is not None:
            raise failure
        return record

    if not callable(getattr(redis, "pipeline", None)):
        return apply(redis)
    from redis.exceptions import WatchError
    for _ in range(5):
        with redis.pipeline(transaction=True) as transaction:
            try:
                transaction.watch(key)
                return apply(transaction, transaction)
            except WatchError:
                continue
    raise SessionApprovalDenied("session approval changed concurrently; retry the decision")


def request_session_approval(redis, config, identity, host, decision, connection_id, source_ip=None):
    if not session_approval_required(config, host, decision):
        return None
    settings = _settings(config)
    binding = _binding(identity, host, decision, connection_id, source_ip)
    now = _now()
    request_id = uuid.uuid4().hex
    identity_expiry = int(identity.get("exp") or 0)
    expiry = min(now + settings["request_timeout_seconds"], identity_expiry)
    if expiry <= now:
        raise SessionApprovalDenied("requester identity has expired")
    record = dict(binding, id=request_id, schema_version=1, binding=binding,
                  requester=identity.get("username"), status="pending", approvals=[],
                  required_approvals=_quorum(config, decision), requested_at=now,
                  request_expires_at=expiry, requester_expires_at=identity_expiry,
                  grant_id=(decision.get("matched_rule") or {}).get("id"))
    from isolate_workflow_audit import stage_event
    if callable(getattr(redis, 'pipeline', None)):
        with redis.pipeline(transaction=True) as transaction:
            transaction.multi()
            transaction.set(_key(request_id), json.dumps(record, sort_keys=True))
            stage_event(transaction, config, 'session_approval_requested', identity, host.get('project_name'),
                session_approval_id=request_id, connection_id=connection_id, grant_id=record.get('grant_id'))
            transaction.execute()
    else:
        redis.set(_key(request_id), json.dumps(record, sort_keys=True))
        stage_event(redis, config, 'session_approval_requested', identity, host.get('project_name'),
            session_approval_id=request_id, connection_id=connection_id, grant_id=record.get('grant_id'))
    return record


def _require_approver(config, record, actor):
    from isolate_permissions import has_permission
    if not isinstance(record.get("project"), str) or not record["project"].strip():
        raise SessionApprovalDenied("session approval has no project scope")
    if not actor.get("keycloak_sub"):
        raise SessionApprovalDenied("a stable verified approver subject is required")
    if actor.get("exp") is not None and int(actor["exp"]) <= _now():
        raise SessionApprovalDenied("approver identity has expired")
    if actor["keycloak_sub"] == record.get("requester_sub"):
        raise SessionApprovalDenied("self-approval is forbidden")
    if not has_permission(actor, config, "sessions.approve", project=record.get("project")):
        raise SessionApprovalDenied("session approval is outside the approver's project scope")


def _valid_approvals(config, record):
    from isolate_permissions import has_permission
    if not isinstance(record.get("project"), str) or not record["project"].strip():
        return set()
    subjects = set()
    for approval in record.get("approvals") or []:
        subject = approval.get("keycloak_sub")
        if subject and subject != record.get("requester_sub") and has_permission(
            approval, config, "sessions.approve", project=record.get("project")
        ):
            subjects.add(subject)
    return subjects


def decide_session_approval(redis, config, request_id, actor, approve=True, reason=None):
    def decide(record):
        _require_approver(config, record, actor)
        if record["status"] != "pending":
            raise SessionApprovalDenied("session request is already {}".format(record["status"]))
        if not approve:
            record.update(status="denied", decided_at=_now(), decided_by=actor["keycloak_sub"], reason=str(reason or "")[:2048])
            return
        if any(item.get("keycloak_sub") == actor["keycloak_sub"] for item in record["approvals"]):
            raise SessionApprovalDenied("this person has already approved the session")
        record["approvals"].append({"keycloak_sub": actor["keycloak_sub"], "username": actor.get("username"),
                                    "groups": list(actor.get("groups") or []), "approved_at": _now(), "reason": str(reason or "")[:2048]})
        required = max(int(record["required_approvals"]), _quorum(config, record))
        record["required_approvals"] = required
        if len(_valid_approvals(config, record)) >= required:
            now = _now()
            record.update(status="approved", approved_at=now,
                          approval_expires_at=min(now + _settings(config)["approval_ttl_seconds"], record["requester_expires_at"]))
    return _mutate(redis, request_id, decide, config=config, actor=actor, event='session_approval_decided')


def revoke_session_approval(redis, config, request_id, actor, reason=None):
    def revoke(record):
        _require_approver(config, record, actor)
        if record["status"] not in ("pending", "approved", "active"):
            raise SessionApprovalDenied("session approval is already {}".format(record["status"]))
        record.update(status="revoked", revoked_at=_now(), revoked_by=actor["keycloak_sub"], reason=str(reason or "")[:2048])
    return _mutate(redis, request_id, revoke, config=config, actor=actor, event='session_approval_revoked')


def cancel_session_approval(redis, config, request_id, identity):
    def cancel(record):
        if not identity.get("keycloak_sub") or record.get("requester_sub") != identity["keycloak_sub"]:
            raise SessionApprovalDenied("session request is not owned by this user")
        if record["status"] not in ("pending", "approved"):
            raise SessionApprovalDenied("only an unconsumed session request can be cancelled")
        record.update(status="cancelled", cancelled_at=_now(), cancelled_by=identity["keycloak_sub"])
    return _mutate(redis, request_id, cancel, config=config, actor=identity, event='session_approval_cancelled')


def _check_binding(record, config, identity, host, decision, connection_id, source_ip):
    if record.get("binding") != _binding(identity, host, decision, connection_id, source_ip):
        raise SessionApprovalDenied("session identity, destination or policy changed after approval")
    required = max(int(record["required_approvals"]), _quorum(config, decision))
    if len(_valid_approvals(config, record)) < required:
        raise SessionApprovalDenied("session approval quorum is no longer sufficient")


def consume_session_approval(redis, config, request_id, identity, host, decision, connection_id, source_ip=None):
    def consume(record):
        if record["status"] != "approved":
            raise SessionApprovalDenied("session approval is {}".format(record["status"]))
        _check_binding(record, config, identity, host, decision, connection_id, source_ip)
        now = _now()
        expiry = min(now + _settings(config)["max_session_seconds"], int(identity.get("exp") or 0))
        grant_expiry = (decision.get("matched_rule") or {}).get("expires_at")
        if grant_expiry is not None:
            expiry = min(expiry, int(grant_expiry))
        if expiry <= now:
            raise SessionApprovalDenied("session authorization expired")
        record.update(status="active", consumed_at=now, session_expires_at=expiry)
    return _mutate(redis, request_id, consume, config=config, actor=identity, event='session_approval_consumed')


def validate_session_approval(redis, config, request_id, identity, host, decision, connection_id, source_ip=None):
    def validate(record):
        if record["status"] != "active":
            raise SessionApprovalDenied("active session approval is missing, expired or revoked")
        _check_binding(record, config, identity, host, decision, connection_id, source_ip)
    return _mutate(redis, request_id, validate, config=config)


def close_session_approval(redis, request_id):
    def close(record):
        if record["status"] == "active":
            record.update(status="closed", closed_at=_now())
    return _mutate(redis, request_id, close)


def set_session_approval_notification_status(redis, request_id, status):
    def update(record):
        record["notification_status"] = dict(status)
    return _mutate(redis, request_id, update)
