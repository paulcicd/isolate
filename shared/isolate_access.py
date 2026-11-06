#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Break-glass access request helpers."""

import datetime
import json
import re
import time


class AccessDenied(Exception):
    pass


def decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def now_ts():
    return int(time.time())


def parse_duration(value, default=None):
    if value is None:
        value = default
    if value is None:
        raise ValueError("duration is required")
    if isinstance(value, (int, float)):
        return int(value)
    value = str(value).strip().lower()
    if value.isdigit():
        return int(value)
    unit = value[-1]
    amount = int(value[:-1])
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if unit not in multipliers:
        raise ValueError("unsupported duration: {}".format(value))
    return amount * multipliers[unit]


def is_access_admin(identity, admin_groups=None):
    return bool(set(identity.get("groups") or []) & set(admin_groups or []))


def parse_access_time(value):
    """Return Unix seconds; human timestamps must include their UTC offset."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("access time must be a Unix timestamp or ISO 8601 time")
    try:
        if isinstance(value, (int, float)) or str(value).strip().isdigit():
            timestamp = int(value)
            if timestamp < 0:
                raise ValueError("access time must not be negative")
            return timestamp
        parsed = datetime.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("access time must include a timezone, for example +07:00 or Z")
        timestamp = int(parsed.timestamp())
        if timestamp < 0:
            raise ValueError("access time must not be negative")
        return timestamp
    except (OverflowError, TypeError) as exc:
        raise ValueError("invalid access time") from exc


def _access_window(starts_at=None, ends_at=None, now=None):
    now = now_ts() if now is None else int(now)
    start = parse_access_time(starts_at)
    end = parse_access_time(ends_at)
    if end is not None and end <= max(start or now, now):
        raise AccessDenied("access window must end after its start and the current time")
    return start, end


def owns_access_request(record, identity):
    if not record or not identity:
        return False
    if record.get("requester_sub"):
        return record["requester_sub"] == identity.get("keycloak_sub")
    return bool(identity.get("username")) and record.get("requester") == identity["username"]


def can_access_request(record, identity, admin_groups=None):
    return bool(record) and (owns_access_request(record, identity) or is_access_admin(identity, admin_groups))


def _require_owner(record, identity):
    if not owns_access_request(record, identity):
        raise AccessDenied("access request is not owned by this user")


def _mutate_request(redis, request_id, mutation):
    """Commit request status and its grant together, retrying competing decisions."""
    key = _request_key(request_id)

    def apply(reader, writer=None):
        record = _load(reader, key)
        if record is None:
            return None
        result, changes = mutation(record, reader)
        if writer is not None:
            writer.multi()
        target = writer if writer is not None else redis
        for operation, changed_key, value in changes:
            if operation == "delete":
                target.delete(changed_key)
            else:
                target.set(changed_key, json.dumps(value, sort_keys=True))
        target.set(key, json.dumps(record, sort_keys=True))
        if writer is not None:
            writer.execute()
        return result

    if not callable(getattr(redis, "pipeline", None)):
        return apply(redis)
    # redis-py WATCH keeps all reads before MULTI and writes one atomic transaction.
    from redis.exceptions import WatchError
    for _ in range(5):
        with redis.pipeline(transaction=True) as pipeline:
            try:
                pipeline.watch(key)
                return apply(pipeline, writer=pipeline)
            except WatchError:
                continue
    raise AccessDenied("access request changed concurrently; retry the action")


def _comment(identity, action, text=None):
    if not text:
        return None
    return {
        "ts": now_ts(),
        "username": (identity or {}).get("username"),
        "action": action,
        "text": text,
    }


def _append_comment(record, identity, action, text=None):
    comment = _comment(identity, action, text)
    if comment:
        record.setdefault("comments", [])
        record["comments"].append(comment)


def validate_ticket(ticket, config=None):
    access_cfg = (config or {}).get("access", {})
    ticket = (ticket or "").strip()
    if access_cfg.get("ticket_required") and not ticket:
        raise AccessDenied("ticket is required")
    pattern = access_cfg.get("ticket_pattern")
    if ticket and pattern and re.match(pattern, ticket) is None:
        raise AccessDenied("ticket does not match configured pattern")
    return ticket or None


def _request_key(request_id):
    return "access_request_{}".format(request_id)


def _load(redis, key):
    raw = redis.get(key)
    if raw is None:
        return None
    return json.loads(decode(raw))


def create_access_request(redis, identity, project, host=None, remote_user=None, sudo_mode=None, reason=None, ticket=None, template=None, config=None, starts_at=None, ends_at=None, renewal_of=None):
    ticket = validate_ticket(ticket, config=config)
    if not identity.get("username") or not str(project or "").strip() or not str(reason or "").strip():
        raise AccessDenied("requester, project and reason are required")
    starts_at, ends_at = _access_window(starts_at, ends_at)
    template_data = ((config or {}).get("access", {}).get("request_templates") or {}).get(template or "") or {}
    remote_user = remote_user if remote_user is not None else template_data.get("remote_user")
    sudo_mode = sudo_mode if sudo_mode is not None else template_data.get("sudo_mode")
    request_id = redis.incr("offset_access_request_id")
    record = {
        "schema_version": 2,
        "id": str(request_id),
        "status": "pending",
        "requester": identity.get("username"),
        "requester_sub": identity.get("keycloak_sub"),
        "requester_groups": identity.get("groups") or [],
        "project": project,
        "host": host,
        "remote_user": remote_user,
        "sudo_mode": sudo_mode,
        "reason": reason,
        "ticket": ticket,
        "template": template,
        "comments": [],
        "notification_status": None,
        "created_at": now_ts(),
        "decided_by": None,
        "decided_at": None,
        "decision_reason": None,
        "expires_at": None,
        "starts_at": starts_at,
        "ends_at": ends_at,
        "grant_id": None,
    }
    if renewal_of is not None:
        record["renewal_of"] = str(renewal_of)
        _append_comment(record, identity, "renew", "Renewal of request #{}".format(renewal_of))
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record


def get_access_request(redis, request_id):
    return _load(redis, _request_key(request_id))


def list_access_requests(redis, status=None, user=None, project=None, ticket=None):
    records = []
    for key in redis.keys("access_request_*"):
        decoded_key = decode(key)
        if re.match(r"^access_request_[0-9]+$", decoded_key) is None:
            continue
        record = json.loads(decode(redis.get(key)))
        if status and record.get("status") != status:
            continue
        if user and record.get("requester") != user:
            continue
        if project and record.get("project") != project:
            continue
        if ticket and record.get("ticket") != ticket:
            continue
        records.append(record)
    return sorted(records, key=lambda item: int(item.get("id", 0)), reverse=True)


def approve_access_request(redis, request_id, approver, ttl_seconds, remote_user=None, sudo_mode=None, max_ttl=None, comment=None, starts_at=None):
    ttl_seconds = int(ttl_seconds)
    if ttl_seconds <= 0:
        raise AccessDenied("ttl must be positive")

    def approve(record, reader):
        if record.get("status") != "pending":
            raise AccessDenied("request is already {}".format(record.get("status")))
        now = now_ts()
        requested_start = starts_at if starts_at is not None else record.get("starts_at")
        start, requested_end = _access_window(requested_start, record.get("ends_at"), now=now)
        # A late approval cannot backdate the granted duration into the past.
        start = max(start or now, now)
        expires_at = min(start + ttl_seconds, requested_end) if requested_end is not None else start + ttl_seconds
        if max_ttl is not None and expires_at - start > int(max_ttl):
            raise AccessDenied("ttl exceeds configured maximum")
        grant = {
            "schema_version": 2,
            "subject": "user",
            "name": record["requester"],
            "project": record.get("project"),
            "project_glob": None,
            "project_set": None,
            "host": record.get("host"),
            "remote_user": remote_user or record.get("remote_user"),
            "sudo_mode": sudo_mode or record.get("sudo_mode") or "none",
            "allowed_actions": ["ssh"],
            "temporary": True,
            "starts_at": start,
            "expires_at": expires_at,
            "request_id": str(request_id),
        }
        # A username can be renamed or reassigned; bind verified requests to the
        # immutable Keycloak subject whenever the request has one.
        if record.get("requester_sub"):
            grant["keycloak_sub"] = record["requester_sub"]
        if grant["sudo_mode"] not in ("none", "sudo-i"):
            raise AccessDenied("a valid sudo mode is required")
        grant_id = str(redis.incr("offset_grant_id"))
        record.update({
            "status": "approved", "decided_by": approver.get("username"),
            "decided_at": now, "starts_at": start, "expires_at": expires_at,
            "grant_id": grant_id, "remote_user": grant["remote_user"], "sudo_mode": grant["sudo_mode"],
        })
        _append_comment(record, approver, "approve", comment)
        return (record, grant), [("set", "grant_{}".format(grant_id), grant)]

    return _mutate_request(redis, request_id, approve) or (None, None)


def deny_access_request(redis, request_id, approver, reason=None, comment=None):
    def deny(record, reader):
        if record.get("status") != "pending":
            raise AccessDenied("request is already {}".format(record.get("status")))
        record.update({"status": "denied", "decided_by": approver.get("username"),
                       "decided_at": now_ts(), "decision_reason": reason})
        _append_comment(record, approver, "deny", comment)
        return record, []
    return _mutate_request(redis, request_id, deny)


def comment_access_request(redis, request_id, identity, text, admin_groups=None):
    def comment(record, reader):
        if not can_access_request(record, identity, admin_groups):
            raise AccessDenied("access request is not visible to this user")
        _append_comment(record, identity, "comment", text)
        return record, []
    return _mutate_request(redis, request_id, comment)


def set_notification_status(redis, request_id, status):
    def update(record, reader):
        record["notification_status"] = status
        return record, []
    return _mutate_request(redis, request_id, update)


def repeat_access_request(redis, request_id, identity, reason=None, ticket=None, config=None, admin_groups=None):
    old = get_access_request(redis, request_id)
    if old is None:
        return None
    if not can_access_request(old, identity, admin_groups):
        raise AccessDenied("access request is not visible to this user")
    return create_access_request(
        redis,
        identity,
        project=old.get("project"),
        host=old.get("host"),
        remote_user=old.get("remote_user"),
        sudo_mode=old.get("sudo_mode"),
        reason=reason or old.get("reason"),
        ticket=ticket or old.get("ticket"),
        template=old.get("template"),
        config=config,
    )


def cancel_access_request(redis, request_id, identity):
    def cancel(record, reader):
        _require_owner(record, identity)
        if record.get("status") != "pending":
            raise AccessDenied("only a pending request can be cancelled")
        record.update({"status": "cancelled", "cancelled_by": identity.get("username"), "cancelled_at": now_ts()})
        _append_comment(record, identity, "cancel", "Request cancelled by requester")
        return record, []
    return _mutate_request(redis, request_id, cancel)


def revoke_access_request(redis, request_id, identity, admin_groups=None, reason=None):
    if not is_access_admin(identity, admin_groups):
        raise AccessDenied("revoking access requires an access administrator")

    def revoke(record, reader):
        if record.get("status") != "approved":
            raise AccessDenied("only an approved request can be revoked")
        changes = []
        if record.get("grant_id"):
            grant_key = "grant_{}".format(record["grant_id"])
            if callable(getattr(reader, "watch", None)):
                reader.watch(grant_key)
            grant = _load(reader, grant_key)
            if grant is not None:
                if (str(grant.get("request_id")) != str(record["id"])
                        or grant.get("subject") != "user" or grant.get("name") != record["requester"]):
                    raise AccessDenied("linked grant no longer belongs to this request")
                changes.append(("delete", grant_key, None))
        record.update({"status": "revoked", "revoked_by": identity.get("username"),
                       "revoked_at": now_ts(), "revoke_reason": reason})
        _append_comment(record, identity, "revoke", reason or "Access revoked by administrator")
        return record, changes
    return _mutate_request(redis, request_id, revoke)


def renew_access_request(redis, request_id, identity, reason=None, ticket=None, starts_at=None, ends_at=None, config=None):
    """Create a new pending request; the existing grant is never extended here."""
    old = get_access_request(redis, request_id)
    if old is None:
        return None
    _require_owner(old, identity)
    if old.get("status") != "approved":
        raise AccessDenied("only an approved request can be renewed")
    return create_access_request(
        redis, identity, project=old.get("project"), host=old.get("host"),
        remote_user=old.get("remote_user"), sudo_mode=old.get("sudo_mode"),
        reason=reason or old.get("reason"), ticket=ticket if ticket is not None else old.get("ticket"),
        template=old.get("template"), config=config, starts_at=starts_at, ends_at=ends_at, renewal_of=old["id"],
    )
