#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Break-glass access request helpers."""

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


def create_access_request(redis, identity, project, host=None, remote_user=None, sudo_mode=None, reason=None, ticket=None, template=None, config=None):
    ticket = validate_ticket(ticket, config=config)
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
        "grant_id": None,
    }
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record


def get_access_request(redis, request_id):
    return _load(redis, _request_key(request_id))


def list_access_requests(redis, status=None, user=None, project=None, ticket=None):
    records = []
    for key in redis.keys("access_request_*"):
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


def approve_access_request(redis, request_id, approver, ttl_seconds, remote_user=None, sudo_mode=None, max_ttl=None, comment=None):
    record = get_access_request(redis, request_id)
    if record is None:
        return None, None
    if record.get("status") != "pending":
        raise AccessDenied("request is already {}".format(record.get("status")))
    if max_ttl is not None and ttl_seconds > max_ttl:
        raise AccessDenied("ttl exceeds configured maximum")

    expires_at = now_ts() + int(ttl_seconds)
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
        "expires_at": expires_at,
        "request_id": str(request_id),
    }
    grant_id = redis.incr("offset_grant_id")
    redis.set("grant_{}".format(grant_id), json.dumps(grant, sort_keys=True))

    record.update(
        {
            "status": "approved",
            "decided_by": approver.get("username"),
            "decided_at": now_ts(),
            "expires_at": expires_at,
            "grant_id": str(grant_id),
            "remote_user": grant["remote_user"],
            "sudo_mode": grant["sudo_mode"],
        }
    )
    _append_comment(record, approver, "approve", comment)
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record, grant


def deny_access_request(redis, request_id, approver, reason=None, comment=None):
    record = get_access_request(redis, request_id)
    if record is None:
        return None
    if record.get("status") != "pending":
        raise AccessDenied("request is already {}".format(record.get("status")))
    record.update(
        {
            "status": "denied",
            "decided_by": approver.get("username"),
            "decided_at": now_ts(),
            "decision_reason": reason,
        }
    )
    _append_comment(record, approver, "deny", comment)
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record


def comment_access_request(redis, request_id, identity, text):
    record = get_access_request(redis, request_id)
    if record is None:
        return None
    _append_comment(record, identity, "comment", text)
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record


def set_notification_status(redis, request_id, status):
    record = get_access_request(redis, request_id)
    if record is None:
        return None
    record["notification_status"] = status
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record


def repeat_access_request(redis, request_id, identity, reason=None, ticket=None, config=None):
    old = get_access_request(redis, request_id)
    if old is None:
        return None
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
