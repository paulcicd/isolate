#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Break-glass access request helpers."""

import json
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


def _request_key(request_id):
    return "access_request_{}".format(request_id)


def _load(redis, key):
    raw = redis.get(key)
    if raw is None:
        return None
    return json.loads(decode(raw))


def create_access_request(redis, identity, project, host=None, remote_user=None, sudo_mode=None, reason=None):
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


def list_access_requests(redis, status=None, user=None):
    records = []
    for key in redis.keys("access_request_*"):
        record = json.loads(decode(redis.get(key)))
        if status and record.get("status") != status:
            continue
        if user and record.get("requester") != user:
            continue
        records.append(record)
    return sorted(records, key=lambda item: int(item.get("id", 0)), reverse=True)


def approve_access_request(redis, request_id, approver, ttl_seconds, remote_user=None, sudo_mode=None, max_ttl=None):
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
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record, grant


def deny_access_request(redis, request_id, approver, reason=None):
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
    redis.set(_request_key(request_id), json.dumps(record, sort_keys=True))
    return record
