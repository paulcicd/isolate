#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Active SSH session registry backed by Redis."""

import json
import time


class SessionControlError(Exception):
    pass


def decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def active_session_key(connection_id):
    return "active_session_{}".format(connection_id)


def _store(redis, connection_id, record, ttl):
    key = active_session_key(connection_id)
    redis.set(key, json.dumps(record, sort_keys=True), ex=int(ttl))


def _mutate(redis, connection_id, change, ttl=None):
    """Merge a registry change without overwriting a concurrent revoke/close.

    Production Redis clients always expose WATCH/MULTI. The nontransactional
    branch only supports the small in-memory fixtures used by older tests.
    """
    key = active_session_key(connection_id)

    def apply(raw):
        record = json.loads(decode(raw)) if raw is not None else None
        updated = change(record)
        expiry = int(ttl if ttl is not None else (updated or {}).get("registry_ttl", 86400))
        return updated, expiry

    if not hasattr(redis, "pipeline"):
        updated, expiry = apply(redis.get(key))
        if updated is not None:
            _store(redis, connection_id, updated, expiry)
        return updated
    from redis.exceptions import WatchError
    for _ in range(16):
        with redis.pipeline() as pipe:
            try:
                pipe.watch(key)
                updated, expiry = apply(pipe.get(key))
                if updated is None:
                    return None
                pipe.multi()
                pipe.set(key, json.dumps(updated, sort_keys=True), ex=expiry)
                pipe.execute()
                return updated
            except WatchError:
                continue
    raise SessionControlError("session registry changed too frequently; retry the operation")


def mark_session_start(redis, connection_id, metadata, ttl=86400):
    record = dict(metadata or {})
    record.update(
        {
            "connection_id": connection_id,
            "status": "active",
            "started_at": record.get("started_at") or int(time.time()),
            "registry_ttl": int(ttl),
        }
    )
    _store(redis, connection_id, record, ttl)
    return record


def get_session(redis, connection_id):
    raw = redis.get(active_session_key(connection_id))
    return json.loads(decode(raw)) if raw is not None else None


def touch_session(redis, connection_id, ttl=86400, now=None):
    def change(record):
        if record is None or record.get("status") != "active":
            return None
        record["heartbeat_at"] = int(time.time() if now is None else now)
        record["registry_ttl"] = int(ttl)
        return record
    return _mutate(redis, connection_id, change)


def request_session_termination(redis, connection_id, actor, reason=None):
    def change(record):
        if record is None or record.get("status") != "active":
            raise SessionControlError("active session was not found")
        record.update({
            "terminate_requested": True,
            "terminate_requested_at": int(time.time()),
            "terminate_requested_by": (actor or {}).get("username") or (actor or {}).get("keycloak_sub"),
            "terminate_reason": str(reason or "administrator request")[:1024],
        })
        return record
    return _mutate(redis, connection_id, change)


def termination_requested(redis, connection_id):
    record = get_session(redis, connection_id)
    return bool(record and record.get("status") == "active" and record.get("terminate_requested"))


def mark_alert_sent(redis, connection_id, alert_name):
    def change(record):
        if record is None:
            return None
        sent = list(record.get("alerts_sent") or [])
        if alert_name not in sent:
            sent.append(alert_name)
        record["alerts_sent"] = sent
        return record
    return _mutate(redis, connection_id, change)


def mark_alert_delivery(redis, connection_id, alert_name, result):
    def change(record):
        if record is None:
            return None
        deliveries = list(record.get("alert_deliveries") or [])
        deliveries.append({
            "alert": str(alert_name),
            "ts": int(time.time()),
            "sent": list((result or {}).get("sent") or []),
            "errors": list((result or {}).get("errors") or []),
            "ok": not bool((result or {}).get("errors")),
        })
        record["alert_deliveries"] = deliveries[-50:]
        return record
    return _mutate(redis, connection_id, change)


def mark_session_end(redis, connection_id, exit_code=None):
    def change(record):
        if record is None:
            return None
        record.update({"status": "completed", "ended_at": int(time.time()), "exit_code": exit_code,
                       "registry_ttl": 3600})
        return record
    return _mutate(redis, connection_id, change, ttl=3600)


def list_session_records(redis, active_only=False):
    records = []
    for key in redis.keys("active_session_*"):
        raw = redis.get(key)
        if raw is None:
            continue
        record = json.loads(decode(raw))
        if not active_only or record.get("status") == "active":
            started_at = int(record.get("started_at") or 0)
            record["duration_seconds"] = max(0, int(time.time()) - started_at) if started_at else None
            records.append(record)
    return sorted(records, key=lambda row: row.get("started_at") or 0, reverse=True)


def list_active_sessions(redis):
    return list_session_records(redis, active_only=True)
