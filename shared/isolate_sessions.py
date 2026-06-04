#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Active SSH session registry backed by Redis."""

import json
import time


def decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def active_session_key(connection_id):
    return "active_session_{}".format(connection_id)


def mark_session_start(redis, connection_id, metadata, ttl=86400):
    record = dict(metadata or {})
    record.update(
        {
            "connection_id": connection_id,
            "status": "active",
            "started_at": record.get("started_at") or int(time.time()),
        }
    )
    redis.set(active_session_key(connection_id), json.dumps(record, sort_keys=True))
    try:
        redis.expire(active_session_key(connection_id), int(ttl))
    except AttributeError:
        pass
    return record


def mark_session_end(redis, connection_id, exit_code=None):
    key = active_session_key(connection_id)
    raw = redis.get(key)
    if raw is None:
        return None
    record = json.loads(decode(raw))
    record.update({"status": "completed", "ended_at": int(time.time()), "exit_code": exit_code})
    redis.set(key, json.dumps(record, sort_keys=True))
    try:
        redis.expire(key, 3600)
    except AttributeError:
        pass
    return record


def list_active_sessions(redis):
    records = []
    for key in redis.keys("active_session_*"):
        raw = redis.get(key)
        if raw is None:
            continue
        record = json.loads(decode(raw))
        if record.get("status") == "active":
            records.append(record)
    return sorted(records, key=lambda row: row.get("started_at") or 0, reverse=True)
