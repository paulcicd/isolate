#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scoped operational announcements stored in Redis."""

import json
import time


class AnnouncementError(Exception):
    pass


def _decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _load(redis, key):
    raw = redis.get(key)
    if raw is None:
        return None
    record = json.loads(_decode(raw))
    record["id"] = str(record.get("id") or _decode(key).replace("announcement_", "", 1))
    return record


def announcement_is_active(record, now=None):
    now = int(now if now is not None else time.time())
    starts_at = int(record.get("starts_at") or 0)
    expires_at = int(record.get("expires_at") or 0)
    return (not starts_at or starts_at <= now) and (not expires_at or expires_at > now)


def create_announcement(redis, text, created_by, project=None, host=None, severity="info", starts_at=None, expires_at=None):
    text = str(text or "").strip()
    if not text or len(text) > 2048:
        raise AnnouncementError("announcement text must contain between 1 and 2048 characters")
    severity = str(severity or "info").lower()
    if severity not in ("info", "warning", "critical"):
        raise AnnouncementError("severity must be info, warning, or critical")
    if project and host:
        raise AnnouncementError("use either project or host scope, not both")
    if host and redis.get("server_{}".format(host)) is None:
        raise AnnouncementError("announcement host not found: {}".format(host))
    starts_at = int(starts_at or 0) or None
    expires_at = int(expires_at or 0) or None
    if starts_at and expires_at and expires_at <= starts_at:
        raise AnnouncementError("expires_at must be later than starts_at")
    redis.set("offset_announcement_id", 0, nx=True)
    announcement_id = str(redis.incr("offset_announcement_id"))
    record = {
        "schema_version": 2,
        "id": announcement_id,
        "text": text,
        "severity": severity,
        "project": str(project).strip() if project else None,
        "host": str(host).strip() if host else None,
        "starts_at": starts_at,
        "expires_at": expires_at,
        "created_at": int(time.time()),
        "created_by": str(created_by or "unknown"),
    }
    redis.set("announcement_{}".format(announcement_id), json.dumps(record, sort_keys=True))
    return record


def list_announcements(redis, project=None, host=None, active_only=False, now=None):
    rows = []
    for key in redis.keys("announcement_*"):
        key_name = _decode(key)
        if not key_name.replace("announcement_", "", 1).isdigit():
            continue
        record = _load(redis, key)
        if record is None:
            continue
        if active_only and not announcement_is_active(record, now=now):
            continue
        if project is not None and record.get("project") not in (None, "", str(project)):
            continue
        if host is not None and record.get("host") not in (None, "", str(host)):
            continue
        rows.append(record)
    return sorted(rows, key=lambda row: (int(row.get("created_at") or 0), int(row.get("id") or 0)), reverse=True)


def announcements_for_host(redis, host, now=None):
    host = host or {}
    return list_announcements(
        redis,
        project=host.get("project_name"),
        host=host.get("server_id"),
        active_only=True,
        now=now,
    )


def delete_announcement(redis, announcement_id):
    if _load(redis, "announcement_{}".format(announcement_id)) is None:
        raise AnnouncementError("announcement not found: {}".format(announcement_id))
    redis.delete("announcement_{}".format(announcement_id))
    return {"id": str(announcement_id), "deleted": True}
