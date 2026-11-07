#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Connection history reader for Isolate JSONL audit logs."""

import datetime
import json
import os
import math
from collections import Counter


class HistoryAccessDenied(Exception):
    pass


def is_history_admin(identity, admin_groups=None):
    return bool(set(identity.get("groups") or []) & set(admin_groups or []))


def _iter_session_files(base_path, users=None):
    users = set(users or [])
    if users:
        base = os.path.realpath(base_path)
        roots = []
        for user in users:
            candidate = os.path.realpath(os.path.join(base, str(user)))
            if candidate != base and os.path.commonpath([base, candidate]) == base:
                roots.append(candidate)
    else:
        roots = [base_path]
    for root in roots:
        if not os.path.isdir(root):
            continue
        for current_root, _, files in os.walk(root):
            if "session.jsonl" in files:
                yield os.path.join(current_root, "session.jsonl")


def _load_events(path):
    events = []
    with open(path, "r", encoding="utf-8") as session_f:
        for line in session_f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


def _row_from_events(events):
    selected = None
    ssh_start = None
    ssh_end = None
    for event in events:
        if event.get("event") == "policy_selected":
            selected = event
        elif event.get("event") == "ssh_start":
            ssh_start = event
        elif event.get("event") == "ssh_end":
            ssh_end = event

    source = selected or ssh_start or ssh_end
    if source is None:
        return None

    result = "selected"
    if ssh_start and not ssh_end:
        result = "started"
    if ssh_end:
        result = "exit={}".format(ssh_end.get("exit_code"))

    return {
        "ts": source.get("ts"),
        "time": format_ts(source.get("ts")),
        "username": source.get("username"),
        "keycloak_sub": source.get("keycloak_sub") or (ssh_start or {}).get("keycloak_sub"),
        "project": source.get("project"),
        "host_id": source.get("host_id"),
        "server_name": source.get("server_name") or source.get("host_name"),
        "target": source.get("target_host"),
        "remote_user": source.get("remote_user"),
        "connection_id": source.get("connection_id"),
        "session_id": source.get("session_id"),
        "raw_log_path": (ssh_end or ssh_start or {}).get("raw_log_path"),
        "result": result,
    }


def _connection_key(event):
    connection_id = event.get("connection_id")
    if connection_id:
        return str(connection_id)
    if event.get("event") in ("policy_selected", "ssh_start", "ssh_end", "command") and event.get("session_id"):
        return str(event["session_id"])
    return None


def parse_history_time(value, end_of_day=False):
    """Parse a Unix timestamp, UTC calendar date or ISO time with an offset."""
    if value in (None, ""):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        text = str(value).strip()
        try:
            if len(text) == 10:
                parsed = datetime.datetime.combine(datetime.date.fromisoformat(text), datetime.time(), datetime.timezone.utc)
                result = parsed.timestamp() + (86400 - 0.000001 if end_of_day else 0)
            else:
                parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise ValueError("timezone required")
                result = parsed.timestamp()
        except (ValueError, OverflowError) as exc:
            raise ValueError("history time must be a UTC date, Unix timestamp, or ISO 8601 time with timezone") from exc
    if not math.isfinite(result):
        raise ValueError("history time must be finite")
    return result


def _matches(row, query=None, user=None, project=None, host=None, since=None, until=None, result=None):
    timestamp = float(row.get("ts") or 0)
    if since is not None and timestamp < since:
        return False
    if until is not None and timestamp > until:
        return False
    outcome = row.get("result") or ""
    if result == "success" and outcome != "exit=0":
        return False
    if result == "failure" and (not outcome.startswith("exit=") or outcome in ("exit=0", "exit=None")):
        return False
    if result and result not in ("success", "failure") and outcome != result:
        return False
    if user and row.get("username") != user:
        return False
    if project and row.get("project") != project:
        return False
    if host and str(host) not in (str(row.get("host_id")), str(row.get("target"))):
        return False
    if query:
        query_l = str(query).lower()
        fields = [
            row.get("username"),
            row.get("project"),
            row.get("host_id"),
            row.get("server_name"),
            row.get("target"),
            row.get("remote_user"),
        ]
        return any(query_l in str(value or "").lower() for value in fields)
    return True


def read_history(base_path, identity, query=None, user=None, project=None, host=None, limit=10, admin_groups=None, since=None, until=None, result=None, permission_config=None):
    since = parse_history_time(since)
    until = parse_history_time(until, end_of_day=True)
    if since is not None and until is not None and since > until:
        raise ValueError("history start must not be after end")
    if result and result not in ("success", "failure", "started", "selected"):
        import re
        if not re.fullmatch(r"exit=-?\d+", str(result)):
            raise ValueError("history result must be success, failure, started, selected, or exit=<code>")
    limit = int(limit)
    if not 1 <= limit <= 10000:
        raise ValueError("history limit must be between 1 and 10000")
    username = identity.get("username")
    admin = is_history_admin(identity, admin_groups)
    from isolate_permissions import has_permission
    scoped_audit = permission_config is not None and has_permission(identity, permission_config, "audit.read")
    if user and user != username and not (admin or scoped_audit):
        raise HistoryAccessDenied("history for other users is visible only to admins")

    scan_users = None if admin or scoped_audit else [username]
    if user:
        scan_users = [user]
    # Stable OIDC subjects remain owners after a username change. The final
    # filter checks each record; legacy records retain username-based ownership.
    if not admin and identity.get("keycloak_sub"):
        scan_users = None

    grouped_events = {}
    for path in _iter_session_files(base_path, users=scan_users):
        events = _load_events(path)
        keyed = False
        for event in events:
            key = _connection_key(event)
            if key:
                keyed = True
                grouped_events.setdefault(key, []).append(event)
        if not keyed and _row_from_events(events) is not None:
            grouped_events["legacy-file:{}".format(path)] = events

    rows = []
    for events in grouped_events.values():
        events.sort(key=lambda event: float(event.get("ts") or 0))
        row = _row_from_events(events)
        owned = row and (row.get("keycloak_sub") == identity.get("keycloak_sub") if row.get("keycloak_sub") else row.get("username") == username)
        visible = row and (admin or (
            bool(row.get("project")) and has_permission(identity, permission_config, "audit.read", row["project"])
            if scoped_audit else owned
        ))
        if row and visible and _matches(
            row, query=query, user=user if admin or scoped_audit else None, project=project, host=host, since=since, until=until, result=result
        ):
            rows.append(row)

    rows = sorted(rows, key=lambda row: row.get("ts") or 0, reverse=True)
    return rows[:limit]


def format_ts(ts):
    if ts is None:
        return ""
    return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


def format_history_table(rows):
    columns = [
        ("time", "time", 19),
        ("username", "user", 14),
        ("project", "project", 12),
        ("host_id", "host_id", 7),
        ("server_name", "host_name", 18),
        ("target", "target", 16),
        ("remote_user", "remote_user", 12),
        ("result", "result", 10),
    ]
    lines = []
    header = "  ".join(label.ljust(width) for _, label, width in columns)
    lines.append(header)
    for row in rows:
        lines.append("  ".join(str(row.get(key) or "").ljust(width) for key, _, width in columns))
    return "\n".join(lines)


def list_user_profiles(base_path):
    profiles = {}
    connections = {}
    for path in _iter_session_files(base_path):
        events = _load_events(path)
        for event in events:
            username = event.get("username")
            if not username:
                continue
            profile = profiles.setdefault(username, {
                "username": username,
                "keycloak_sub": None,
                "groups": [],
                "roles": [],
                "last_seen": 0,
                "connection_count": 0,
            })
            ts = float(event.get("ts") or 0)
            if ts >= float(profile.get("last_seen") or 0):
                profile["last_seen"] = ts
                profile["keycloak_sub"] = event.get("keycloak_sub") or profile.get("keycloak_sub")
                if event.get("event") == "policy_selected" and event.get("groups") is not None:
                    profile["groups"] = sorted(set(event.get("groups") or []))
                elif event.get("groups"):
                    profile["groups"] = sorted(set(event.get("groups") or []))
                if event.get("event") == "policy_selected" and event.get("roles") is not None:
                    profile["roles"] = sorted(set(event.get("roles") or []))
                elif event.get("roles"):
                    profile["roles"] = sorted(set(event.get("roles") or []))
            connection_id = _connection_key(event)
            if connection_id:
                connections.setdefault(username, set()).add(connection_id)
    for username, profile in profiles.items():
        profile["connection_count"] = len(connections.get(username) or set())
    return sorted(profiles.values(), key=lambda row: row.get("last_seen") or 0, reverse=True)


def user_activity_summary(base_path, username, limit=10, active_sessions=None, grants=None, access_requests=None):
    """Build a compact activity view from existing audit and authorization data."""
    identity = {"username": str(username), "groups": ["__activity_reader__"]}
    rows = read_history(
        base_path,
        identity,
        user=str(username),
        limit=max(1, int(limit)),
        admin_groups=["__activity_reader__"],
    )
    profiles = {row.get("username"): row for row in list_user_profiles(base_path)}
    profile = profiles.get(str(username), {
        "username": str(username), "groups": [], "roles": [], "connection_count": 0, "last_seen": 0,
    })
    project_counts = Counter(str(row.get("project") or "unknown") for row in rows)
    failed = sum(1 for row in rows if str(row.get("result") or "").startswith("exit=") and row.get("result") != "exit=0")
    active = [row for row in (active_sessions or []) if row.get("username") == username]
    subject_pairs = {("user", str(username))}
    subject_pairs.update(("group", group) for group in profile.get("groups") or [])
    subject_pairs.update(("role", role) for role in profile.get("roles") or [])
    effective_grants = [row for row in (grants or []) if (row.get("subject"), row.get("name")) in subject_pairs]
    requests = [row for row in (access_requests or []) if row.get("requester") == username]
    return {
        "profile": profile,
        "metrics": {
            "connections": int(profile.get("connection_count") or len(rows)),
            "recent_failures": failed,
            "active_sessions": len(active),
            "grant_candidates": len(effective_grants),
            "access_requests": len(requests),
        },
        "top_projects": [{"project": name, "connections": count} for name, count in project_counts.most_common(5)],
        "recent_sessions": rows,
        "active_sessions": active,
        "grants": effective_grants,
        "access_requests": sorted(requests, key=lambda row: int(row.get("created_at") or 0), reverse=True)[:10],
    }
