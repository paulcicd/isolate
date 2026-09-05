#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Connection history reader for Isolate JSONL audit logs."""

import datetime
import json
import os


class HistoryAccessDenied(Exception):
    pass


def is_history_admin(identity, admin_groups=None):
    return bool(set(identity.get("groups") or []) & set(admin_groups or []))


def _iter_session_files(base_path, users=None):
    users = set(users or [])
    if users:
        roots = [os.path.join(base_path, user) for user in users]
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
        "project": source.get("project"),
        "host_id": source.get("host_id"),
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


def _matches(row, query=None, user=None, project=None, host=None):
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
            row.get("target"),
            row.get("remote_user"),
        ]
        return any(query_l in str(value or "").lower() for value in fields)
    return True


def read_history(base_path, identity, query=None, user=None, project=None, host=None, limit=10, admin_groups=None):
    username = identity.get("username")
    admin = is_history_admin(identity, admin_groups)
    if user and user != username and not admin:
        raise HistoryAccessDenied("history for other users is visible only to admins")

    scan_users = None if admin else [username]
    if user:
        scan_users = [user]

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
        if row and _matches(row, query=query, user=user, project=project, host=host):
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
