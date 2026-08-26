#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Structured command audit helpers."""

import json
import os
import time

from isolate_replay import find_session


class CommandAuditError(Exception):
    pass


def _first_context(events):
    for event in events:
        if event.get("event") in ("policy_selected", "ssh_start", "ssh_end"):
            return event
    return events[0] if events else {}


def append_command_event(base_path, connection_id, command, cwd=None, exit_code=None, project=None, host_id=None, shell=None, source=None, config=None):
    audit_cfg = (config or {}).get("command_audit", {})
    if not audit_cfg.get("enabled", False):
        raise CommandAuditError("command audit is disabled")
    if audit_cfg.get("require_connection_id", True) and not connection_id:
        raise CommandAuditError("connection_id is required")

    details = find_session(base_path, connection_id)
    if details is None:
        raise CommandAuditError("session not found for connection_id {}".format(connection_id))

    command = str(command or "")
    max_len = int(audit_cfg.get("max_command_length", 4096))
    truncated = False
    if len(command) > max_len:
        command = command[:max_len]
        truncated = True

    events = details.get("events") or []
    context = _first_context(events)
    record = {
        "ts": time.time(),
        "event": "command",
        "session_id": context.get("session_id"),
        "connection_id": connection_id,
        "keycloak_sub": context.get("keycloak_sub"),
        "username": context.get("username"),
        "groups": context.get("groups", []),
        "project": project or context.get("project"),
        "host_id": host_id or context.get("host_id"),
        "cwd": cwd,
        "command": command,
        "command_truncated": truncated,
        "exit_code": int(exit_code) if exit_code is not None else None,
        "shell": shell or "unknown",
        "source": source or "target-shell-hook",
    }
    with open(details["session_path"], "a", encoding="utf-8") as session_f:
        session_f.write(json.dumps(record, sort_keys=True) + "\n")
    if os.name == "posix":
        try:
            os.chmod(details["session_path"], 0o660)
        except PermissionError:
            pass
    return record
