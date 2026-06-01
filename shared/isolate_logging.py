#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSONL audit logging for Isolate v2."""

import json
import os
import time

try:
    import grp
except ImportError:  # pragma: no cover - Windows test/dev environments
    grp = None


def ensure_dir(path, mode=0o700, group=None):
    effective_mode = mode if os.name == "posix" else 0o700
    if not os.path.isdir(path):
        if os.name == "posix":
            os.makedirs(path, effective_mode)
        else:
            os.makedirs(path)
    if os.name == "posix":
        try:
            os.chmod(path, effective_mode)
        except PermissionError:
            pass
    if group and grp is not None:
        try:
            os.chown(path, -1, grp.getgrnam(group).gr_gid)
        except PermissionError:
            pass
        except KeyError:
            pass
    return path


class SessionLogger(object):
    def __init__(self, base_path, identity, session_id=None):
        self.identity = identity or {}
        self.session_id = session_id or self.identity.get("session_id")
        username = self.identity.get("username") or "unknown"
        self.user_dir = ensure_dir(os.path.join(base_path, username), 0o2770, group="auth")
        self.session_dir = ensure_dir(os.path.join(self.user_dir, self.session_id), 0o2770, group="auth")
        self.jsonl_path = os.path.join(self.session_dir, "session.jsonl")

    def event(self, event_type, **fields):
        record = {
            "ts": time.time(),
            "event": event_type,
            "session_id": self.session_id,
            "keycloak_sub": self.identity.get("keycloak_sub"),
            "username": self.identity.get("username"),
            "groups": self.identity.get("groups", []),
        }
        record.update(fields)
        with open(self.jsonl_path, "a", encoding="utf-8") as log_f:
            log_f.write(json.dumps(record, sort_keys=True) + "\n")
        if os.name == "posix":
            try:
                os.chmod(self.jsonl_path, 0o660)
            except PermissionError:
                pass
        return record
