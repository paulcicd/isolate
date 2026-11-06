#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSONL audit logging for Isolate v2."""

import os
import time

from isolate_audit import append_jsonl_record, prepare_and_dispatch

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
    def __init__(self, base_path, identity, session_id=None, logging_config=None):
        self.identity = identity or {}
        self.logging_config = logging_config or {}
        self.session_id = session_id or self.identity.get("session_id")
        username = self.identity.get("username") or "unknown"
        for value in (username, self.session_id):
            if not isinstance(value, str) or not value or value in (".", "..") or any(char in value for char in ("/", "\\", "\x00", ":")):
                raise ValueError("invalid audit path component")
        self.user_dir = ensure_dir(os.path.join(base_path, username), 0o2770, group="auth")
        self.session_dir = ensure_dir(os.path.join(self.user_dir, self.session_id), 0o2770, group="auth")
        self.jsonl_path = os.path.join(self.session_dir, "session.jsonl")

    def event(self, event_type, **fields):
        return self._event(event_type, fields)

    def event_durable(self, event_type, **fields):
        """Require successful signing/sink dispatch and fsync before execution."""
        return self._event(event_type, fields, durable=True)

    def _event(self, event_type, fields, durable=False):
        record = {
            "ts": time.time(),
            "event": event_type,
            "session_id": self.session_id,
            "keycloak_sub": self.identity.get("keycloak_sub"),
            "username": self.identity.get("username"),
            "groups": self.identity.get("groups", []),
        }
        record.update(fields)
        logging_config = dict(self.logging_config)
        if durable:
            logging_config.update(fail_closed=True, sync=True)
        record = prepare_and_dispatch(record, logging_config)
        append_jsonl_record(self.jsonl_path, record, mode=0o660, sync=durable)
        if durable and os.name == "posix":
            # Persist newly created user/session directory entries as well.
            for path in (self.user_dir, os.path.dirname(self.user_dir)):
                directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        if os.name == "posix":
            try:
                os.chmod(self.jsonl_path, 0o660)
            except PermissionError:
                pass
        return record
