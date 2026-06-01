#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSONL audit logging for Isolate v2."""

import json
import os
import time


def ensure_dir(path, mode=0o700):
    if not os.path.isdir(path):
        os.makedirs(path, mode)
    return path


class SessionLogger(object):
    def __init__(self, base_path, identity, session_id=None):
        self.identity = identity or {}
        self.session_id = session_id or self.identity.get("session_id")
        username = self.identity.get("username") or "unknown"
        self.session_dir = ensure_dir(os.path.join(base_path, username, self.session_id))
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
        return record
