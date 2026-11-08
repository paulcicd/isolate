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
    def __init__(self, base_path, identity, session_id=None, logging_config=None, archive_config=None, state_client=None):
        self.identity = identity or {}
        self.logging_config = logging_config or {}
        self.session_id = session_id or self.identity.get("session_id")
        self._private_capture = bool((archive_config or {}).get("recordings", {}).get("enabled"))
        if self._private_capture:
            from isolate_recordings import capture_root
            base_path = capture_root(archive_config)
        username = self.identity.get("username") or "unknown"
        for value in (username, self.session_id):
            if not isinstance(value, str) or not value or value in (".", "..") or any(char in value for char in ("/", "\\", "\x00", ":")):
                raise ValueError("invalid audit path component")
        if self._private_capture:
            from isolate_recordings import _directory
            self.user_dir = _directory(os.path.join(base_path, username))
            self.session_dir = _directory(os.path.join(self.user_dir, self.session_id))
        else:
            self.user_dir = ensure_dir(os.path.join(base_path, username), 0o2770, group="auth")
            self.session_dir = ensure_dir(os.path.join(self.user_dir, self.session_id), 0o2770, group="auth")
        self.jsonl_path = os.path.join(self.session_dir, "session.jsonl")
        self.archive = None
        self._archive_metadata = {}
        if (archive_config or {}).get("recordings", {}).get("enabled"):
            from isolate_recordings import RecordingArchive
            self.archive = RecordingArchive(archive_config, state_client=state_client)

    def archive_file(self, path, artifact="terminal.log", closed=False):
        """Queue append-only bytes locally; the publisher performs network I/O."""
        if self.archive:
            return self.archive.enqueue_file(self.session_id, artifact, path,
                metadata=self._archive_metadata, closed=closed)
        return None

    def close_archive(self, raw_log_path=None):
        if self.archive:
            if raw_log_path and os.path.isfile(raw_log_path):
                self.archive_file(raw_log_path)
                if os.path.isfile(raw_log_path + ".meta"):
                    self.archive_file(raw_log_path + ".meta", artifact="terminal.log.meta")
            return self.archive_file(self.jsonl_path, artifact="session.jsonl", closed=True)
        return None

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
        append_jsonl_record(self.jsonl_path, record, mode=0o600 if self._private_capture else 0o660, sync=durable)
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
                os.chmod(self.jsonl_path, 0o600 if self._private_capture else 0o660)
            except PermissionError:
                pass
        if self.archive:
            from isolate_recordings import METADATA
            self._archive_metadata.update({key: value for key, value in record.items() if key in METADATA and value is not None})
            if event_type in ("ssh_start", "protocol_start"):
                self._archive_metadata["started_at"] = record["ts"]
            if event_type in ("ssh_end", "protocol_end"):
                self._archive_metadata["ended_at"] = record["ts"]
            self.archive_file(self.jsonl_path, artifact="session.jsonl")
        return record
