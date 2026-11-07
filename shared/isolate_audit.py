#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Best-effort structured audit signing and central sink dispatch."""

import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import socket
import stat
import uuid


class AuditSinkError(Exception):
    pass


def classify_audit_record(record):
    result = dict(record)
    tags = set(result.get("risk_tags") or [])
    event = str(result.get("event") or "")
    remote_user = str(result.get("remote_user") or "").lower()
    policy = result.get("policy") or {}
    if not isinstance(policy, dict):
        policy = {}
    sudo_mode = str(result.get("sudo_mode") or policy.get("sudo_mode") or "none").lower()
    if remote_user == "root" or sudo_mode not in ("", "none", "false", "disabled"):
        tags.add("privileged")
    if result.get("server_vip"):
        tags.add("vip")
    if "denied" in event:
        tags.add("denied")
    if result.get("temporary") or result.get("request_id"):
        tags.add("break-glass")
    if tags:
        result["risk_tags"] = sorted(tags)
    return result


def _canonical_bytes(record):
    unsigned = {key: value for key, value in record.items() if not key.startswith("integrity_")}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_audit_record(record, logging_config):
    result = dict(record)
    integrity = (logging_config or {}).get("integrity") or {}
    if not isinstance(integrity, dict):
        raise AuditSinkError("logging.integrity must be an object")
    if not integrity.get("enabled"):
        return result
    key_path = integrity.get("key_file")
    try:
        with open(key_path, "rb") as key_f:
            key = key_f.read().strip()
    except (OSError, TypeError) as exc:
        raise AuditSinkError("cannot read audit integrity key: {}".format(exc))
    if not key:
        raise AuditSinkError("audit integrity key is empty")
    result["integrity_alg"] = "hmac-sha256"
    result["integrity_key_id"] = integrity.get("key_id") or "isolate-audit-v1"
    result["integrity_signature"] = hmac.new(key, _canonical_bytes(result), hashlib.sha256).hexdigest()
    return result


def verify_audit_record(record, key):
    signature = record.get("integrity_signature")
    if not signature:
        return False
    expected = hmac.new(key, _canonical_bytes(record), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(signature), expected)


def verify_jsonl_file(path, key_file):
    with open(key_file, "rb") as key_f:
        key = key_f.read().strip()
    checked = 0
    invalid = []
    with open(path, "r", encoding="utf-8") as audit_f:
        for line_number, line in enumerate(audit_f, 1):
            if not line.strip():
                continue
            checked += 1
            try:
                record = json.loads(line)
            except ValueError:
                invalid.append({"line": line_number, "reason": "invalid JSON"})
                continue
            if not verify_audit_record(record, key):
                invalid.append({"line": line_number, "reason": "invalid or missing signature"})
    return {"valid": not invalid, "checked": checked, "invalid": invalid}


def append_jsonl_record(path, record, mode=0o640, sync=False):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, mode=0o750, exist_ok=True)
    payload = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, mode)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditSinkError("audit destination must be a regular file")
        if os.name == "posix":
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        remaining = memoryview(payload)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise OSError("short audit log write")
            remaining = remaining[count:]
        if sync:
            os.fsync(fd)
    finally:
        os.close(fd)
    if sync and parent and os.name == "posix":
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _send_syslog(sink, record):
    address = sink.get("address")
    if isinstance(address, str) and ":" in address and not address.startswith("/"):
        host, port = address.rsplit(":", 1)
        address = (host, int(port))
    socktype = socket.SOCK_STREAM if str(sink.get("protocol", "udp")).lower() == "tcp" else socket.SOCK_DGRAM
    facility_name = str(sink.get("facility", "authpriv")).lower()
    facility = logging.handlers.SysLogHandler.facility_names.get(facility_name, logging.handlers.SysLogHandler.LOG_AUTHPRIV)
    handler = logging.handlers.SysLogHandler(address=address, facility=facility, socktype=socktype)
    try:
        handler.setFormatter(logging.Formatter("%(message)s"))
        log_record = logging.LogRecord(
            name="isolate-audit-sink",
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg=json.dumps(record, sort_keys=True),
            args=(),
            exc_info=None,
        )
        handler.emit(log_record)
    finally:
        handler.close()


def dispatch_audit_record(record, logging_config):
    results = {"sent": [], "errors": []}
    sinks = (logging_config or {}).get("sinks") or []
    if not isinstance(sinks, list):
        sinks = []
        results["errors"].append("logging.sinks must be a list")
    for sink in sinks:
        sink_type = sink.get("type") if isinstance(sink, dict) else None
        try:
            if not isinstance(sink, dict):
                raise AuditSinkError("audit sink must be an object")
            if sink_type == "jsonl":
                append_jsonl_record(sink["path"], record, sync=bool((logging_config or {}).get("sync", False)))
            elif sink_type == "syslog":
                _send_syslog(sink, record)
            elif sink_type == "sql":
                from isolate_audit_index import AuditIndex
                AuditIndex(sink).ingest(record)
            else:
                raise AuditSinkError("unsupported audit sink type: {}".format(sink_type))
            results["sent"].append(sink_type)
        except Exception as exc:
            results["errors"].append("{}: {}".format(sink_type or "unknown", exc))
    if results["errors"] and (logging_config or {}).get("fail_closed", False):
        raise AuditSinkError("; ".join(results["errors"]))
    return results


def prepare_and_dispatch(record, logging_config):
    record = classify_audit_record(record)
    # The same signed event can appear in both the runtime spool and a session
    # file. Generate its identity before signing so exporters can correlate it.
    record.setdefault("event_id", str(uuid.uuid4()))
    try:
        prepared = sign_audit_record(record, logging_config)
    except AuditSinkError:
        if (logging_config or {}).get("fail_closed", False):
            raise
        prepared = dict(record)
        prepared["integrity_error"] = "signing failed"
    dispatch_audit_record(prepared, logging_config)
    return prepared
