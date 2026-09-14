#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Non-interactive host connectivity diagnostics."""

import json
import os
import socket
import subprocess
import time


class ConnectivityError(Exception):
    pass


def check_host(host, config, timeout=3, ssh_auth=False, remote_user=None, connector=None, resolver=None, runner=None):
    connector = connector or socket.create_connection
    resolver = resolver or socket.getaddrinfo
    runner = runner or subprocess.run
    timeout = max(1, min(int(timeout), 30))
    address = str(host.get("server_ip") or "").strip()
    port = int(host.get("server_port") or 22)
    if not address:
        raise ConnectivityError("host address is missing")
    started = time.time()
    record = {
        "host_id": str(host.get("server_id") or ""),
        "project": host.get("project_name"),
        "server_name": host.get("server_name"),
        "address": address,
        "port": port,
        "checked_at": int(started),
        "dns": "skipped",
        "tcp": "failed",
        "ssh": "not-checked",
        "ok": False,
        "error": None,
    }
    try:
        resolved = resolver(address, port, type=socket.SOCK_STREAM)
        record["dns"] = "ok"
        record["resolved_addresses"] = sorted({str(item[4][0]) for item in resolved})
        connection = connector((address, port), timeout=timeout)
        try:
            connection.close()
        except AttributeError:
            pass
        record["tcp"] = "ok"
        record["ok"] = True
    except (OSError, socket.error) as exc:
        record["error"] = str(exc)
    if ssh_auth and record["tcp"] == "ok":
        ssh_cfg = config.get("ssh", {}) or {}
        binary = str(ssh_cfg.get("binary") or "/usr/bin/ssh")
        user = str(remote_user or host.get("server_user") or "").strip()
        if not user:
            raise ConnectivityError("remote user is required for SSH authentication check")
        argv = [binary]
        config_path = ssh_cfg.get("config_path")
        if config_path and os.path.exists(config_path):
            argv.extend(["-F", str(config_path)])
        argv.extend([
            "-o", "BatchMode=yes",
            "-o", "ConnectionAttempts=1",
            "-o", "ConnectTimeout={}".format(timeout),
            "-o", "RequestTTY=no",
            "-o", "StrictHostKeyChecking={}".format("yes" if ssh_cfg.get("require_known_hosts", True) else "accept-new"),
            "-p", str(port),
            "{}@{}".format(user, address),
            "true",
        ])
        try:
            completed = runner(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2, check=False)
            record["ssh"] = "ok" if completed.returncode == 0 else "failed"
            record["ssh_exit_code"] = int(completed.returncode)
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace") if isinstance(completed.stderr, bytes) else str(completed.stderr or "")
                record["error"] = stderr.strip()[-512:] or "SSH authentication failed"
            record["ok"] = completed.returncode == 0
        except (OSError, subprocess.SubprocessError) as exc:
            record["ssh"] = "failed"
            record["error"] = str(exc)
            record["ok"] = False
    record["duration_ms"] = max(0, int((time.time() - started) * 1000))
    return record


def save_check(redis, record, ttl=3600):
    key = "host_check_{}".format(record.get("host_id"))
    redis.set(key, json.dumps(record, sort_keys=True), ex=max(60, int(ttl)))
    return record


def get_last_check(redis, host_id):
    raw = redis.get("host_check_{}".format(host_id))
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw)
