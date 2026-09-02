#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Redis-backed asynchronous command jobs for Isolate MCP."""

import hashlib
import hmac
import json
import os
import re
import shlex
import signal
import subprocess
import time

from isolate_audit import prepare_and_dispatch
from isolate_inventory import get_host
from isolate_policy import PolicyDenied, resolve_grant
from isolate_ssh import SSHArgumentError, build_ssh_argv


class JobError(Exception):
    pass


SIGNED_JOB_FIELDS = (
    "schema_version", "id", "type", "username", "keycloak_sub", "groups", "roles",
    "project", "host_id", "target_host", "target_port", "remote_user", "sudo_mode",
    "grant_id", "command", "command_sha256", "timeout", "created_at",
)


def decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def now_ts():
    return int(time.time())


def _job_key(job_id):
    return "job_{}".format(job_id)


def _save(redis, record):
    redis.set(_job_key(record["id"]), json.dumps(record, sort_keys=True))
    return record


def _signing_key(config):
    path = (config.get("command_execution", {}) or {}).get("signing_key_file")
    if not path:
        raise JobError("command execution signing key is not configured")
    try:
        with open(path, "rb") as key_f:
            key = key_f.read().strip()
    except OSError as exc:
        raise JobError("cannot read command execution signing key") from exc
    if len(key) < 32:
        raise JobError("command execution signing key is too short")
    return key


def _signature_payload(record):
    return json.dumps(
        {name: record.get(name) for name in SIGNED_JOB_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sign_job(record, config):
    record["authorization_signature"] = hmac.new(
        _signing_key(config), _signature_payload(record), hashlib.sha256
    ).hexdigest()
    return record


def verify_job_signature(record, config):
    expected = hmac.new(_signing_key(config), _signature_payload(record), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(record.get("authorization_signature") or ""), expected)


def get_job(redis, job_id):
    raw = redis.get(_job_key(job_id))
    return json.loads(decode(raw)) if raw is not None else None


def list_jobs(redis, user=None, status=None, limit=50):
    rows = []
    for key in redis.keys("job_*"):
        if re.match(r"^job_[0-9]+$", decode(key)) is None:
            continue
        record = get_job(redis, decode(key).split("_", 1)[1])
        if user and record.get("username") != user:
            continue
        if status and record.get("status") != status:
            continue
        rows.append(record)
    rows.sort(key=lambda row: int(row.get("id", 0)), reverse=True)
    return rows[: max(1, int(limit))]


def validate_command(command, config):
    execution = config.get("command_execution", {}) or {}
    command = str(command or "").strip()
    if not command:
        raise JobError("command is required")
    if "\x00" in command:
        raise JobError("command contains a NUL byte")
    if len(command) > int(execution.get("max_command_length", 4096)):
        raise JobError("command exceeds configured maximum length")
    if execution.get("allow_arbitrary_commands", False):
        return command
    patterns = execution.get("allowed_command_patterns") or []
    if not patterns or not any(re.fullmatch(pattern, command) for pattern in patterns):
        raise JobError("command does not match an allowed command pattern")
    return command


def create_command_job(redis, config, identity, host, decision, command, timeout=None):
    execution = config.get("command_execution", {}) or {}
    command = validate_command(command, config)
    timeout = int(timeout or execution.get("default_timeout", 60))
    if timeout <= 0 or timeout > int(execution.get("max_timeout", 900)):
        raise JobError("timeout is outside the configured range")
    job_id = redis.incr("offset_job_id")
    matched = decision.get("matched_rule") or {}
    record = {
        "schema_version": 1,
        "id": str(job_id),
        "type": "remote-command",
        "status": "queued",
        "username": identity.get("username"),
        "keycloak_sub": identity.get("keycloak_sub"),
        "groups": identity.get("groups") or [],
        "roles": identity.get("roles") or [],
        "project": host.get("project_name"),
        "host_id": str(host.get("server_id")),
        "target_host": host.get("server_ip"),
        "target_port": int(host.get("server_port") or 22),
        "remote_user": decision.get("remote_user"),
        "sudo_mode": decision.get("sudo_mode") or "none",
        "grant_id": matched.get("id"),
        "command": command,
        "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
        "timeout": timeout,
        "created_at": now_ts(),
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "error": None,
        "cancel_requested": False,
        "output_path": None,
        "output_bytes": 0,
        "output_truncated": False,
    }
    sign_job(record, config)
    return _save(redis, record)


def request_job_cancel(redis, job_id, actor):
    record = get_job(redis, job_id)
    if record is None:
        return None
    if record.get("status") in ("completed", "failed", "cancelled", "timed_out"):
        raise JobError("job is already {}".format(record.get("status")))
    record["cancel_requested"] = True
    record["cancel_requested_by"] = actor.get("username")
    record["cancel_requested_at"] = now_ts()
    if record.get("status") == "queued":
        record["status"] = "cancelled"
        record["finished_at"] = now_ts()
    return _save(redis, record)


def read_job_output(record, max_bytes=None, jobs_path=None, job_id=None):
    if jobs_path is not None:
        selected_id = str(job_id or (record or {}).get("id") or "")
        if re.fullmatch(r"[0-9]+", selected_id) is None:
            raise JobError("invalid job id")
        path = os.path.join(os.path.realpath(jobs_path), "job-{}.log".format(selected_id))
    else:
        path = (record or {}).get("output_path")
    if not path or not os.path.isfile(path):
        return ""
    with open(path, "rb") as output_f:
        data = output_f.read(int(max_bytes)) if max_bytes else output_f.read()
    return data.decode("utf-8", errors="replace")


def _audit(config, event, record, extra=None):
    payload = {
        "event": event,
        "ts": time.time(),
        "job_id": record.get("id"),
        "username": record.get("username"),
        "keycloak_sub": record.get("keycloak_sub"),
        "project": record.get("project"),
        "host_id": record.get("host_id"),
        "remote_user": record.get("remote_user"),
        "command_sha256": record.get("command_sha256"),
        "source": "isolate-job-worker",
    }
    payload.update(extra or {})
    prepare_and_dispatch(payload, config.get("logging", {}))


def _load_json_records(redis, pattern, prefix):
    records = []
    for key in redis.keys(pattern):
        decoded_key = decode(key)
        if re.match(r"^{}[0-9]+$".format(re.escape(prefix)), decoded_key) is None:
            continue
        raw = redis.get(key)
        if raw is None:
            continue
        record = json.loads(decode(raw))
        record.setdefault("id", decoded_key[len(prefix):])
        records.append(record)
    return records


def _load_project_sets(redis):
    result = {}
    for key in redis.keys("project_set_*"):
        raw = redis.get(key)
        if raw is None:
            continue
        record = json.loads(decode(raw))
        result[record.get("name") or decode(key)[len("project_set_"):]] = record
    return result


def _fail_job(redis, config, record, error):
    record.update({"status": "failed", "error": str(error), "finished_at": now_ts()})
    _save(redis, record)
    _audit(config, "job_end", record, {"status": "failed", "error": str(error)})
    return record


def _terminate_process(proc):
    if proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass


def _remote_command(record, execution):
    shell = execution.get("remote_shell", "/bin/sh")
    command = "{} -lc {}".format(shlex.quote(shell), shlex.quote(record["command"]))
    if record.get("sudo_mode") == "sudo-i":
        command = "sudo -n -i -- {}".format(command)
    return command


def execute_job(redis, config, record):
    execution = config.get("command_execution", {}) or {}
    lock_key = "job_lock_{}".format(record["id"])
    if not redis.set(lock_key, str(os.getpid()), nx=True, ex=int(record["timeout"]) + 60):
        return None
    current = get_job(redis, record["id"])
    if current is None or current.get("status") != "queued" or current.get("cancel_requested"):
        return current
    try:
        if not verify_job_signature(current, config):
            return _fail_job(redis, config, current, "job authorization signature is invalid")
    except JobError as exc:
        return _fail_job(redis, config, current, exc)

    host = get_host(redis, current["host_id"])
    if host is None:
        return _fail_job(redis, config, current, "host no longer exists")
    if (
        host.get("project_name") != current.get("project")
        or host.get("server_ip") != current.get("target_host")
        or int(host.get("server_port") or 22) != int(current.get("target_port") or 22)
    ):
        return _fail_job(redis, config, current, "host routing changed after the job was queued")
    if not execution.get("enabled", False):
        return _fail_job(redis, config, current, "command execution was disabled after the job was queued")
    if not (set(current.get("groups") or []) & set(execution.get("allowed_groups") or [])):
        return _fail_job(redis, config, current, "submitter group is no longer allowed by command execution config")
    try:
        validate_command(current.get("command"), config)
        decision = resolve_grant(
            {
                "username": current.get("username"),
                "keycloak_sub": current.get("keycloak_sub"),
                "groups": current.get("groups") or [],
                "roles": current.get("roles") or [],
            },
            project=host.get("project_name"),
            host=host,
            grants=_load_json_records(redis, "grant_*", "grant_"),
            project_sets=_load_project_sets(redis),
            defaults={**config.get("policy", {}), **config.get("ssh", {})},
            action="command",
        )
    except (JobError, PolicyDenied) as exc:
        return _fail_job(redis, config, current, "command authorization changed: {}".format(exc))
    if decision.get("remote_user") != current.get("remote_user") or decision.get("sudo_mode") != current.get("sudo_mode"):
        return _fail_job(redis, config, current, "command remote identity changed after the job was queued")
    if decision.get("sudo_mode") == "sudo-i" and not execution.get("allow_sudo", False):
        return _fail_job(redis, config, current, "sudo command execution is disabled")
    proxy = None
    if host.get("proxy_id"):
        proxy_host = get_host(redis, host["proxy_id"])
        if proxy_host is None:
            return _fail_job(redis, config, current, "proxy host no longer exists")
        proxy = {
            "host": proxy_host.get("server_ip"),
            "port": proxy_host.get("server_port") or 22,
            "user": proxy_host.get("server_user"),
        }

    jobs_path = execution.get("jobs_path", "/opt/auth/jobs")
    os.makedirs(jobs_path, mode=0o700, exist_ok=True)
    output_path = os.path.join(jobs_path, "job-{}.log".format(current["id"]))
    ssh_config = dict(config.get("ssh", {}) or {})
    ssh_config["allocate_tty"] = False
    try:
        argv = build_ssh_argv(
            ssh_config,
            {
                "hostname": host.get("server_ip"),
                "port": host.get("server_port") or 22,
                "user": current.get("remote_user"),
            },
            proxy=proxy,
            remote_command=_remote_command(current, execution),
        )
    except SSHArgumentError as exc:
        return _fail_job(redis, config, current, "SSH arguments are invalid: {}".format(exc))
    claim_path = os.path.join(jobs_path, ".job-{}.claimed".format(current["id"]))
    try:
        claim_fd = os.open(claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(claim_fd, "w", encoding="ascii") as claim_f:
            claim_f.write("{}\n".format(now_ts()))
    except FileExistsError:
        return _fail_job(redis, config, current, "job has already been claimed for execution")
    current.update({"status": "running", "started_at": now_ts(), "output_path": output_path})
    _save(redis, current)
    _audit(config, "job_start", current)

    max_output = int(execution.get("max_output_bytes", 1048576))
    deadline = time.monotonic() + int(current["timeout"])
    status = "failed"
    error = None
    written = 0
    with open(output_path, "wb") as output_f:
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except OSError as exc:
            return _fail_job(redis, config, current, "cannot start SSH process: {}".format(exc))
        os.set_blocking(proc.stdout.fileno(), False)
        while True:
            chunk = b""
            try:
                chunk = os.read(proc.stdout.fileno(), 65536)
            except BlockingIOError:
                pass
            if chunk:
                remaining = max_output - written
                if remaining > 0:
                    output_f.write(chunk[:remaining])
                    output_f.flush()
                    written += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    _terminate_process(proc)
                    status = "failed"
                    error = "command output exceeded configured maximum"
                    break
            latest = get_job(redis, current["id"]) or current
            if latest.get("cancel_requested"):
                _terminate_process(proc)
                status = "cancelled"
                break
            if time.monotonic() >= deadline:
                _terminate_process(proc)
                status = "timed_out"
                error = "command timed out"
                break
            if proc.poll() is not None and not chunk:
                status = "completed" if proc.returncode == 0 else "failed"
                break
            time.sleep(0.25)
        proc.stdout.close()

    size = os.path.getsize(output_path)
    current = get_job(redis, current["id"]) or current
    current.update(
        {
            "status": status,
            "finished_at": now_ts(),
            "exit_code": proc.returncode,
            "error": error,
            "output_path": output_path,
            "output_bytes": size,
            "output_truncated": error == "command output exceeded configured maximum",
        }
    )
    _save(redis, current)
    _audit(config, "job_end", current, {"status": status, "exit_code": proc.returncode, "output_bytes": size})
    return current


def run_worker(config, redis, once=False):
    execution = config.get("command_execution", {}) or {}
    poll = max(float(execution.get("poll_interval", 1)), 0.1)
    while True:
        queued = list_jobs(redis, status="queued", limit=100)
        for record in reversed(queued):
            execute_job(redis, config, record)
        if once:
            return
        time.sleep(poll)
