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
from isolate_identity import IdentityError
from isolate_inventory import get_host
from isolate_policy import PolicyDenied, resolve_grant
from isolate_runbooks import RunbookError, render_runbook
from isolate_ssh import SSHArgumentError, build_ssh_argv
from isolate_worker_ownership import (
    JobOwnershipError, claim_job, claim_key, mark_recovery_required, mutate_job,
    owner_token, release_lock, update_owned_job,
)


class JobError(Exception):
    pass


FAILED_JOB_STATUSES = ("failed", "timed_out")


SIGNED_JOB_FIELDS_V1 = (
    "schema_version", "id", "type", "username", "keycloak_sub", "groups", "roles",
    "project", "host_id", "target_host", "target_port", "remote_user", "sudo_mode",
    "grant_id", "command", "command_sha256", "timeout", "created_at",
)

SIGNED_RUNBOOK_FIELDS = (
    "runbook_id", "runbook_class", "runbook_parameters", "policy_action",
    "runbook_definition_sha256",
)

SIGNED_DELEGATION_FIELDS = ("delegation_id", "delegation_expires_at", "delegation_epoch", "principal_type", "service_client_id", "proxy_id")
SIGNED_CAMPAIGN_FIELDS = ("campaign_id", "campaign_stage", "campaign_slot")

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
    fields = SIGNED_JOB_FIELDS_V1
    if int(record.get("schema_version") or 1) >= 2:
        fields += SIGNED_RUNBOOK_FIELDS
    if int(record.get("schema_version") or 1) >= 3:
        fields += SIGNED_DELEGATION_FIELDS
    if int(record.get("schema_version") or 1) >= 4:
        fields += SIGNED_CAMPAIGN_FIELDS
    return json.dumps(
        {name: record.get(name) for name in fields},
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


def _reject_gated_job(redis, config, host, decision, delegated=False):
    """Unattended execution must not bypass a human per-connection gate."""
    security = config.get("identity_security", {})
    if not delegated and ((security.get("backchannel_logout") or {}).get("enabled")
            or (security.get("introspection") or {}).get("enabled")
            or (security.get("membership") or {}).get("enabled")):
        raise JobError("unattended jobs require delegated Keycloak identity lifecycle support; "
                       "jobs are disabled while centralized identity revocation is enabled")
    from isolate_identity_security import step_up_required
    if not delegated and step_up_required(config, host, decision):
        raise JobError("target requires fresh step-up authentication; unattended jobs are not permitted")
    from isolate_session_approvals import SessionApprovalDenied, session_approval_required
    try:
        required = session_approval_required(config, host, decision)
        if host.get("proxy_id"):
            proxy_host = get_host(redis, host["proxy_id"])
            if proxy_host is None:
                raise JobError("proxy host no longer exists")
            required = required or session_approval_required(config, proxy_host, {
                "remote_user": proxy_host.get("server_user"), "sudo_mode": "none"})
    except SessionApprovalDenied as exc:
        raise JobError(str(exc)) from exc
    if required:
        raise JobError("target requires human session approval; unattended jobs are not permitted")


def _job_identity(redis, config, identity, token, host, decision, action):
    from isolate_delegation import submission_identity
    try:
        effective, selected = submission_identity(redis, config, identity, token, host, decision, action)
        from isolate_governance import check_governance_access
        check_governance_access(redis, effective, host.get('project_name'))
        return effective, selected
    except (IdentityError, PolicyDenied, ValueError) as exc:
        raise JobError("delegated Keycloak identity or current policy could not be authorized") from exc


def _attach_job_delegation(redis, config, record, identity, token, host, decision):
    from isolate_delegation import attach_delegation
    try:
        return attach_delegation(redis, config, record, identity, token, host, decision)
    except IdentityError as exc:
        raise JobError("delegated Keycloak authorization could not be stored") from exc


def create_command_job(redis, config, identity, host, decision, command, timeout=None, token=None):
    from isolate_delegation import attach_delegation, options, submission_identity
    delegated = bool(token and options(config).get("enabled"))
    _reject_gated_job(redis, config, host, decision, delegated=delegated)
    identity, decision = _job_identity(redis, config, identity, token, host, decision, "command")
    execution = config.get("command_execution", {}) or {}
    if delegated and not execution.get("enabled", False):
        raise JobError("command execution is disabled")
    if delegated and not set(identity.get("groups") or []).intersection(execution.get("allowed_groups") or []) and identity.get("principal_type") != "service":
        raise JobError("current identity is not in an allowed command execution group")
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
    record["proxy_id"] = host.get("proxy_id")
    record['access_request_id'] = matched.get('request_id') or matched.get('access_request_id')
    from isolate_investigations import identity_session_reference
    record['identity_session_sha256'] = identity_session_reference(identity)
    _attach_job_delegation(redis, config, record, identity, token, host, decision)
    sign_job(record, config)
    return _save(redis, record)


def create_runbook_job(redis, config, identity, host, decision, rendered, timeout=None, token=None, *, publish=True, campaign=None):
    from isolate_delegation import attach_delegation, options, submission_identity
    _reject_gated_job(redis, config, host, decision, delegated=bool(token and options(config).get("enabled")))
    identity, decision = _job_identity(redis, config, identity, token, host, decision, rendered["policy_action"])
    from isolate_identity_security import assert_workload_action
    try:
        assert_workload_action(config, identity, rendered["policy_action"], rendered["runbook"]["class"])
    except IdentityError as exc:
        raise JobError(str(exc)) from exc
    if token and options(config).get("enabled"):
        runbooks = config.get("runbooks") or {}
        class_config = runbooks.get(rendered["runbook"]["class"]) or {}
        if not runbooks.get("enabled") or (rendered["runbook"]["class"] == "operational" and not class_config.get("enabled")):
            raise JobError("runbook execution is disabled")
        if identity.get("principal_type") != "service" and not set(identity.get("groups") or []).intersection(class_config.get("allowed_groups") or []):
            raise JobError("current identity is not allowed for this runbook class")
    execution = config.get("command_execution", {}) or {}
    runbook = rendered["runbook"]
    timeout = int(timeout or runbook.get("default_timeout") or execution.get("default_timeout", 60))
    if timeout <= 0 or timeout > int(execution.get("max_timeout", 900)):
        raise JobError("timeout is outside the configured range")
    command = rendered["command"]
    job_id = redis.incr("offset_job_id")
    matched = decision.get("matched_rule") or {}
    record = {
        "schema_version": 2,
        "id": str(job_id),
        "type": "runbook",
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
        "runbook_id": runbook["id"],
        "runbook_class": runbook["class"],
        "runbook_parameters": rendered["parameters"],
        "policy_action": rendered["policy_action"],
        "runbook_definition_sha256": runbook["definition_sha256"],
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
    record["proxy_id"] = host.get("proxy_id")
    record['access_request_id'] = matched.get('request_id') or matched.get('access_request_id')
    from isolate_investigations import identity_session_reference
    record['identity_session_sha256'] = identity_session_reference(identity)
    if campaign is not None:
        if (not isinstance(campaign, dict) or set(campaign) != set(SIGNED_CAMPAIGN_FIELDS)
                or re.fullmatch(r'[a-f0-9]{32}', str(campaign.get('campaign_id', ''))) is None
                or type(campaign.get('campaign_stage')) is not int or campaign['campaign_stage'] < 0
                or type(campaign.get('campaign_slot')) is not int or campaign['campaign_slot'] < 0):
            raise JobError('invalid campaign binding')
        record.update(campaign, schema_version=4, status='held')
    _attach_job_delegation(redis, config, record, identity, token, host, decision)
    sign_job(record, config)
    return _save(redis, record) if publish else record


def _runbook_submission_plan(redis, config, identity, runbook_id, host_ids, parameters=None, timeout=None, token=None):
    runbooks = config.get("runbooks", {}) or {}
    if not runbooks.get("enabled", False):
        raise JobError("runbooks are disabled")
    try:
        rendered = render_runbook(config, runbook_id, parameters)
    except RunbookError as exc:
        raise JobError(str(exc)) from exc
    runbook = rendered["runbook"]
    class_config = runbooks.get(runbook["class"], {}) or {}
    if runbook["class"] == "operational" and not class_config.get("enabled", False):
        raise JobError("operational runbooks are disabled pending security review")
    if identity.get("principal_type") != "service" and not (set(identity.get("groups") or []) & set(class_config.get("allowed_groups") or [])):
        raise JobError("identity is not in an allowed {} runbook group".format(runbook["class"]))
    selected_ids = []
    for host_id in host_ids:
        host_id = str(host_id).strip()
        if host_id and host_id not in selected_ids:
            selected_ids.append(host_id)
    maximum = int(runbooks.get("max_fleet_hosts") or 100)
    if not selected_ids:
        raise JobError("at least one host id is required")
    if len(selected_ids) > maximum:
        raise JobError("fleet exceeds configured maximum of {} hosts".format(maximum))
    grants = _load_json_records(redis, "grant_*", "grant_")
    project_sets = _load_project_sets(redis)
    defaults = {**config.get("policy", {}), **config.get("ssh", {})}
    planned = []
    for host_id in selected_ids:
        host = get_host(redis, host_id)
        if host is None:
            raise JobError("host {} was not found".format(host_id))
        try:
            decision = resolve_grant(
                identity,
                project=host.get("project_name"),
                host=host,
                grants=grants,
                project_sets=project_sets,
                defaults=defaults,
                action=rendered["policy_action"],
            )
        except PolicyDenied as exc:
            raise JobError("host {} is not allowed: {}".format(host_id, exc)) from exc
        if decision.get("sudo_mode") == "sudo-i" and not class_config.get("allow_sudo", False):
            raise JobError("sudo execution is disabled for this runbook class")
        from isolate_delegation import options, submission_identity
        _reject_gated_job(redis, config, host, decision, delegated=bool(token and options(config).get("enabled")))
        identity, decision = _job_identity(redis, config, identity, token, host, decision, rendered["policy_action"])
        from isolate_identity_security import assert_workload_action
        try:
            assert_workload_action(config, identity, rendered["policy_action"], runbook["class"])
        except IdentityError as exc:
            raise JobError(str(exc)) from exc
        if identity.get("principal_type") != "service" and not set(identity.get("groups") or []).intersection(class_config.get("allowed_groups") or []):
            raise JobError("current identity is no longer allowed for this runbook class")
        _reject_gated_job(redis, config, host, decision, delegated=bool(token and options(config).get("enabled")))
        planned.append((host, decision))
    return rendered, planned, timeout


def create_runbook_fleet(redis, config, identity, runbook_id, host_ids, parameters=None, timeout=None, confirmed=False, token=None):
    """Queue a runbook for multiple hosts after validating the entire fleet."""
    rendered, planned, timeout = _runbook_submission_plan(
        redis, config, identity, runbook_id, host_ids, parameters=parameters, timeout=timeout, token=token
    )
    class_config = (config.get("runbooks", {}) or {}).get(rendered["runbook"]["class"], {}) or {}
    if class_config.get("require_confirmation", True) and not confirmed:
        raise JobError("explicit confirmation is required to queue this runbook")
    fleet_id = str(redis.incr("offset_fleet_id"))
    jobs = []
    for index, (host, decision) in enumerate(planned, start=1):
        job = create_runbook_job(redis, config, identity, host, decision, rendered, timeout=timeout, token=token)
        job.update({
            "fleet_id": fleet_id,
            "fleet_index": index,
            "fleet_size": len(planned),
            "fleet_slot": str(host.get("server_id")),
            "retry_of": None,
            "attempt": 1,
        })
        sign_job(job, config)
        jobs.append(_save(redis, job))
    _audit(config, "fleet_queued", jobs[0], {
        "fleet_id": fleet_id,
        "runbook_id": rendered["runbook"]["id"],
        "host_count": len(jobs),
    })
    return {"fleet_id": fleet_id, "jobs": jobs, "count": len(jobs)}


def retry_job(redis, config, original_job_id, actor, current_identity=None, token=None):
    """Requeue a terminal failed job using its original identity and current policy."""
    original = get_job(redis, original_job_id)
    if original is None:
        raise JobError("job was not found")
    if original.get('campaign_id') or int(original.get('schema_version') or 1) >= 4:
        raise JobError('campaign children cannot be retried independently; review the outcome and create a fresh campaign')
    if original.get("status") not in FAILED_JOB_STATUSES:
        raise JobError("only failed or timed-out jobs can be retried")
    if not verify_job_signature(original, config):
        raise JobError("job authorization signature is invalid")
    if original.get("delegation_id") and not token:
        raise JobError("retrying a delegated job requires fresh submitter authorization")
    identity = {
        "username": original.get("username"),
        "keycloak_sub": original.get("keycloak_sub"),
        "groups": original.get("groups") or [],
        "roles": original.get("roles") or [],
    }
    if current_identity is not None:
        if (original.get("keycloak_sub") and current_identity.get("keycloak_sub") != original.get("keycloak_sub")
                or not original.get("keycloak_sub") and current_identity.get("username") != original.get("username")):
            raise JobError("retry identity must match the original submitter")
        identity = dict(current_identity)
    host = get_host(redis, original.get("host_id"))
    if host is None:
        raise JobError("host no longer exists")
    grants = _load_json_records(redis, "grant_*", "grant_")
    project_sets = _load_project_sets(redis)
    defaults = {**config.get("policy", {}), **config.get("ssh", {})}
    if original.get("type") == "runbook":
        rendered, planned, timeout = _runbook_submission_plan(
            redis,
            config,
            identity,
            original.get("runbook_id"),
            [original.get("host_id")],
            parameters=original.get("runbook_parameters") or {},
            timeout=original.get("timeout"), token=token,
        )
        retried = create_runbook_job(redis, config, identity, planned[0][0], planned[0][1], rendered, timeout=timeout, token=token)
    elif original.get("type") == "remote-command":
        execution = config.get("command_execution", {}) or {}
        if not execution.get("enabled", False):
            raise JobError("command execution is disabled")
        if not (set(identity.get("groups") or []) & set(execution.get("allowed_groups") or [])):
            raise JobError("submitter group is no longer allowed by command execution config")
        try:
            decision = resolve_grant(
                identity,
                project=host.get("project_name"),
                host=host,
                grants=grants,
                project_sets=project_sets,
                defaults=defaults,
                action="command",
            )
        except PolicyDenied as exc:
            raise JobError("job authorization changed: {}".format(exc)) from exc
        retried = create_command_job(
            redis, config, identity, host, decision, original.get("command"), timeout=original.get("timeout"), token=token
        )
    else:
        raise JobError("unsupported job type")
    retried.update({
        "fleet_id": original.get("fleet_id"),
        "fleet_index": original.get("fleet_index"),
        "fleet_size": original.get("fleet_size"),
        "fleet_slot": original.get("fleet_slot") or str(original.get("host_id")),
        "retry_of": str(original.get("id")),
        "attempt": int(original.get("attempt") or 1) + 1,
        "retried_by": (actor or {}).get("username") or (actor or {}).get("keycloak_sub"),
    })
    sign_job(retried, config)
    _save(redis, retried)
    _audit(config, "job_retried", retried, {
        "retry_of": str(original.get("id")),
        "retried_by": retried.get("retried_by"),
        "fleet_id": retried.get("fleet_id"),
    })
    return retried


def request_job_cancel(redis, job_id, actor):
    def change(record):
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
        return record
    return mutate_job(redis, job_id, change)


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
        "runbook_id": record.get("runbook_id"),
        "runbook_class": record.get("runbook_class"),
        "campaign_id": record.get("campaign_id"),
        "grant_id": record.get("grant_id"),
        "access_request_id": record.get("access_request_id"),
        "delegation_id": record.get("delegation_id"),
        "identity_session_sha256": record.get("identity_session_sha256"),
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
    lock_key = "job_lock_{}".format(record["id"])
    owner = owner_token()
    if not redis.set(lock_key, owner, nx=True, ex=int(record["timeout"]) + 60):
        return None
    try:
        current = get_job(redis, record["id"])
        if current and (current.get("status") in ("claimed", "running")
                        or redis.get(claim_key(record["id"])) is not None):
            recovered = mark_recovery_required(redis, record["id"], owner)
            if recovered and recovered.get("status") == "recovery_required":
                _audit(config, "job_recovery_required", recovered)
            return recovered
        return _execute_job_locked(redis, config, record, owner)
    finally:
        release_lock(redis, lock_key, owner)


def _execute_job_locked(redis, config, record, owner):
    execution = config.get("command_execution", {}) or {}
    current = get_job(redis, record["id"])
    if current is None or current.get("status") != "queued" or current.get("cancel_requested"):
        return current
    try:
        if not verify_job_signature(current, config):
            return _fail_job(redis, config, current, "job authorization signature is invalid")
        from isolate_campaigns import check_campaign_job
        check_campaign_job(redis, config, current)
    except (JobError, ValueError) as exc:
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
    job_type = current.get("type")
    policy_action = "command"
    authorization_config = execution
    try:
        effective_identity = {"username": current.get("username"), "keycloak_sub": current.get("keycloak_sub"),
                              "groups": current.get("groups") or [], "roles": current.get("roles") or []}
        if current.get("delegation_id"):
            from isolate_delegation import recheck_delegation
            effective_identity, _ = recheck_delegation(redis, config, current, host)
        from isolate_governance import check_governance_access
        check_governance_access(redis, effective_identity, host.get('project_name'))
        if job_type == "remote-command":
            if not execution.get("enabled", False):
                raise JobError("command execution was disabled after the job was queued")
            if effective_identity.get("principal_type") != "service" and not (set(effective_identity.get("groups") or []) & set(execution.get("allowed_groups") or [])):
                raise JobError("submitter group is no longer allowed by command execution config")
            validate_command(current.get("command"), config)
        elif job_type == "runbook":
            runbooks = config.get("runbooks", {}) or {}
            if not runbooks.get("enabled", False):
                raise JobError("runbooks were disabled after the job was queued")
            rendered = render_runbook(config, current.get("runbook_id"), current.get("runbook_parameters"))
            runbook = rendered["runbook"]
            authorization_config = runbooks.get(runbook["class"], {}) or {}
            if runbook["class"] == "operational" and not authorization_config.get("enabled", False):
                raise JobError("operational runbooks were disabled after the job was queued")
            if effective_identity.get("principal_type") != "service" and not (set(effective_identity.get("groups") or []) & set(authorization_config.get("allowed_groups") or [])):
                raise JobError("submitter group is no longer allowed for this runbook class")
            if (
                rendered["command"] != current.get("command")
                or rendered["policy_action"] != current.get("policy_action")
                or runbook["class"] != current.get("runbook_class")
                or runbook["definition_sha256"] != current.get("runbook_definition_sha256")
            ):
                raise JobError("runbook definition changed after the job was queued")
            policy_action = rendered["policy_action"]
        else:
            raise JobError("unsupported job type")
        decision = resolve_grant(
            effective_identity,
            project=host.get("project_name"),
            host=host,
            grants=_load_json_records(redis, "grant_*", "grant_"),
            project_sets=_load_project_sets(redis),
            defaults={**config.get("policy", {}), **config.get("ssh", {})},
            action=policy_action,
        )
    except (JobError, PolicyDenied, RunbookError, IdentityError, ValueError) as exc:
        return _fail_job(redis, config, current, "job authorization changed: {}".format(exc))
    if decision.get("remote_user") != current.get("remote_user") or decision.get("sudo_mode") != current.get("sudo_mode"):
        return _fail_job(redis, config, current, "command remote identity changed after the job was queued")
    if decision.get("sudo_mode") == "sudo-i" and not authorization_config.get("allow_sudo", False):
        return _fail_job(redis, config, current, "sudo execution is disabled for this job class")
    try:
        _reject_gated_job(redis, config, host, decision, delegated=bool(current.get("delegation_id")))
    except JobError as exc:
        return _fail_job(redis, config, current, exc)
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
    try:
        current = claim_job(redis, current["id"], owner)
    except JobOwnershipError:
        return get_job(redis, record["id"])
    if current is None:
        return get_job(redis, record["id"])
    claim_path = os.path.join(jobs_path, ".job-{}.claimed".format(current["id"]))
    try:
        claim_fd = os.open(claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(claim_fd, "w", encoding="ascii") as claim_f:
            claim_f.write("{}\n".format(now_ts()))
    except FileExistsError:
        current = update_owned_job(redis, current["id"], owner, {
            "status": "recovery_required", "recovery_required_at": now_ts(),
            "error": "A local execution claim already exists; inspect the remote outcome",
        })
        _audit(config, "job_recovery_required", current)
        return current
    current = update_owned_job(redis, current["id"], owner,
                               {"status": "running", "started_at": now_ts(), "output_path": output_path})
    if current.get("cancel_requested"):
        current = update_owned_job(redis, current["id"], owner,
                                   {"status": "cancelled", "finished_at": now_ts()})
        _audit(config, "job_end", current, {"status": "cancelled"})
        return current
    if current.get("delegation_id"):
        try:
            from isolate_delegation import recheck_delegation
            live_host = get_host(redis, current["host_id"])
            recheck_delegation(redis, config, current, live_host or {})
        except Exception:
            return _fail_job(redis, config, current, "delegated authorization failed before execution")
    try:
        from isolate_campaigns import check_campaign_job
        check_campaign_job(redis, config, current)
    except ValueError:
        return _fail_job(redis, config, current, 'campaign authorization failed before execution')
    _audit(config, "job_start", current)

    max_output = int(execution.get("max_output_bytes", 1048576))
    deadline = time.monotonic() + int(current["timeout"])
    status = "failed"
    error = None
    written = 0
    next_identity_check = 0
    delegation_interval = max(0.25, min(10, float((config.get("identity_security", {}).get("delegation") or {}).get("recheck_interval", 2))))
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
            live_owner = redis.get('job_lock_' + current['id'])
            live_owner = live_owner.decode() if isinstance(live_owner, bytes) else live_owner
            if (live_owner != owner or latest.get('execution_owner') != owner
                    or latest.get('status') == 'recovery_required'):
                _terminate_process(proc)
                proc.stdout.close()
                return latest
            try:
                from isolate_governance import check_governance_access
                check_governance_access(redis, effective_identity, current.get('project'))
            except Exception:
                _terminate_process(proc)
                status = 'cancelled'
                error = 'job access was revoked or the control store became unavailable'
                break
            if latest.get("cancel_requested"):
                _terminate_process(proc)
                status = "cancelled"
                break
            if current.get('campaign_id'):
                try:
                    from isolate_campaigns import check_campaign_job
                    check_campaign_job(redis, config, current)
                except Exception:
                    _terminate_process(proc)
                    status = 'cancelled'
                    error = 'campaign was stopped, expired or became unavailable'
                    break
            if current.get("delegation_id") and time.monotonic() >= next_identity_check:
                try:
                    from isolate_delegation import recheck_delegation
                    live_host = get_host(redis, current["host_id"])
                    live_identity, live_decision = recheck_delegation(redis, config, current, live_host or {})
                    _reject_gated_job(redis, config, live_host or {}, live_decision, delegated=True)
                    if live_identity.get("principal_type") != "service" and not set(live_identity.get("groups") or []).intersection(authorization_config.get("allowed_groups") or []):
                        raise JobError("current identity is not allowed for this job class")
                    next_identity_check = time.monotonic() + delegation_interval
                except Exception:
                    _terminate_process(proc)
                    status = "cancelled"
                    error = "delegated authorization was revoked, expired or became unavailable"
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
    updates = {
            "status": status,
            "finished_at": now_ts(),
            "exit_code": proc.returncode,
            "error": error,
            "output_path": output_path,
            "output_bytes": size,
            "output_truncated": error == "command output exceeded configured maximum",
        }
    if current.get('campaign_id'):
        from isolate_campaigns import terminal_result_receipt
        updates['campaign_result'] = terminal_result_receipt(redis, config, current, updates, owner)
    try:
        current = update_owned_job(redis, current["id"], owner, updates)
    except JobOwnershipError:
        return get_job(redis, current['id'])
    _audit(config, "job_end", current, {"status": status, "exit_code": proc.returncode, "output_bytes": size})
    return current


def run_worker(config, redis, once=False):
    execution = config.get("command_execution", {}) or {}
    poll = max(float(execution.get("poll_interval", 1)), 0.1)
    while True:
        from isolate_campaigns import reconcile_campaigns
        reconcile_campaigns(redis, config)
        # A crashed owner's job is no longer queued. Surface its ambiguous
        # result without automatically repeating a possibly completed command.
        for status in ("claimed", "running"):
            for record in list_jobs(redis, status=status, limit=100):
                if redis.get("job_lock_" + str(record["id"])) is None:
                    execute_job(redis, config, record)
        queued = list_jobs(redis, status="queued", limit=100)
        for record in reversed(queued):
            execute_job(redis, config, record)
            reconcile_campaigns(redis, config)
        if once:
            return
        time.sleep(poll)
