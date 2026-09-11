#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Configuration validation and local health checks."""

import os
import re
import ipaddress

from isolate_redis import create_redis_client


SUPPORTED_AUDIT_SINKS = {"jsonl", "syslog"}


def validate_config(config, check_paths=False):
    errors = []
    warnings = []

    def section(name):
        value = config.get(name, {})
        if not isinstance(value, dict):
            errors.append("{} must be an object".format(name))
            return {}
        return value

    redis_cfg = section("redis")
    keycloak = section("keycloak")
    logging_cfg = section("logging")
    dashboard = section("dashboard")
    access_packages = section("access_packages")
    mcp = section("mcp")
    command_execution = section("command_execution")
    runbooks = section("runbooks")
    command_audit = section("command_audit")
    session_control = section("session_control")
    policy_as_code = section("policy_as_code")
    backup = section("backup")

    try:
        redis_port = int(redis_cfg.get("port", 6379))
        if not 1 <= redis_port <= 65535:
            errors.append("redis.port must be between 1 and 65535")
    except (TypeError, ValueError):
        errors.append("redis.port must be an integer")

    if redis_cfg.get("ssl") and not redis_cfg.get("ssl_ca_certs"):
        warnings.append("redis.ssl is enabled without ssl_ca_certs")
    if redis_cfg.get("ssl") and redis_cfg.get("ssl_check_hostname", True) is False:
        warnings.append("redis.ssl_check_hostname is disabled")

    if not keycloak.get("issuer"):
        warnings.append("keycloak.issuer is not configured")
    elif not re.match(r"^https://", str(keycloak.get("issuer")), re.I):
        warnings.append("keycloak.issuer does not use HTTPS")
    if not keycloak.get("client_id"):
        errors.append("keycloak.client_id is required")

    sinks = logging_cfg.get("sinks") or []
    if not isinstance(sinks, list):
        errors.append("logging.sinks must be a list")
        sinks = []
    for index, sink in enumerate(sinks):
        if not isinstance(sink, dict):
            errors.append("logging.sinks[{}] must be an object".format(index))
            continue
        sink_type = sink.get("type")
        if sink_type not in SUPPORTED_AUDIT_SINKS:
            errors.append("logging.sinks[{}] has unsupported type: {}".format(index, sink_type))
        elif sink_type == "jsonl" and not sink.get("path"):
            errors.append("logging.sinks[{}].path is required for jsonl".format(index))
        elif sink_type == "syslog" and not sink.get("address"):
            errors.append("logging.sinks[{}].address is required for syslog".format(index))

    integrity = logging_cfg.get("integrity") or {}
    if integrity.get("enabled") and not integrity.get("key_file"):
        errors.append("logging.integrity.key_file is required when integrity is enabled")
    if check_paths and integrity.get("enabled") and integrity.get("key_file") and not os.path.isfile(integrity["key_file"]):
        errors.append("audit integrity key does not exist: {}".format(integrity["key_file"]))
    elif check_paths and integrity.get("enabled") and os.name == "posix":
        key_mode = os.stat(integrity["key_file"]).st_mode & 0o777
        if key_mode & 0o077:
            errors.append("audit integrity key must be owner-only (0600 or stricter)")

    try:
        retention_days = int(logging_cfg.get("retention_days", 90))
        if retention_days < 1:
            errors.append("logging.retention_days must be greater than zero")
    except (TypeError, ValueError):
        errors.append("logging.retention_days must be an integer")

    if dashboard.get("enabled"):
        if not dashboard.get("public_url"):
            errors.append("dashboard.public_url is required when dashboard is enabled")
        secret_path = dashboard.get("secret_key_file")
        if check_paths and (not secret_path or not os.path.isfile(secret_path)):
            errors.append("dashboard secret key file does not exist: {}".format(secret_path or "<unset>"))
        if not dashboard.get("admin_groups"):
            warnings.append("dashboard is enabled without dashboard.admin_groups")
        if not isinstance(dashboard.get("require_mutation_confirmation", True), bool):
            errors.append("dashboard.require_mutation_confirmation must be a boolean")
    try:
        if int(dashboard.get("jobs_max_results", 250)) < 1:
            errors.append("dashboard.jobs_max_results must be greater than zero")
    except (TypeError, ValueError):
        errors.append("dashboard.jobs_max_results must be an integer")
    if str(dashboard.get("default_locale") or "en").lower() not in ("en", "ru"):
        errors.append("dashboard.default_locale must be en or ru")

    if not isinstance(access_packages.get("enabled", True), bool):
        errors.append("access_packages.enabled must be a boolean")
    for name, default, maximum in (("max_rules", 50, 500), ("max_assignments_per_operation", 100, 1000)):
        try:
            value = int(access_packages.get(name, default))
            if not 1 <= value <= maximum:
                errors.append("access_packages.{} must be between 1 and {}".format(name, maximum))
        except (TypeError, ValueError):
            errors.append("access_packages.{} must be an integer".format(name))

    try:
        max_fleet_hosts = int(runbooks.get("max_fleet_hosts", 100))
        if not 1 <= max_fleet_hosts <= 1000:
            errors.append("runbooks.max_fleet_hosts must be between 1 and 1000")
    except (TypeError, ValueError):
        errors.append("runbooks.max_fleet_hosts must be an integer")

    if not isinstance(command_audit.get("send_env", False), bool):
        errors.append("command_audit.send_env must be a boolean")
    for name in ("enabled", "require_connection_id", "require_active_session"):
        if not isinstance(command_audit.get(name, name == "require_active_session"), bool):
            errors.append("command_audit.{} must be a boolean".format(name))
    try:
        if int(command_audit.get("completion_grace_seconds", 30)) < 0:
            errors.append("command_audit.completion_grace_seconds must not be negative")
    except (TypeError, ValueError):
        errors.append("command_audit.completion_grace_seconds must be an integer")
    if command_audit.get("send_env") and not command_audit.get("enabled"):
        warnings.append("command_audit.send_env is enabled while command audit is disabled")
    ingest_user = str(command_audit.get("ingest_user", "auth") or "")
    if not ingest_user or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,47}", ingest_user) is None:
        errors.append("command_audit.ingest_user must be a valid Unix account name")

    for name, default in (("poll_interval", 1), ("heartbeat_interval", 15), ("active_ttl", 86400), ("live_tail_bytes", 262144)):
        try:
            if float(session_control.get(name, default)) <= 0:
                errors.append("session_control.{} must be greater than zero".format(name))
        except (TypeError, ValueError):
            errors.append("session_control.{} must be numeric".format(name))
    alerts = session_control.get("alerts", {}) or {}
    for cidr in alerts.get("trusted_source_cidrs") or []:
        try:
            ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            errors.append("session_control.alerts.trusted_source_cidrs contains an invalid network: {}".format(cidr))
    if session_control.get("terminate_enabled") and not dashboard.get("admin_groups"):
        warnings.append("session termination is enabled without dashboard.admin_groups")

    if policy_as_code.get("enforce_git") and not policy_as_code.get("enabled"):
        errors.append("policy_as_code.enabled must be true when enforce_git is enabled")
    if policy_as_code.get("enabled"):
        if not policy_as_code.get("require_pr_approval", True):
            errors.append("policy_as_code.require_pr_approval must remain enabled")
        if not policy_as_code.get("repository"):
            errors.append("policy_as_code.repository is required when GitOps is enabled")
        for name in ("checkout_path", "git_binary"):
            value = str(policy_as_code.get(name) or "")
            if not (os.path.isabs(value) or value.startswith("/")):
                errors.append("policy_as_code.{} must be an absolute path".format(name))
        if not policy_as_code.get("branch") or not policy_as_code.get("git_bundle_path"):
            errors.append("policy_as_code.branch and git_bundle_path are required")
        try:
            if int(policy_as_code.get("minimum_approvals", 1)) < 1:
                errors.append("policy_as_code.minimum_approvals must be greater than zero")
        except (TypeError, ValueError):
            errors.append("policy_as_code.minimum_approvals must be an integer")
        if policy_as_code.get("require_pr_approval", True):
            approval_key = policy_as_code.get("approval_key_file")
            if not approval_key or not (os.path.isabs(str(approval_key)) or str(approval_key).startswith("/")):
                errors.append("policy_as_code.approval_key_file must be an absolute path")
            elif check_paths and not os.path.isfile(approval_key):
                errors.append("policy approval key does not exist: {}".format(approval_key))

    if mcp.get("enabled"):
        mcp_issuer = mcp.get("issuer") or keycloak.get("issuer")
        if not mcp_issuer:
            errors.append("mcp.issuer or keycloak.issuer is required when MCP is enabled")
        elif not re.match(r"^https://", str(mcp_issuer), re.I):
            warnings.append("MCP issuer does not use HTTPS")
        public_url = str(mcp.get("public_url") or "")
        if not public_url:
            errors.append("mcp.public_url is required when MCP is enabled")
        elif not re.match(r"^https://", public_url, re.I) and not re.match(r"^http://(127\.0\.0\.1|localhost|\[::1\])", public_url, re.I):
            errors.append("mcp.public_url must use HTTPS outside localhost")
        if not mcp.get("expected_audience"):
            errors.append("mcp.expected_audience is required when MCP is enabled")
        if not mcp.get("required_scopes") or not isinstance(mcp.get("required_scopes"), list):
            errors.append("mcp.required_scopes must be a non-empty list")
        if not mcp.get("self_service_scope"):
            errors.append("mcp.self_service_scope is required when MCP is enabled")
        if not mcp.get("approval_scope"):
            errors.append("mcp.approval_scope is required when MCP is enabled")
        for scope_name in ("inventory_write_scope", "policy_read_scope", "execute_scope", "runbook_scope", "operate_scope"):
            if not mcp.get(scope_name):
                errors.append("mcp.{} is required when MCP is enabled".format(scope_name))
        if not isinstance(mcp.get("prevent_self_approval", True), bool):
            errors.append("mcp.prevent_self_approval must be a boolean")
        if not isinstance(mcp.get("require_mutation_confirmation", True), bool):
            errors.append("mcp.require_mutation_confirmation must be a boolean")
        if not isinstance(mcp.get("allowed_hosts"), list) or not mcp.get("allowed_hosts"):
            errors.append("mcp.allowed_hosts must be a non-empty list")
        if not isinstance(mcp.get("allowed_origins"), list):
            errors.append("mcp.allowed_origins must be a list")
        try:
            if not 1 <= int(mcp.get("listen_port", 8090)) <= 65535:
                errors.append("mcp.listen_port must be between 1 and 65535")
        except (TypeError, ValueError):
            errors.append("mcp.listen_port must be an integer")
        try:
            if int(mcp.get("max_results", 100)) < 1:
                errors.append("mcp.max_results must be greater than zero")
        except (TypeError, ValueError):
            errors.append("mcp.max_results must be an integer")

    if command_execution.get("enabled"):
        if not mcp.get("enabled"):
            errors.append("mcp.enabled must be true when command execution is enabled")
        if not command_execution.get("allowed_groups") or not isinstance(command_execution.get("allowed_groups"), list):
            errors.append("command_execution.allowed_groups must be a non-empty list")
        if not command_execution.get("allow_arbitrary_commands") and not command_execution.get("allowed_command_patterns"):
            errors.append("command_execution.allowed_command_patterns is required unless arbitrary commands are enabled")
        if command_execution.get("allow_arbitrary_commands"):
            warnings.append("arbitrary remote command execution is enabled")
        for name, default in (
            ("default_timeout", 60),
            ("max_timeout", 900),
            ("max_command_length", 4096),
            ("max_output_bytes", 1048576),
            ("max_return_bytes", 262144),
        ):
            try:
                if int(command_execution.get(name, default)) < 1:
                    errors.append("command_execution.{} must be greater than zero".format(name))
            except (TypeError, ValueError):
                errors.append("command_execution.{} must be an integer".format(name))
        try:
            if int(command_execution.get("default_timeout", 60)) > int(command_execution.get("max_timeout", 900)):
                errors.append("command_execution.default_timeout cannot exceed max_timeout")
            if int(command_execution.get("max_return_bytes", 262144)) > int(command_execution.get("max_output_bytes", 1048576)):
                errors.append("command_execution.max_return_bytes cannot exceed max_output_bytes")
        except (TypeError, ValueError):
            pass

    if runbooks.get("enabled"):
        if not mcp.get("enabled"):
            errors.append("mcp.enabled must be true when runbooks are enabled")
        if not isinstance(runbooks.get("disabled", []), list):
            errors.append("runbooks.disabled must be a list")
        read_only = runbooks.get("read_only")
        operational = runbooks.get("operational")
        if not isinstance(read_only, dict):
            errors.append("runbooks.read_only must be an object")
            read_only = {}
        if not isinstance(operational, dict):
            errors.append("runbooks.operational must be an object")
            operational = {}
        if not read_only.get("allowed_groups") or not isinstance(read_only.get("allowed_groups"), list):
            errors.append("runbooks.read_only.allowed_groups must be a non-empty list")
        if operational.get("enabled"):
            if not operational.get("allowed_groups") or not isinstance(operational.get("allowed_groups"), list):
                errors.append("runbooks.operational.allowed_groups must be a non-empty list")
            warnings.append("operational runbooks are enabled")
            if operational.get("allow_sudo"):
                warnings.append("sudo operational runbooks are enabled")
        if not command_execution.get("enabled"):
            for name, default in (
                ("default_timeout", 60),
                ("max_timeout", 900),
                ("max_output_bytes", 1048576),
                ("max_return_bytes", 262144),
            ):
                try:
                    if int(command_execution.get(name, default)) < 1:
                        errors.append("command_execution.{} must be greater than zero".format(name))
                except (TypeError, ValueError):
                    errors.append("command_execution.{} must be an integer".format(name))
            try:
                if int(command_execution.get("default_timeout", 60)) > int(command_execution.get("max_timeout", 900)):
                    errors.append("command_execution.default_timeout cannot exceed max_timeout")
                if int(command_execution.get("max_return_bytes", 262144)) > int(command_execution.get("max_output_bytes", 1048576)):
                    errors.append("command_execution.max_return_bytes cannot exceed max_output_bytes")
            except (TypeError, ValueError):
                pass

    if command_execution.get("enabled") or runbooks.get("enabled"):
        jobs_path = command_execution.get("jobs_path")
        if not jobs_path or not os.path.isabs(str(jobs_path)):
            errors.append("command_execution.jobs_path must be an absolute path")
        elif check_paths and not (os.path.isdir(jobs_path) and os.access(jobs_path, os.W_OK | os.X_OK)):
            errors.append("job execution path is missing or not writable: {}".format(jobs_path))
        remote_shell = command_execution.get("remote_shell", "/bin/sh")
        # Commands run on Linux targets even when validation is invoked from a
        # Windows operator workstation, so validate POSIX paths explicitly.
        if not str(remote_shell).startswith("/"):
            errors.append("command_execution.remote_shell must be an absolute path")
        signing_key = command_execution.get("signing_key_file")
        if not signing_key or not os.path.isabs(str(signing_key)):
            errors.append("command_execution.signing_key_file must be an absolute path")
        elif check_paths:
            if not os.path.isfile(signing_key):
                errors.append("job execution signing key does not exist: {}".format(signing_key))
            elif os.name == "posix" and os.stat(signing_key).st_mode & 0o077:
                errors.append("job execution signing key must be owner-only (0600 or stricter)")

    try:
        if int(backup.get("retention_count", 14)) < 1:
            errors.append("backup.retention_count must be greater than zero")
    except (TypeError, ValueError):
        errors.append("backup.retention_count must be an integer")
    if backup.get("paths") is not None and not isinstance(backup.get("paths"), list):
        errors.append("backup.paths must be a list")
    if backup.get("redis_patterns") is not None and not isinstance(backup.get("redis_patterns"), list):
        errors.append("backup.redis_patterns must be a list")

    return {"valid": not errors, "errors": errors, "warnings": warnings}


def run_health_checks(config, redis_factory=create_redis_client):
    validation = validate_config(config, check_paths=True)
    checks = {
        "config": {
            "ok": validation["valid"],
            "errors": validation["errors"],
            "warnings": validation["warnings"],
        }
    }

    try:
        redis_factory(config).ping()
        checks["redis"] = {"ok": True}
    except Exception as exc:
        checks["redis"] = {"ok": False, "error": str(exc)}

    log_path = config.get("logging", {}).get("base_path")
    log_ok = bool(log_path and os.path.isdir(log_path) and os.access(log_path, os.W_OK | os.X_OK))
    checks["logging"] = {"ok": log_ok, "path": log_path}
    if not log_ok:
        checks["logging"]["error"] = "logging base path is missing or not writable"

    ok = all(check.get("ok") for check in checks.values())
    return {"status": "ok" if ok else "unhealthy", "ok": ok, "checks": checks}
