#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Configuration validation and local health checks."""

import os
import re

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
    mcp = section("mcp")
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
