#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runtime configuration for Isolate v2."""

import json
import os
import copy

try:
    import yaml
except ImportError:  # pragma: no cover - optional dependency for old installs
    yaml = None


DEFAULT_CONFIG_PATHS = (
    "/etc/isolate/isolate.yml",
    "/opt/auth/configs/isolate.yml",
)

DEFAULT_CONFIG = {
    "schema_version": 2,
    "state": {"backend": "redis", "migration_guard": True, "require_tls": True, "dsn_file": None, "sqlite_path": None},
    "recordings": {
        "enabled": False, "backend": "s3", "bucket": None, "prefix": "isolate",
        "capture_path": "/opt/auth/spool/evidence",
        "endpoint_url": None, "region": None, "ca_bundle": None,
        "outbox_path": "/opt/auth/spool/recordings", "cache_path": "/opt/auth/cache/recordings",
        "signing_key_file": "/opt/auth/keys/recordings_hmac.key",
        "chunk_bytes": 262144, "upload_interval_seconds": 2, "max_outbox_age_seconds": 300,
    },
    "admission": {"enabled": False, "per_subject_per_minute": 60, "global_per_minute": 1000},
    "governance": {"review_interval_days": 90},
    "campaigns": {"enabled": False, "max_hosts": 100, "max_batch_size": 50},
    "api": {"enabled": False, "client_url": None, "ticket_ttl": 60, "bind_ticket_ip": False},
    "gateway": {
        "enabled": False, "listen_host": "127.0.0.1", "ssh_port": 2222,
        "web_host": "127.0.0.1", "web_port": 8092,
        "host_key_file": "/opt/auth/keys/gateway_ed25519", "known_hosts": "/opt/auth/known_hosts",
        "public_ssh_host": None, "public_web_url": None, "allowed_origins": [],
        "max_connections": 100, "recheck_interval": 2,
        "ssh_features": {"multiple_channels": False, "max_channels": 8, "sftp": False,
            "scp": False, "forwarding": False, "proxy_hops": False, "max_proxy_hops": 3},
        "forwarding_targets": {},
        "browser_auth": {"enabled": False, "timeout_seconds": 120},
    },
    "identity_security": {
        "backchannel_logout": {"enabled": False, "max_logout_age_seconds": 300, "max_token_lifetime_seconds": 86400},
        "introspection": {"enabled": False},
        "step_up": {"enabled": False, "require_privileged": True, "all_connections": False,
                    "required_projects": [], "required_project_globs": [], "acr_values": [],
                    "required_amr": [], "max_age_seconds": 300},
        "membership": {"enabled": False, "source": "keycloak-admin", "token_file": None,
                       "group_name_style": "name", "include_realm_roles": True, "max_groups": 1000},
        "delegation": {"enabled": False, "max_seconds": 300, "recheck_interval": 2},
        "workloads": {"enabled": False, "clients": {}},
    },
    "credentials": {"default": "legacy", "targets": {}, "providers": {}, "known_hosts": None},
    "protocols": {"enabled": False, "targets": {}},
    "web_apps": {"enabled": False, "session_ttl_seconds": 3600, "launch_ttl": 30,
                 "idle_timeout_seconds": 900, "max_sessions": 100, "max_requests_per_session": 16},
    "audit_index": {"enabled": False, "driver": "sqlite", "path": "/opt/auth/spool/audit.sqlite3"},
    "cluster": {"node_id": None, "draining": False, "lease_ttl": 30, "node_ttl": 30},
    "connection_authorization": {
        "connections_enabled": True,
        "require_explicit_mapping": False,
        "unix_users": {},
        "allowed_target_ports": [],
        "allow_proxy": False,
        "max_session_seconds": 28800,
        "recheck_interval": 5,
    },
    "service_discovery": {
        "enabled": False,
        "remote_user": None,
        "host_ids": [],
        "timeout": 10,
    },
    "session_approval": {
        "enabled": False,
        "required_projects": [],
        "required_project_globs": [],
        "require_privileged": False,
        "minimum_approvals": 1,
        "privileged_minimum_approvals": 2,
        "request_timeout_seconds": 300,
        "approval_ttl_seconds": 300,
        "max_session_seconds": 3600,
        "poll_interval_seconds": 2,
    },
    "data_root": "/opt/auth",
    "redis": {
        "host": "127.0.0.1",
        "port": 6379,
        "db": 0,
        "username": None,
        "password": None,
        "ssl": False,
        "ssl_ca_certs": None,
        "ssl_certfile": None,
        "ssl_keyfile": None,
        "ssl_check_hostname": True,
        "socket_timeout": 3,
    },
    "keycloak": {
        "http_connect_timeout": 2,
        "http_read_timeout": 3,
        "issuer": None,
        "client_id": "isolate-bastion",
        "client_secret": None,
        "scopes": ["openid", "profile", "email"],
        "device_authorization_endpoint": None,
        "token_endpoint": None,
        "introspection_endpoint": None,
        "jwks_uri": None,
        "verify_tokens": True,
        "expected_audience": "isolate-bastion",
        "jwks_cache_path": "/opt/auth/cache/keycloak_jwks.json",
        "jwks_cache_ttl": 3600,
        "poll_timeout": 300,
        "tls_verify": True,
    },
    "ssh": {
        "binary": "/usr/bin/ssh",
        "config_path": "/opt/auth/configs/defaults.conf",
        "allow_unknown_args": False,
        "allowed_extra_args": ["-4", "-6", "-a", "-C", "-v", "-vv", "-vvv"],
        "default_remote_user": None,
        "default_sudo_mode": "sudo-i",
        "require_known_hosts": True,
        "allocate_tty": True,
    },
    "logging": {
        "base_path": "/opt/auth/logs",
        "jsonl_name": "session.jsonl",
        "sink": "local",
        "fail_closed": False,
        "retention_days": 90,
        "sinks": [],
        "integrity": {
            "enabled": False,
            "key_file": "/opt/auth/keys/audit_hmac.key",
            "key_id": "isolate-audit-v1",
        },
    },
    "history": {
        "admin_groups": [],
        "default_limit": 10,
        "max_limit": 100,
    },
    "maintenance": {
        "enforce": True,
        "bypass_groups": [],
    },
    "connectivity": {
        "default_timeout": 3,
        "max_hosts_per_check": 100,
        "result_ttl": 3600,
    },
    "announcements": {
        "enabled": True,
        "max_active": 100,
    },
    "access": {
        "admin_groups": [],
        "default_ttl": "2h",
        "max_ttl": "24h",
        "ticket_required": False,
        "ticket_pattern": None,
        "request_templates": {},
    },
    "access_packages": {
        "enabled": True,
        "max_rules": 50,
        "max_assignments_per_operation": 100,
    },
    "command_audit": {
        "enabled": False,
        "mode": "target-hooks",
        "command_timeout_seconds": 300,
        "require_connection_id": True,
        "require_active_session": True,
        "completion_grace_seconds": 30,
        "max_command_length": 4096,
        "send_env": False,
        "ingest_user": "auth",
    },
    "session_control": {
        "enabled": True,
        "terminate_enabled": False,
        "poll_interval": 1,
        "heartbeat_interval": 15,
        "active_ttl": 86400,
        "live_tail_bytes": 262144,
        "alerts": {
            "enabled": False,
            "long_session_seconds": 14400,
            "vip": True,
            "privileged": True,
            "unusual_source": True,
            "trusted_source_cidrs": [],
        },
    },
    "replay": {
        "max_bytes": 10485760,
        "default_speed": 1,
    },
    "dashboard": {
        "enabled": False,
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "public_url": "http://127.0.0.1:8080",
        "secret_key_file": "/opt/auth/keys/dashboard_secret",
        "admin_groups": [],
        "refresh_seconds": 15,
        "self_service_enabled": True,
        "workspace_enabled": True,
        "self_service_groups": [],
        "role_bindings": [],
        "require_mutation_confirmation": True,
        "jobs_max_results": 250,
        "default_locale": "en",
    },
    "build": {
        "version": "2.1.0-dev",
        "revision": None,
        "built_at": None,
    },
    "mcp": {
        "enabled": False,
        "listen_host": "127.0.0.1",
        "listen_port": 8090,
        "public_url": "http://127.0.0.1:8090/mcp",
        "issuer": None,
        "expected_audience": "isolate-mcp",
        "jwks_uri": None,
        "jwks_cache_path": "/opt/auth/cache/keycloak_mcp_jwks.json",
        "jwks_cache_ttl": 3600,
        "tls_verify": True,
        "required_scopes": ["isolate.read"],
        "self_service_scope": "isolate.self-service",
        "approval_scope": "isolate.approve",
        "inventory_write_scope": "isolate.inventory.write",
        "policy_read_scope": "isolate.policy.read",
        "execute_scope": "isolate.execute",
        "runbook_scope": "isolate.runbook",
        "operate_scope": "isolate.operate",
        "inventory_admin_groups": [],
        "policy_admin_groups": [],
        "execution_admin_groups": [],
        "prevent_self_approval": True,
        "require_mutation_confirmation": True,
        "allowed_hosts": ["127.0.0.1:*", "localhost:*", "[::1]:*"],
        "allowed_origins": ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        "max_results": 100,
        "max_request_body_size": 1048576,
    },
    "command_execution": {
        "enabled": False,
        "allowed_groups": [],
        "allow_arbitrary_commands": False,
        "allowed_command_patterns": [],
        "allow_sudo": False,
        "require_confirmation": True,
        "default_timeout": 60,
        "max_timeout": 900,
        "max_command_length": 4096,
        "max_output_bytes": 1048576,
        "max_return_bytes": 262144,
        "jobs_path": "/opt/auth/jobs",
        "signing_key_file": "/opt/auth/keys/job_hmac.key",
        "remote_shell": "/bin/sh",
        "poll_interval": 1,
    },
    "runbooks": {
        "enabled": False,
        "max_fleet_hosts": 100,
        "disabled": [],
        "read_only": {
            "allowed_groups": [],
            "allow_sudo": False,
            "require_confirmation": True,
        },
        "operational": {
            "enabled": False,
            "allowed_groups": [],
            "allow_sudo": False,
            "require_confirmation": True,
        },
    },
    "notifications": {
        "enabled": False,
        "timeout_seconds": 5,
        "fail_closed": False,
        "sinks": [],
    },
    "policy": {
        "default_allowed_actions": ["ssh"],
        "fallback_remote_user": None,
    },
    "policy_as_code": {
        "bundle_path": "/opt/auth/configs/policy.yml",
        "backup_dir": "/opt/auth/backups",
        "require_confirmation": True,
        "enabled": False,
        "enforce_git": False,
        "repository": None,
        "checkout_path": "/opt/auth/cache/policy-repo",
        "branch": "main",
        "git_bundle_path": "policy.yml",
        "git_binary": "/usr/bin/git",
        "git_timeout": 60,
        "prune": False,
        "require_pr_approval": True,
        "approval_attestation_path": "policy.approval.json",
        "approval_key_file": "/opt/auth/keys/policy_approval_hmac.key",
        "minimum_approvals": 1,
    },
    "backup": {
        "base_path": None,
        "retention_count": 14,
        "include_logs": False,
        "owner": "auth",
        "group": "auth",
        "redis": {},
        "redis_patterns": [
            "server_*",
            "host_services_*",
            "grant_*",
            "policy_*",
            "project_set_*",
            "access_request_*",
            "session_approval_*",
            "identity_revocation_*",
            "governance_*",
            "workflow_event_*",
            "workflow_pending_*",
            "runbook_campaign_*",
            "active_session_*",
            "job_*",
            "dashboard_alert_state_*",
            "access_package_*",
            "announcement_*",
            "ssh_config_*",
            "complete_hosts_*",
            "offset_*",
            "projects_list",
            "schema_version",
        ],
        "paths": None,
    },
}


def _deep_merge(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_file(path):
    with open(path, "r", encoding="utf-8") as config_f:
        text = config_f.read()
    if not text.strip():
        return {}
    if path.endswith(".json"):
        return json.loads(text)
    if yaml is None:
        raise RuntimeError("PyYAML is required to read {}".format(path))
    loaded = yaml.safe_load(text)
    return loaded or {}


def load_config(path=None, use_env=True):
    """Load config from env/file and merge it with v2 defaults."""
    config = copy.deepcopy(DEFAULT_CONFIG)
    config_path = path or (os.getenv("ISOLATE_CONFIG") if use_env else None)
    if config_path:
        if os.path.exists(config_path):
            config = _deep_merge(config, _load_file(config_path))
    else:
        for candidate in DEFAULT_CONFIG_PATHS:
            if os.path.exists(candidate):
                config = _deep_merge(config, _load_file(candidate))
                break

    config = _deep_merge(config, _env_overrides() if use_env else {})
    data_root = config.get("data_root") or "/opt/auth"
    config["ssh"]["config_path"] = config["ssh"].get("config_path") or os.path.join(
        data_root, "configs", "defaults.conf"
    )
    config["logging"]["base_path"] = config["logging"].get("base_path") or os.path.join(
        data_root, "logs"
    )
    backup = config.setdefault("backup", {})
    backup["base_path"] = backup.get("base_path") or os.path.join(data_root, "backups", "service")
    if backup.get("paths") is None:
        backup["paths"] = [
            {"path": os.path.join(data_root, "configs"), "required": True},
            {"path": os.path.join(data_root, "keys"), "required": True},
            {"path": os.path.join(data_root, "known_hosts"), "required": True},
            {"path": "/home/auth/.ssh", "required": False},
            {"path": "/etc/isolate", "required": False},
            {"path": "/etc/sudoers.d/isolate", "required": False},
            {"path": "/etc/default/isolate-dashboard", "required": False},
            {"path": "/etc/systemd/system/isolate-dashboard.service", "required": False},
            {"path": "/etc/systemd/system/isolate-log-retention.service", "required": False},
            {"path": "/etc/systemd/system/isolate-log-retention.timer", "required": False},
            {"path": "/etc/systemd/system/isolate-backup.service", "required": False},
            {"path": "/etc/systemd/system/isolate-backup.timer", "required": False},
            {"path": "/etc/systemd/system/isolate-mcp.service", "required": False},
            {"path": "/etc/systemd/system/isolate-job-worker.service", "required": False},
            {"path": "/etc/systemd/system/isolate-gateway.service", "required": False},
            {"path": "/etc/systemd/system/isolate-policy-sync.service", "required": False},
            {"path": "/etc/systemd/system/isolate-policy-sync.timer", "required": False},
            {"path": "/etc/default/isolate-mcp", "required": False},
        ]
    return canonical_identity_config(config)


def canonical_identity_config(config):
    """Keep the internal legacy alias while selecting exactly one provider."""
    from isolate_oidc import identity_provider_config
    result = copy.deepcopy(config)
    result["keycloak"] = identity_provider_config(result)
    return result


def with_identity_provider(config, provider):
    result = copy.deepcopy(config)
    result["keycloak"] = copy.deepcopy(provider)
    if provider.get("provider") == "oidc":
        result["oidc"] = dict(provider, enabled=True)
    else:
        result.pop("oidc", None)
    return result


def _env_overrides():
    overrides = {}
    if os.getenv("ISOLATE_DATA_ROOT"):
        overrides["data_root"] = os.getenv("ISOLATE_DATA_ROOT")

    redis = {}
    if os.getenv("ISOLATE_REDIS_HOST"):
        redis["host"] = os.getenv("ISOLATE_REDIS_HOST")
    if os.getenv("ISOLATE_REDIS_PORT"):
        redis["port"] = int(os.getenv("ISOLATE_REDIS_PORT"))
    if os.getenv("ISOLATE_REDIS_DB"):
        redis["db"] = int(os.getenv("ISOLATE_REDIS_DB"))
    if os.getenv("ISOLATE_REDIS_USER"):
        redis["username"] = os.getenv("ISOLATE_REDIS_USER")
    if os.getenv("ISOLATE_REDIS_PASS"):
        redis["password"] = os.getenv("ISOLATE_REDIS_PASS")
    if os.getenv("ISOLATE_REDIS_PASSWORD_FILE"):
        redis["password_file"] = os.getenv("ISOLATE_REDIS_PASSWORD_FILE")
    if os.getenv("ISOLATE_REDIS_SSL"):
        redis["ssl"] = os.getenv("ISOLATE_REDIS_SSL").strip().lower() in ("1", "true", "yes", "on")
    if os.getenv("ISOLATE_REDIS_CA_CERT"):
        redis["ssl_ca_certs"] = os.getenv("ISOLATE_REDIS_CA_CERT")
    if os.getenv("ISOLATE_REDIS_CLIENT_CERT"):
        redis["ssl_certfile"] = os.getenv("ISOLATE_REDIS_CLIENT_CERT")
    if os.getenv("ISOLATE_REDIS_CLIENT_KEY"):
        redis["ssl_keyfile"] = os.getenv("ISOLATE_REDIS_CLIENT_KEY")
    if redis:
        overrides["redis"] = redis

    keycloak = {}
    if os.getenv("ISOLATE_KEYCLOAK_ISSUER"):
        keycloak["issuer"] = os.getenv("ISOLATE_KEYCLOAK_ISSUER")
    if os.getenv("ISOLATE_KEYCLOAK_CLIENT_ID"):
        keycloak["client_id"] = os.getenv("ISOLATE_KEYCLOAK_CLIENT_ID")
    if os.getenv("ISOLATE_KEYCLOAK_CLIENT_SECRET"):
        keycloak["client_secret"] = os.getenv("ISOLATE_KEYCLOAK_CLIENT_SECRET")
    if keycloak:
        overrides["keycloak"] = keycloak

    oidc = {}
    for suffix, key in (("ISSUER", "issuer"), ("CLIENT_ID", "client_id"),
                        ("AUDIENCE", "expected_audience"), ("CLIENT_SECRET_FILE", "client_secret_file")):
        if os.getenv("ISOLATE_OIDC_" + suffix):
            oidc[key] = os.getenv("ISOLATE_OIDC_" + suffix)
    if oidc:
        overrides["oidc"] = dict(oidc, enabled=True)

    return overrides
