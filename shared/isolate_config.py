#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runtime configuration for Isolate v2."""

import json
import os

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
    "data_root": "/opt/auth",
    "redis": {
        "host": "127.0.0.1",
        "port": 6379,
        "db": 0,
        "password": None,
    },
    "keycloak": {
        "issuer": None,
        "client_id": "isolate-bastion",
        "client_secret": None,
        "scopes": ["openid", "profile", "email"],
        "device_authorization_endpoint": None,
        "token_endpoint": None,
        "introspection_endpoint": None,
        "jwks_uri": None,
        "poll_timeout": 300,
        "tls_verify": True,
    },
    "ssh": {
        "binary": "/usr/bin/ssh",
        "config_path": "/opt/auth/configs/defaults.conf",
        "allow_unknown_args": False,
        "allowed_extra_args": ["-4", "-6", "-A", "-a", "-C", "-v", "-vv", "-vvv"],
        "default_remote_user": None,
        "default_sudo_mode": "sudo-i",
        "require_known_hosts": True,
        "allocate_tty": True,
    },
    "logging": {
        "base_path": "/opt/auth/logs",
        "jsonl_name": "session.jsonl",
        "sink": "local",
    },
    "history": {
        "admin_groups": [],
        "default_limit": 10,
        "max_limit": 100,
    },
    "access": {
        "admin_groups": [],
        "default_ttl": "2h",
        "max_ttl": "24h",
    },
    "dashboard": {
        "enabled": False,
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "public_url": "http://127.0.0.1:8080",
        "secret_key_file": "/opt/auth/keys/dashboard_secret",
        "admin_groups": [],
    },
    "policy": {
        "default_allowed_actions": ["ssh"],
        "fallback_remote_user": None,
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


def load_config(path=None):
    """Load config from env/file and merge it with v2 defaults."""
    config = DEFAULT_CONFIG
    config_path = path or os.getenv("ISOLATE_CONFIG")
    if config_path:
        if os.path.exists(config_path):
            config = _deep_merge(config, _load_file(config_path))
    else:
        for candidate in DEFAULT_CONFIG_PATHS:
            if os.path.exists(candidate):
                config = _deep_merge(config, _load_file(candidate))
                break

    config = _deep_merge(config, _env_overrides())
    data_root = config.get("data_root") or "/opt/auth"
    config["ssh"]["config_path"] = config["ssh"].get("config_path") or os.path.join(
        data_root, "configs", "defaults.conf"
    )
    config["logging"]["base_path"] = config["logging"].get("base_path") or os.path.join(
        data_root, "logs"
    )
    return config


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
    if os.getenv("ISOLATE_REDIS_PASS"):
        redis["password"] = os.getenv("ISOLATE_REDIS_PASS")
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

    return overrides
