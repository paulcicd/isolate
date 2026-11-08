#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Redis client construction shared by Isolate runtime components."""


def redis_options(config):
    redis_cfg = (config or {}).get("redis", {})
    options = {
        "host": redis_cfg.get("host", "127.0.0.1"),
        "port": int(redis_cfg.get("port", 6379)),
        "db": int(redis_cfg.get("db", 0)),
        "password": redis_cfg.get("password"),
        "socket_timeout": float(redis_cfg.get("socket_timeout", 3)),
    }
    if redis_cfg.get("password_file"):
        from isolate_oidc import read_client_secret
        options["password"] = read_client_secret({"client_secret_file": redis_cfg["password_file"]})
    if redis_cfg.get("username"):
        options["username"] = redis_cfg["username"]
    if redis_cfg.get("ssl", False):
        options["ssl"] = True
        options["ssl_check_hostname"] = bool(redis_cfg.get("ssl_check_hostname", True))
        for key in ("ssl_ca_certs", "ssl_certfile", "ssl_keyfile"):
            if redis_cfg.get(key):
                options[key] = redis_cfg[key]
    return options


def create_ephemeral_redis_client(config):
    """Construct raw Redis; migration tooling uses it explicitly as a source."""
    from redis import Redis
    sentinel = (config or {}).get("redis", {}).get("sentinel") or {}
    if sentinel.get("enabled"):
        from redis.sentinel import Sentinel
        options = redis_options(config)
        options.pop("host", None)
        options.pop("port", None)
        endpoints = [(str(node[0]), int(node[1])) for node in sentinel.get("nodes", [])]
        if not endpoints or not sentinel.get("master_name"):
            raise ValueError("Redis Sentinel nodes and master_name are required")
        sentinel_options = {"socket_timeout": options.get("socket_timeout", 3)}
        for name in ("username", "password"):
            if sentinel.get(name):
                sentinel_options[name] = sentinel[name]
        if sentinel.get("ssl"):
            sentinel_options.update(ssl=True, ssl_check_hostname=True)
            for name in ("ssl_ca_certs", "ssl_certfile", "ssl_keyfile"):
                if sentinel.get(name):
                    sentinel_options[name] = sentinel[name]
        return Sentinel(endpoints, sentinel_kwargs=sentinel_options, **options).master_for(sentinel["master_name"])
    return Redis(**redis_options(config))


def create_redis_client(config):
    """Construct the shared state facade without changing legacy record schemas.

    SQL is authoritative when selected. It is never populated automatically and
    a failed SQL request never retries against the old Redis domain records.
    """
    redis = create_ephemeral_redis_client(config)
    options = (config or {}).get("state") or {}
    backend = options.get("backend", "redis")
    from isolate_state import LegacyGuard, StateClient
    if backend == "redis":
        return LegacyGuard(redis) if options.get("migration_guard", True) else redis
    if backend in ("postgresql", "sqlite"):
        return StateClient(redis, options)
    raise ValueError("state.backend must be redis, postgresql, or sqlite")
