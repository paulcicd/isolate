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
    if redis_cfg.get("username"):
        options["username"] = redis_cfg["username"]
    if redis_cfg.get("ssl", False):
        options["ssl"] = True
        options["ssl_check_hostname"] = bool(redis_cfg.get("ssl_check_hostname", True))
        for key in ("ssl_ca_certs", "ssl_certfile", "ssl_keyfile"):
            if redis_cfg.get(key):
                options[key] = redis_cfg[key]
    return options


def create_redis_client(config):
    from redis import Redis

    return Redis(**redis_options(config))
