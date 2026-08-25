#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inventory helpers for Redis-backed Isolate hosts."""

import json
import re
import time

from IsolateCore import is_valid_fqdn, is_valid_ipv4_address, is_valid_ipv6_address


class HostValidationError(Exception):
    pass


def decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def normalize_services(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def normalize_host(host):
    row = dict(host)
    row["server_id"] = str(row.get("server_id") or "")
    row["project_name"] = str(row.get("project_name") or "")
    row["server_name"] = str(row.get("server_name") or "")
    row["server_ip"] = str(row.get("server_ip") or "")
    row["server_services"] = normalize_services(row.get("server_services"))
    row["server_note"] = str(row.get("server_note") or "").strip()
    return row


def list_hosts(redis, project=None, query=None):
    rows = []
    for key in redis.keys("server_*"):
        raw = redis.get(key)
        if raw is None:
            continue
        host = normalize_host(json.loads(decode(raw)))
        if project and host.get("project_name") != project:
            continue
        if query and not host_matches_query(host, query):
            continue
        rows.append(host)
    return sorted(rows, key=lambda row: (row.get("project_name") or "", row.get("server_name") or "", row.get("server_id") or ""))


def get_host(redis, server_id):
    raw = redis.get("server_{}".format(server_id))
    if raw is None:
        return None
    return normalize_host(json.loads(decode(raw)))


def host_matches_query(host, query):
    query_l = str(query or "").lower()
    if not query_l:
        return True
    fields = (
        "project_name",
        "server_name",
        "server_id",
        "server_ip",
        "server_user",
        "server_services",
        "server_note",
    )
    return any(query_l in str(host.get(field) or "").lower() for field in fields)


def validate_host_updates(redis, updates):
    normalized = {}
    if updates.get("project_name") is not None:
        project = str(updates["project_name"]).strip().lower()
        if re.match(r"^[A-Za-z,\d\-]*$", project) is None or len(project) > 48:
            raise HostValidationError("project validation failed")
        normalized["project_name"] = project
    if updates.get("server_name") is not None:
        name = str(updates["server_name"]).strip().lower()
        if not is_valid_fqdn(name):
            raise HostValidationError("server name validation failed")
        normalized["server_name"] = name
    if updates.get("server_ip") is not None:
        ip = str(updates["server_ip"]).strip()
        if not is_valid_ipv4_address(ip) and not is_valid_ipv6_address(ip):
            raise HostValidationError("server ip validation failed")
        normalized["server_ip"] = ip
    if updates.get("server_port") is not None:
        port = int(updates["server_port"])
        if port > 65535 or port <= 0:
            raise HostValidationError("port validation failed")
        normalized["server_port"] = port
    if updates.get("server_user") is not None:
        user = str(updates["server_user"]).strip()
        if re.match(r"^[A-Za-z,\d\-]*$", user) is None or len(user) > 48:
            raise HostValidationError("user validation failed")
        normalized["server_user"] = user
    if updates.get("server_nosudo") is not None:
        normalized["server_nosudo"] = bool(updates["server_nosudo"])
    if updates.get("server_services") is not None:
        services = normalize_services(updates["server_services"])
        if len(services) > 2048:
            raise HostValidationError("services value is too long")
        normalized["server_services"] = services
    if updates.get("server_note") is not None:
        note = str(updates["server_note"]).strip()
        if len(note) > 2048:
            raise HostValidationError("note value is too long")
        normalized["server_note"] = note
    if updates.get("proxy_id") is not None:
        proxy_id = str(updates["proxy_id"]).strip()
        if proxy_id and redis.get("server_{}".format(proxy_id)) is None:
            raise HostValidationError("proxy with id {} not found".format(proxy_id))
        normalized["proxy_id"] = proxy_id or None
    return normalized


def update_host(redis, server_id, updates, updated_by=None):
    raw = redis.get("server_{}".format(server_id))
    if raw is None:
        return None
    host = json.loads(decode(raw))
    host.update(validate_host_updates(redis, updates))
    host["updated_by"] = updated_by or "unknown"
    host["updated_at"] = int(time.time())
    redis.set("server_{}".format(server_id), json.dumps(host, sort_keys=True))
    return normalize_host(host)


def format_hosts_table(rows):
    columns = [
        ("server_id", "id", 6),
        ("project_name", "project", 16),
        ("server_ip", "ip", 16),
        ("server_name", "name", 20),
        ("server_user", "user", 12),
        ("server_services", "services", 32),
    ]
    lines = ["  ".join(label.ljust(width) for _, label, width in columns)]
    for row in rows:
        lines.append("  ".join(str(row.get(key) or "").ljust(width) for key, _, width in columns))
    return "\n".join(lines)
