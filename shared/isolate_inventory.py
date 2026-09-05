#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inventory helpers for Redis-backed Isolate hosts."""

import json
import hashlib
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
    row["server_vip"] = bool(row.get("server_vip"))
    row["server_vip_marker"] = "VIP" if row["server_vip"] else ""
    row["privileged_access_provider"] = str(row.get("privileged_access_provider") or "").strip()
    row["privileged_access_url"] = str(row.get("privileged_access_url") or "").strip()
    row["privileged_access_hint"] = str(row.get("privileged_access_hint") or "").strip()
    return row


def host_revision(host):
    payload = dict(host or {})
    payload.pop("_revision", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def list_hosts(redis, project=None, query=None):
    rows = []
    for key in redis.keys("server_*"):
        if re.match(r"^server_[0-9]+$", decode(key)) is None:
            continue
        raw = redis.get(key)
        if raw is None:
            continue
        host = normalize_host(json.loads(decode(raw)))
        host["_revision"] = host_revision(host)
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
    host = normalize_host(json.loads(decode(raw)))
    host["_revision"] = host_revision(host)
    return host


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
        "server_vip_marker",
        "privileged_access_provider",
        "privileged_access_url",
        "privileged_access_hint",
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
    if updates.get("server_vip") is not None:
        normalized["server_vip"] = bool(updates["server_vip"])
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
    for source, target in (
        ("privileged_access_provider", "privileged_access_provider"),
        ("privileged_access_url", "privileged_access_url"),
        ("privileged_access_hint", "privileged_access_hint"),
    ):
        if updates.get(source) is not None:
            value = str(updates[source]).strip()
            if len(value) > 2048:
                raise HostValidationError("{} value is too long".format(target))
            normalized[target] = value
    if updates.get("proxy_id") is not None:
        proxy_id = str(updates["proxy_id"]).strip()
        if proxy_id and redis.get("server_{}".format(proxy_id)) is None:
            raise HostValidationError("proxy with id {} not found".format(proxy_id))
        normalized["proxy_id"] = proxy_id or None
    return normalized


def update_host(redis, server_id, updates, updated_by=None, expected_revision=None):
    raw = redis.get("server_{}".format(server_id))
    if raw is None:
        return None
    host = json.loads(decode(raw))
    if expected_revision and host_revision(normalize_host(host)) != str(expected_revision):
        raise HostValidationError("host changed since this form was opened; reload before saving")
    host.update(validate_host_updates(redis, updates))
    host["updated_by"] = updated_by or "unknown"
    host["updated_at"] = int(time.time())
    redis.set("server_{}".format(server_id), json.dumps(host, sort_keys=True))
    normalized = normalize_host(host)
    normalized["_revision"] = host_revision(normalized)
    return normalized


def bulk_update_hosts(redis, server_ids, updates, updated_by=None):
    ids = [str(server_id) for server_id in server_ids]
    if not ids:
        raise HostValidationError("at least one host id is required")
    if len(ids) != len(set(ids)):
        raise HostValidationError("duplicate host ids are not allowed")
    normalized_updates = validate_host_updates(redis, updates)
    if not normalized_updates:
        raise HostValidationError("at least one update field is required")
    current = []
    for server_id in ids:
        raw = redis.get("server_{}".format(server_id))
        if raw is None:
            raise HostValidationError("host not found: {}".format(server_id))
        current.append((server_id, json.loads(decode(raw))))

    updated_at = int(time.time())
    records = []
    for server_id, host in current:
        host.update(normalized_updates)
        host["updated_by"] = updated_by or "unknown"
        host["updated_at"] = updated_at
        records.append((server_id, host))
    if hasattr(redis, "pipeline"):
        pipeline = redis.pipeline(transaction=True)
        for server_id, host in records:
            pipeline.set("server_{}".format(server_id), json.dumps(host, sort_keys=True))
        pipeline.execute()
    else:
        for server_id, host in records:
            redis.set("server_{}".format(server_id), json.dumps(host, sort_keys=True))
    return [normalize_host(host) for _, host in records]


def create_host(redis, values, updated_by=None):
    required = ("project_name", "server_name", "server_ip", "server_user")
    missing = [name for name in required if values.get(name) in (None, "")]
    if missing:
        raise HostValidationError("missing required host fields: {}".format(", ".join(missing)))
    candidate = dict(values)
    candidate.setdefault("server_port", 22)
    normalized = validate_host_updates(redis, candidate)
    redis.set("offset_server_id", 10000, nx=True)
    server_id = redis.incr("offset_server_id")
    host = {
        "server_id": int(server_id),
        "project_name": normalized.get("project_name"),
        "server_name": normalized.get("server_name"),
        "server_ip": normalized.get("server_ip"),
        "server_port": normalized.get("server_port", 22),
        "server_user": normalized.get("server_user"),
        "server_nosudo": normalized.get("server_nosudo"),
        "server_services": normalized.get("server_services", ""),
        "server_note": normalized.get("server_note", ""),
        "server_vip": normalized.get("server_vip", False),
        "privileged_access_provider": normalized.get("privileged_access_provider", ""),
        "privileged_access_url": normalized.get("privileged_access_url", ""),
        "privileged_access_hint": normalized.get("privileged_access_hint", ""),
        "proxy_id": normalized.get("proxy_id"),
        "geoip_asn": None,
        "updated_by": updated_by or "unknown",
        "updated_at": int(time.time()),
    }
    redis.set("server_{}".format(server_id), json.dumps(host, sort_keys=True))
    result = normalize_host(host)
    result["_revision"] = host_revision(result)
    return result


def format_hosts_table(rows):
    columns = [
        ("server_id", "id", 6),
        ("project_name", "project", 16),
        ("server_ip", "ip", 16),
        ("server_name", "name", 20),
        ("server_vip_marker", "vip", 4),
        ("server_user", "user", 12),
        ("server_services", "services", 32),
    ]
    lines = ["  ".join(label.ljust(width) for _, label, width in columns)]
    for row in rows:
        lines.append("  ".join(str(row.get(key) or "").ljust(width) for key, _, width in columns))
    return "\n".join(lines)
