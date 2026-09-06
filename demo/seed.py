#!/usr/bin/env python3
"""Seed the disposable Redis inventory and RBAC policy for the Docker demo."""

import json
import os
import sys
import time

import redis


SEED_VERSION = "isolate-v2-demo-1"


HOSTS = [
    {
        "server_id": 10001,
        "project_name": "payments-dev",
        "server_name": "payments-dev-1",
        "server_ip": "172.30.50.11",
        "server_port": 22,
        "server_user": "support",
        "server_nosudo": True,
        "server_services": "nginx, payments-api, redis",
        "server_note": "Developer sandbox",
    },
    {
        "server_id": 10002,
        "project_name": "payments-prod",
        "server_name": "payments-prod-1",
        "server_ip": "172.30.50.12",
        "server_port": 22,
        "server_user": "support",
        "server_nosudo": True,
        "server_services": "nginx, payments-api",
        "server_note": "Production application node",
    },
    {
        "server_id": 10003,
        "project_name": "database-prod",
        "server_name": "database-prod-1",
        "server_ip": "172.30.50.13",
        "server_port": 22,
        "server_user": "dba",
        "server_nosudo": True,
        "server_services": "postgresql, redis",
        "server_note": "Database operations demo",
    },
    {
        "server_id": 10004,
        "project_name": "observability",
        "server_name": "observability-1",
        "server_ip": "172.30.50.14",
        "server_port": 22,
        "server_user": "support",
        "server_nosudo": True,
        "server_services": "prometheus, grafana, loki",
        "server_note": "Monitoring stack",
    },
    {
        "server_id": 10005,
        "project_name": "vip-core",
        "server_name": "vip-core-1",
        "server_ip": "172.30.50.15",
        "server_port": 22,
        "server_user": "support",
        "server_nosudo": True,
        "server_services": "core-api, haproxy",
        "server_note": "VIP host: ordinary access is read-only",
        "server_vip": True,
        "privileged_access_provider": "External PAM",
        "privileged_access_url": "https://pam.example.test",
        "privileged_access_hint": "Use the approved external PAM service for sudo/root access",
    },
]


PROJECT_SETS = [
    {
        "schema_version": 2,
        "name": "developer-projects",
        "projects": [],
        "project_globs": ["*-dev"],
    },
    {
        "schema_version": 2,
        "name": "production-projects",
        "projects": ["payments-prod", "database-prod", "vip-core"],
        "project_globs": [],
    },
]


GRANTS = [
    {
        "schema_version": 2,
        "subject": "group",
        "name": "Demo-DevOps",
        "project": "*",
        "project_glob": None,
        "project_set": None,
        "host": None,
        "remote_user": "support",
        "sudo_mode": "none",
        "allowed_actions": ["ssh"],
    },
    {
        "schema_version": 2,
        "subject": "group",
        "name": "Demo-Developers",
        "project": None,
        "project_glob": None,
        "project_set": "developer-projects",
        "host": None,
        "remote_user": "dev",
        "sudo_mode": "none",
        "allowed_actions": ["ssh"],
    },
    {
        "schema_version": 2,
        "subject": "group",
        "name": "Demo-DBA",
        "project": "database-prod",
        "project_glob": None,
        "project_set": None,
        "host": None,
        "remote_user": "dba",
        "sudo_mode": "none",
        "allowed_actions": ["ssh"],
    },
]


def connect():
    client = redis.Redis(
        host=os.getenv("ISOLATE_REDIS_HOST", "redis"),
        port=int(os.getenv("ISOLATE_REDIS_PORT", "6379")),
        db=int(os.getenv("ISOLATE_REDIS_DB", "0")),
        decode_responses=True,
    )
    for _ in range(60):
        try:
            client.ping()
            return client
        except redis.RedisError:
            time.sleep(1)
    raise RuntimeError("Redis was not ready after 60 seconds")


def main():
    client = connect()
    if client.get("demo_seed_version") == SEED_VERSION:
        print("Isolate demo inventory is already seeded")
        return 0

    pipeline = client.pipeline(transaction=True)
    projects = sorted({host["project_name"] for host in HOSTS})
    for host in HOSTS:
        record = dict(host)
        record.setdefault("server_vip", False)
        record.setdefault("privileged_access_provider", "")
        record.setdefault("privileged_access_url", "")
        record.setdefault("privileged_access_hint", "")
        record.update({"geoip_asn": None, "proxy_id": None, "updated_by": "demo-seed", "updated_at": int(time.time())})
        pipeline.set("server_{}".format(host["server_id"]), json.dumps(record, sort_keys=True))
    for project_set in PROJECT_SETS:
        pipeline.set("project_set_{}".format(project_set["name"]), json.dumps(project_set, sort_keys=True))
    for index, grant in enumerate(GRANTS, 1):
        pipeline.set("grant_{}".format(index), json.dumps(grant, sort_keys=True))
    pipeline.set("schema_version", 2)
    pipeline.set("offset_server_id", max(host["server_id"] for host in HOSTS))
    pipeline.set("offset_grant_id", len(GRANTS))
    pipeline.set("projects_list", " ".join(projects))
    for project in projects:
        names = sorted(host["server_name"] for host in HOSTS if host["project_name"] == project)
        pipeline.set("complete_hosts_{}".format(project), " ".join(names))
    pipeline.set("demo_seed_version", SEED_VERSION)
    pipeline.execute()
    print("Seeded {} hosts, {} grants, and {} project sets".format(len(HOSTS), len(GRANTS), len(PROJECT_SETS)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("Demo seed failed: {}".format(exc), file=sys.stderr)
        sys.exit(1)

