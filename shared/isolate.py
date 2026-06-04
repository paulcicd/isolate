#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Isolate v2 administrative CLI."""

import argparse
import json
import os
import sys

from isolate_access import (
    AccessDenied,
    approve_access_request,
    create_access_request,
    deny_access_request,
    get_access_request,
    is_access_admin,
    list_access_requests,
    parse_duration,
)
from isolate_config import load_config
from isolate_identity import (
    IdentityError,
    KeycloakDeviceClient,
    clear_cached_identity,
    decode_jwt_payload,
    identity_cache_path,
    load_cached_identity,
    normalize_claims,
    save_identity,
)
from isolate_history import HistoryAccessDenied, format_history_table, read_history
from isolate_policy import PolicyDenied, resolve_grant, resolve_policy


def redis_client(config):
    from redis import Redis

    redis_cfg = config["redis"]
    return Redis(
        host=redis_cfg["host"],
        port=int(redis_cfg["port"]),
        password=redis_cfg.get("password"),
        db=int(redis_cfg["db"]),
    )


def decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def load_rules(redis):
    rules = []
    for key in redis.keys("policy_*"):
        rules.append(json.loads(decode(redis.get(key))))
    return rules


def load_grants(redis):
    grants = []
    for pattern in ("grant_*", "policy_*"):
        for key in redis.keys(pattern):
            grants.append(json.loads(decode(redis.get(key))))
    return grants


def load_project_sets(redis):
    project_sets = {}
    for key in redis.keys("project_set_*"):
        data = json.loads(decode(redis.get(key)))
        project_sets[data["name"]] = data
    return project_sets


def _redis_key_name(key):
    return decode(key)


def list_grant_records(redis, **filters):
    grants = []
    for key in redis.keys("grant_*"):
        key_name = _redis_key_name(key)
        grant = json.loads(decode(redis.get(key)))
        grant["id"] = key_name.replace("grant_", "", 1)
        if filters.get("user") and not (grant.get("subject") == "user" and grant.get("name") == filters["user"]):
            continue
        if filters.get("group") and not (grant.get("subject") == "group" and grant.get("name") == filters["group"]):
            continue
        if filters.get("project") and grant.get("project") != filters["project"]:
            continue
        if filters.get("project_set") and grant.get("project_set") != filters["project_set"]:
            continue
        if filters.get("project_glob") and grant.get("project_glob") != filters["project_glob"]:
            continue
        grants.append(grant)
    return sorted(grants, key=lambda grant: int(grant["id"]) if str(grant["id"]).isdigit() else grant["id"])


def get_grant_record(redis, grant_id):
    raw = redis.get("grant_{}".format(grant_id))
    if raw is None:
        return None
    grant = json.loads(decode(raw))
    grant["id"] = str(grant_id)
    return grant


def update_grant_record(redis, grant_id, updates):
    grant = get_grant_record(redis, grant_id)
    if grant is None:
        return None
    grant.pop("id", None)
    grant.update({key: value for key, value in updates.items() if value is not None})
    redis.set("grant_{}".format(grant_id), json.dumps(grant, sort_keys=True))
    grant["id"] = str(grant_id)
    return grant


def format_grants_table(grants):
    columns = [
        ("id", "id", 4),
        ("subject", "subject", 7),
        ("name", "name", 18),
        ("selector", "selector", 24),
        ("host", "host", 8),
        ("remote_user", "remote_user", 12),
        ("sudo_mode", "sudo_mode", 10),
    ]
    lines = ["  ".join(label.ljust(width) for _, label, width in columns)]
    for grant in grants:
        selector = grant.get("project") or grant.get("project_set") or grant.get("project_glob") or ""
        row = dict(grant)
        row["selector"] = selector
        lines.append("  ".join(str(row.get(key) or "").ljust(width) for key, _, width in columns))
    return "\n".join(lines)


def format_access_table(records):
    columns = [
        ("id", "id", 4),
        ("status", "status", 9),
        ("requester", "user", 16),
        ("project", "project", 14),
        ("host", "host", 8),
        ("remote_user", "remote_user", 12),
        ("sudo_mode", "sudo", 8),
        ("reason", "reason", 24),
    ]
    lines = ["  ".join(label.ljust(width) for _, label, width in columns)]
    for record in records:
        lines.append("  ".join(str(record.get(key) or "").ljust(width) for key, _, width in columns))
    return "\n".join(lines)


def _load_cli_identity():
    return load_cached_identity()


def _require_access_admin(config):
    identity = _load_cli_identity()
    if not is_access_admin(identity, config.get("access", {}).get("admin_groups") or []):
        raise AccessDenied("access administration is allowed only for configured admin groups")
    return identity


def cmd_policy_add(args, config):
    redis = redis_client(config)
    rule = {
        "schema_version": 2,
        "subject": args.subject,
        "name": args.name,
        "project": args.project,
        "host": args.host,
        "remote_user": args.remote_user,
        "sudo_mode": args.sudo_mode,
        "allowed_actions": args.allowed_action,
    }
    rule_id = redis.incr("offset_policy_id")
    redis.set("policy_{}".format(rule_id), json.dumps(rule, sort_keys=True))
    print("Policy added: {}".format(rule_id))


def cmd_policy_test(args, config):
    redis = redis_client(config)
    identity = normalize_claims(
        {
            "sub": "test:{}".format(args.user),
            "preferred_username": args.user,
            "groups": args.group or [],
        }
    )
    host = None
    if args.host:
        raw = redis.get("server_{}".format(args.host))
        if raw is not None:
            host = json.loads(decode(raw))
        else:
            host = {"server_id": args.host, "server_name": args.host}
    defaults = {}
    defaults.update(config.get("policy", {}))
    defaults.update(config.get("ssh", {}))
    try:
        decision = resolve_policy(
            identity,
            project=args.project,
            host=host,
            rules=load_rules(redis),
            defaults=defaults,
        )
        print(json.dumps(decision, indent=2, sort_keys=True))
    except PolicyDenied as exc:
        print(json.dumps({"denied": str(exc)}, indent=2, sort_keys=True))
        return 2
    return 0


def cmd_session_search(args, config):
    base = config["logging"]["base_path"]
    for root, _, files in os.walk(base):
        if "session.jsonl" not in files:
            continue
        path = os.path.join(root, "session.jsonl")
        with open(path, "r", encoding="utf-8") as session_f:
            for line in session_f:
                record = json.loads(line)
                if args.user and record.get("username") != args.user:
                    continue
                if args.project and record.get("project") != args.project:
                    continue
                print(json.dumps(record, sort_keys=True))


def cmd_whoami(args, config):
    try:
        identity = load_cached_identity()
    except IdentityError as exc:
        print("isolate identity unavailable: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(identity, indent=2, sort_keys=True))


def cmd_logout(args, config):
    removed = clear_cached_identity()
    if removed:
        print("Isolate identity removed: {}".format(identity_cache_path()))
    else:
        print("No Isolate identity found: {}".format(identity_cache_path()))


def cmd_login(args, config):
    client = KeycloakDeviceClient(config["keycloak"])
    try:
        device = client.start()
        url = device.get("verification_uri_complete") or device.get("verification_uri")
        print("Open this URL to authorize Isolate:")
        print(url)
        if device.get("user_code"):
            print("Code: {}".format(device["user_code"]))
        tokens = client.poll(device["device_code"], interval=int(device.get("interval", 5)))
        claims = {}
        if tokens.get("access_token"):
            introspected = client.introspect(tokens["access_token"])
            if introspected:
                claims.update(introspected)
        if tokens.get("id_token"):
            claims.update(decode_jwt_payload(tokens["id_token"]))
        identity = normalize_claims(claims)
        save_identity(identity)
        print(json.dumps(identity, indent=2, sort_keys=True))
    except IdentityError as exc:
        print("isolate login failed: {}".format(exc), file=sys.stderr)
        return 2


def _subject_from_args(args):
    if getattr(args, "user", None):
        return "user", args.user
    if getattr(args, "group", None):
        return "group", args.group
    raise ValueError("grant subject is required")


def cmd_project_set_add(args, config):
    redis = redis_client(config)
    key = "project_set_{}".format(args.name)
    existing = redis.get(key)
    if existing is not None:
        project_set = json.loads(decode(existing))
    else:
        project_set = {
            "schema_version": 2,
            "name": args.name,
            "projects": [],
            "project_globs": [],
        }
    project_set["projects"] = sorted(set((project_set.get("projects") or []) + (getattr(args, "project", None) or [])))
    project_set["project_globs"] = sorted(
        set((project_set.get("project_globs") or []) + (getattr(args, "project_glob", None) or []))
    )
    redis.set(key, json.dumps(project_set, sort_keys=True))
    print("Project set saved: {}".format(args.name))


def cmd_project_set_remove_project(args, config):
    redis = redis_client(config)
    key = "project_set_{}".format(args.name)
    existing = redis.get(key)
    if existing is None:
        print("Project set not found: {}".format(args.name), file=sys.stderr)
        return 2
    project_set = json.loads(decode(existing))
    project_set["projects"] = [p for p in project_set.get("projects") or [] if p != args.project]
    redis.set(key, json.dumps(project_set, sort_keys=True))
    print("Project removed from set: {} {}".format(args.name, args.project))


def cmd_project_set_list(args, config):
    redis = redis_client(config)
    rows = sorted(load_project_sets(redis).values(), key=lambda item: item["name"])
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    print("name                 projects  globs")
    for row in rows:
        print("{:<20} {:<8} {}".format(row["name"], len(row.get("projects") or []), len(row.get("project_globs") or [])))


def cmd_project_set_show(args, config):
    redis = redis_client(config)
    project_set = load_project_sets(redis).get(args.name)
    if project_set is None:
        print("Project set not found: {}".format(args.name), file=sys.stderr)
        return 2
    print(json.dumps(project_set, indent=2, sort_keys=True))


def cmd_project_set_remove_pattern(args, config):
    redis = redis_client(config)
    key = "project_set_{}".format(args.name)
    existing = redis.get(key)
    if existing is None:
        print("Project set not found: {}".format(args.name), file=sys.stderr)
        return 2
    project_set = json.loads(decode(existing))
    project_set["project_globs"] = [p for p in project_set.get("project_globs") or [] if p != args.project_glob]
    redis.set(key, json.dumps(project_set, sort_keys=True))
    print("Pattern removed from set: {} {}".format(args.name, args.project_glob))


def cmd_project_set_remove(args, config):
    redis = redis_client(config)
    deleted = redis.delete("project_set_{}".format(args.name))
    print("Project sets removed: {}".format(deleted))
    return 0 if deleted else 2


def cmd_grant_add(args, config):
    redis = redis_client(config)
    try:
        subject, name = _subject_from_args(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    grant = {
        "schema_version": 2,
        "subject": subject,
        "name": name,
        "project": args.project,
        "project_glob": args.project_glob,
        "project_set": args.project_set,
        "host": args.host,
        "remote_user": args.remote_user,
        "sudo_mode": args.sudo_mode,
        "allowed_actions": args.allowed_action,
    }
    grant_id = redis.incr("offset_grant_id")
    redis.set("grant_{}".format(grant_id), json.dumps(grant, sort_keys=True))
    print("Grant added: {}".format(grant_id))


def cmd_grant_revoke(args, config):
    redis = redis_client(config)
    if args.id:
        deleted = redis.delete("grant_{}".format(args.id))
        print("Grants revoked: {}".format(deleted))
        return 0 if deleted else 2

    try:
        subject, name = _subject_from_args(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    deleted = 0
    for key in redis.keys("grant_*"):
        grant = json.loads(decode(redis.get(key)))
        if grant.get("subject") != subject or grant.get("name") != name:
            continue
        if args.project and grant.get("project") != args.project:
            continue
        if args.project_glob and grant.get("project_glob") != args.project_glob:
            continue
        if args.project_set and grant.get("project_set") != args.project_set:
            continue
        if args.host and grant.get("host") != args.host:
            continue
        deleted += redis.delete(key)
    print("Grants revoked: {}".format(deleted))
    return 0 if deleted else 2


def cmd_grant_list(args, config):
    redis = redis_client(config)
    grants = list_grant_records(
        redis,
        user=args.user,
        group=args.group,
        project=args.project,
        project_set=args.project_set,
        project_glob=args.project_glob,
    )
    if args.json:
        print(json.dumps(grants, indent=2, sort_keys=True))
    else:
        print(format_grants_table(grants))


def cmd_grant_show(args, config):
    redis = redis_client(config)
    grant = get_grant_record(redis, args.id)
    if grant is None:
        print("Grant not found: {}".format(args.id), file=sys.stderr)
        return 2
    print(json.dumps(grant, indent=2, sort_keys=True))


def cmd_grant_update(args, config):
    redis = redis_client(config)
    selector_updates = {
        "project": args.project,
        "project_glob": args.project_glob,
        "project_set": args.project_set,
    }
    selected = [key for key, value in selector_updates.items() if value is not None]
    updates = {
        "host": args.host,
        "remote_user": args.remote_user,
        "sudo_mode": args.sudo_mode,
    }
    if selected:
        updates.update({"project": None, "project_glob": None, "project_set": None})
        updates[selected[0]] = selector_updates[selected[0]]
    if args.allowed_action is not None:
        updates["allowed_actions"] = args.allowed_action

    grant = get_grant_record(redis, args.id)
    if grant is None:
        print("Grant not found: {}".format(args.id), file=sys.stderr)
        return 2
    grant.pop("id", None)
    for key, value in updates.items():
        if value is None and key in ("project", "project_glob", "project_set") and selected:
            grant[key] = None
        elif value is not None:
            grant[key] = value
    redis.set("grant_{}".format(args.id), json.dumps(grant, sort_keys=True))
    grant["id"] = str(args.id)
    print(json.dumps(grant, indent=2, sort_keys=True))


def cmd_grant_test(args, config):
    redis = redis_client(config)
    identity = normalize_claims(
        {
            "sub": "test:{}".format(args.user),
            "preferred_username": args.user,
            "groups": args.group or [],
        }
    )
    host = None
    if args.host:
        raw = redis.get("server_{}".format(args.host))
        if raw is not None:
            host = json.loads(decode(raw))
        else:
            host = {"server_id": args.host, "server_name": args.host}
    defaults = {}
    defaults.update(config.get("policy", {}))
    defaults.update(config.get("ssh", {}))
    try:
        decision = resolve_grant(
            identity,
            project=args.project,
            host=host,
            grants=load_grants(redis),
            project_sets=load_project_sets(redis),
            defaults=defaults,
        )
        print(json.dumps(decision, indent=2, sort_keys=True))
    except PolicyDenied as exc:
        print(json.dumps({"denied": str(exc)}, indent=2, sort_keys=True))
        return 2
    return 0


def cmd_history(args, config):
    try:
        identity = load_cached_identity()
    except IdentityError as exc:
        print("isolate identity unavailable: {}; run isolate login".format(exc), file=sys.stderr)
        return 2

    history_cfg = config.get("history", {})
    default_limit = int(history_cfg.get("default_limit", 10))
    max_limit = int(history_cfg.get("max_limit", 100))
    limit = min(max(args.limit or default_limit, 1), max_limit)
    try:
        rows = read_history(
            config["logging"]["base_path"],
            identity,
            query=args.query,
            user=args.user,
            project=args.project,
            host=args.host,
            limit=limit,
            admin_groups=history_cfg.get("admin_groups") or [],
        )
    except HistoryAccessDenied as exc:
        print("history denied: {}".format(exc), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
    elif rows:
        print(format_history_table(rows))
    else:
        print("No connection history found")


def cmd_access_request(args, config):
    try:
        identity = _load_cli_identity()
    except IdentityError as exc:
        print("isolate identity unavailable: {}; run isolate login".format(exc), file=sys.stderr)
        return 2
    redis = redis_client(config)
    record = create_access_request(
        redis,
        identity,
        project=args.project,
        host=args.host,
        remote_user=args.remote_user,
        sudo_mode=args.sudo_mode,
        reason=args.reason,
    )
    print(json.dumps(record, indent=2, sort_keys=True))


def cmd_access_list(args, config):
    redis = redis_client(config)
    try:
        identity = _load_cli_identity()
    except IdentityError as exc:
        print("isolate identity unavailable: {}; run isolate login".format(exc), file=sys.stderr)
        return 2
    admin = is_access_admin(identity, config.get("access", {}).get("admin_groups") or [])
    if args.user and args.user != identity.get("username") and not admin:
        print("access list denied: other users are visible only to admins", file=sys.stderr)
        return 2
    user = args.user if admin else identity.get("username")
    records = list_access_requests(redis, status=args.status, user=user)
    if args.json:
        print(json.dumps(records, indent=2, sort_keys=True))
    else:
        print(format_access_table(records))


def cmd_access_show(args, config):
    redis = redis_client(config)
    record = get_access_request(redis, args.id)
    if record is None:
        print("Access request not found: {}".format(args.id), file=sys.stderr)
        return 2
    try:
        identity = _load_cli_identity()
    except IdentityError as exc:
        print("isolate identity unavailable: {}; run isolate login".format(exc), file=sys.stderr)
        return 2
    admin = is_access_admin(identity, config.get("access", {}).get("admin_groups") or [])
    if record.get("requester") != identity.get("username") and not admin:
        print("access show denied: other users are visible only to admins", file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2, sort_keys=True))


def cmd_access_approve(args, config):
    redis = redis_client(config)
    try:
        approver = _require_access_admin(config)
        access_cfg = config.get("access", {})
        ttl = parse_duration(args.ttl, default=access_cfg.get("default_ttl", "2h"))
        max_ttl = parse_duration(access_cfg.get("max_ttl", "24h"))
        record, grant = approve_access_request(
            redis,
            args.id,
            approver,
            ttl,
            remote_user=args.remote_user,
            sudo_mode=args.sudo_mode,
            max_ttl=max_ttl,
        )
    except (AccessDenied, IdentityError, ValueError) as exc:
        print("access approve failed: {}".format(exc), file=sys.stderr)
        return 2
    if record is None:
        print("Access request not found: {}".format(args.id), file=sys.stderr)
        return 2
    print(json.dumps({"request": record, "grant": grant}, indent=2, sort_keys=True))


def cmd_access_deny(args, config):
    redis = redis_client(config)
    try:
        approver = _require_access_admin(config)
        record = deny_access_request(redis, args.id, approver, reason=args.reason)
    except (AccessDenied, IdentityError) as exc:
        print("access deny failed: {}".format(exc), file=sys.stderr)
        return 2
    if record is None:
        print("Access request not found: {}".format(args.id), file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(prog="isolate")
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login")
    login.set_defaults(func=cmd_login)

    whoami = sub.add_parser("whoami")
    whoami.set_defaults(func=cmd_whoami)

    logout = sub.add_parser("logout")
    logout.set_defaults(func=cmd_logout)

    policy = sub.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)

    add = policy_sub.add_parser("add")
    add.add_argument("--subject", choices=["user", "group"], required=True)
    add.add_argument("--name", required=True)
    add.add_argument("--project")
    add.add_argument("--host")
    add.add_argument("--remote-user", required=True)
    add.add_argument("--sudo-mode", default="sudo-i")
    add.add_argument("--allowed-action", action="append", default=["ssh"])
    add.set_defaults(func=cmd_policy_add)

    test = policy_sub.add_parser("test")
    test.add_argument("--user", required=True)
    test.add_argument("--group", action="append")
    test.add_argument("--project")
    test.add_argument("--host")
    test.set_defaults(func=cmd_policy_test)

    project_set = sub.add_parser("project-set")
    project_set_sub = project_set.add_subparsers(dest="project_set_command", required=True)
    ps_add = project_set_sub.add_parser("add")
    ps_add.add_argument("name")
    ps_add.add_argument("--project", action="append")
    ps_add.add_argument("--project-glob", action="append")
    ps_add.set_defaults(func=cmd_project_set_add)

    ps_add_pattern = project_set_sub.add_parser("add-pattern")
    ps_add_pattern.add_argument("name")
    ps_add_pattern.add_argument("--project-glob", action="append", required=True)
    ps_add_pattern.set_defaults(func=cmd_project_set_add)

    ps_list = project_set_sub.add_parser("list")
    ps_list.add_argument("--json", action="store_true")
    ps_list.set_defaults(func=cmd_project_set_list)

    ps_show = project_set_sub.add_parser("show")
    ps_show.add_argument("name")
    ps_show.set_defaults(func=cmd_project_set_show)

    ps_remove = project_set_sub.add_parser("remove-project")
    ps_remove.add_argument("name")
    ps_remove.add_argument("project")
    ps_remove.set_defaults(func=cmd_project_set_remove_project)

    ps_remove_pattern = project_set_sub.add_parser("remove-pattern")
    ps_remove_pattern.add_argument("name")
    ps_remove_pattern.add_argument("project_glob")
    ps_remove_pattern.set_defaults(func=cmd_project_set_remove_pattern)

    ps_remove_set = project_set_sub.add_parser("remove")
    ps_remove_set.add_argument("name")
    ps_remove_set.set_defaults(func=cmd_project_set_remove)

    grant = sub.add_parser("grant")
    grant_sub = grant.add_subparsers(dest="grant_command", required=True)

    grant_add = grant_sub.add_parser("add")
    subject = grant_add.add_mutually_exclusive_group(required=True)
    subject.add_argument("--user")
    subject.add_argument("--group")
    selector = grant_add.add_mutually_exclusive_group(required=True)
    selector.add_argument("--project")
    selector.add_argument("--project-glob")
    selector.add_argument("--project-set")
    grant_add.add_argument("--host")
    grant_add.add_argument("--remote-user", required=True)
    grant_add.add_argument("--sudo-mode", default="sudo-i")
    grant_add.add_argument("--allowed-action", action="append", default=["ssh"])
    grant_add.set_defaults(func=cmd_grant_add)

    grant_revoke = grant_sub.add_parser("revoke")
    grant_revoke.add_argument("--id")
    revoke_subject = grant_revoke.add_mutually_exclusive_group()
    revoke_subject.add_argument("--user")
    revoke_subject.add_argument("--group")
    grant_revoke.add_argument("--project")
    grant_revoke.add_argument("--project-glob")
    grant_revoke.add_argument("--project-set")
    grant_revoke.add_argument("--host")
    grant_revoke.set_defaults(func=cmd_grant_revoke)

    grant_list = grant_sub.add_parser("list")
    grant_list.add_argument("--user")
    grant_list.add_argument("--group")
    grant_list.add_argument("--project")
    grant_list.add_argument("--project-glob")
    grant_list.add_argument("--project-set")
    grant_list.add_argument("--json", action="store_true")
    grant_list.set_defaults(func=cmd_grant_list)

    grant_show = grant_sub.add_parser("show")
    grant_show.add_argument("--id", required=True)
    grant_show.set_defaults(func=cmd_grant_show)

    grant_update = grant_sub.add_parser("update")
    grant_update.add_argument("--id", required=True)
    selector_update = grant_update.add_mutually_exclusive_group()
    selector_update.add_argument("--project")
    selector_update.add_argument("--project-glob")
    selector_update.add_argument("--project-set")
    grant_update.add_argument("--host")
    grant_update.add_argument("--remote-user")
    grant_update.add_argument("--sudo-mode")
    grant_update.add_argument("--allowed-action", action="append")
    grant_update.set_defaults(func=cmd_grant_update)

    grant_test = grant_sub.add_parser("test")
    grant_test.add_argument("--user", required=True)
    grant_test.add_argument("--group", action="append")
    grant_test.add_argument("--project")
    grant_test.add_argument("--host")
    grant_test.set_defaults(func=cmd_grant_test)

    session = sub.add_parser("session")
    session_sub = session.add_subparsers(dest="session_command", required=True)
    search = session_sub.add_parser("search")
    search.add_argument("--user")
    search.add_argument("--project")
    search.set_defaults(func=cmd_session_search)

    history = sub.add_parser("history")
    history.add_argument("query", nargs="?")
    history.add_argument("--user")
    history.add_argument("--project")
    history.add_argument("--host")
    history.add_argument("--limit", type=int)
    history.add_argument("--json", action="store_true")
    history.set_defaults(func=cmd_history)

    access = sub.add_parser("access")
    access_sub = access.add_subparsers(dest="access_command", required=True)
    access_request = access_sub.add_parser("request")
    access_request.add_argument("--project", required=True)
    access_request.add_argument("--host")
    access_request.add_argument("--remote-user")
    access_request.add_argument("--sudo-mode")
    access_request.add_argument("--reason", required=True)
    access_request.set_defaults(func=cmd_access_request)

    access_list = access_sub.add_parser("list")
    access_list.add_argument("--status", choices=["pending", "approved", "denied"])
    access_list.add_argument("--user")
    access_list.add_argument("--json", action="store_true")
    access_list.set_defaults(func=cmd_access_list)

    access_show = access_sub.add_parser("show")
    access_show.add_argument("--id", required=True)
    access_show.set_defaults(func=cmd_access_show)

    access_approve = access_sub.add_parser("approve")
    access_approve.add_argument("--id", required=True)
    access_approve.add_argument("--ttl")
    access_approve.add_argument("--remote-user")
    access_approve.add_argument("--sudo-mode")
    access_approve.set_defaults(func=cmd_access_approve)

    access_deny = access_sub.add_parser("deny")
    access_deny.add_argument("--id", required=True)
    access_deny.add_argument("--reason", required=True)
    access_deny.set_defaults(func=cmd_access_deny)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = load_config()
    return args.func(args, config) or 0


if __name__ == "__main__":
    sys.exit(main())
