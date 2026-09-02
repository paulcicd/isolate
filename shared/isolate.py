#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Isolate v2 administrative CLI."""

import argparse
import datetime
import json
import os
import sys

from isolate_access import (
    AccessDenied,
    approve_access_request,
    comment_access_request,
    create_access_request,
    deny_access_request,
    get_access_request,
    is_access_admin,
    list_access_requests,
    parse_duration,
    repeat_access_request,
    set_notification_status,
)
from isolate_audit import AuditSinkError, verify_jsonl_file
from isolate_backup import BackupError, create_backup, list_backups, restore_backup, verify_backup
from isolate_command_audit import CommandAuditError, append_command_event
from isolate_config import load_config
from isolate_identity import (
    IdentityError,
    KeycloakDeviceClient,
    clear_cached_identity,
    decode_jwt_payload,
    identity_cache_path,
    load_verified_identity,
    normalize_claims,
    refresh_jwks_cache,
    save_token_cache,
)
from isolate_history import HistoryAccessDenied, format_history_table, read_history
from isolate_inventory import HostValidationError, format_hosts_table, get_host, list_hosts, update_host
from isolate_notifications import NotificationError, notify_access_event
from isolate_policy import PolicyDenied, resolve_grant, resolve_policy
from isolate_health import run_health_checks, validate_config
from isolate_policy_bundle import (
    PolicyBundleError,
    apply_bundle,
    change_count,
    dump_bundle,
    export_bundle,
    load_bundle,
    plan_bundle,
    validate_bundle,
)
from isolate_redis import create_redis_client


def redis_client(config):
    return create_redis_client(config)


def backup_redis_client(config):
    backup_redis = (config.get("backup", {}) or {}).get("redis", {}) or {}
    if not backup_redis:
        return redis_client(config)
    backup_config = dict(config)
    redis_config = dict(config.get("redis", {}) or {})
    redis_config.update(backup_redis)
    backup_config["redis"] = redis_config
    return create_redis_client(backup_config)


def _write_private_file(path, content):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, mode=0o750, exist_ok=True)
    with open(path, "w", encoding="utf-8") as output_f:
        output_f.write(content)
    if os.name == "posix":
        os.chmod(path, 0o640)


def cmd_config_validate(args, config):
    result = validate_config(config, check_paths=args.check_paths)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Configuration: {}".format("valid" if result["valid"] else "invalid"))
        for warning in result["warnings"]:
            print("warning: {}".format(warning))
        for error in result["errors"]:
            print("error: {}".format(error), file=sys.stderr)
    return 0 if result["valid"] else 2


def cmd_health(args, config):
    result = run_health_checks(config)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Isolate health: {}".format(result["status"]))
        for name, check in result["checks"].items():
            print("{:<10} {}{}".format(name, "ok" if check.get("ok") else "failed", ": {}".format(check.get("error")) if check.get("error") else ""))
    return 0 if result["ok"] else 2


def cmd_audit_verify(args, config):
    integrity = config.get("logging", {}).get("integrity") or {}
    key_file = args.key_file or integrity.get("key_file")
    if not key_file:
        print("audit verification failed: integrity key file is not configured", file=sys.stderr)
        return 2
    try:
        result = verify_jsonl_file(args.path, key_file)
    except (OSError, ValueError, AuditSinkError) as exc:
        print("audit verification failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


def cmd_backup_create(args, config):
    try:
        result = create_backup(
            config,
            backup_redis_client(config),
            output_path=args.output,
            include_logs=args.include_logs,
        )
    except Exception as exc:
        print("backup create failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))


def cmd_backup_list(args, config):
    try:
        rows = list_backups(config)
    except (OSError, ValueError, BackupError) as exc:
        print("backup list failed: {}".format(exc), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0
    print("created_at                 size       files  redis  archive")
    for row in rows:
        print("{:<26} {:<10} {:<6} {:<6} {}".format(
            str(row.get("created_at") or "error"),
            str(row.get("size") or ""),
            str(row.get("file_count") or ""),
            str(row.get("redis_key_count") or ""),
            row.get("archive"),
        ))


def cmd_backup_verify(args, config):
    try:
        result = verify_backup(args.archive)
    except (OSError, ValueError, BackupError) as exc:
        print("backup verify failed: {}".format(exc), file=sys.stderr)
        return 2
    display = dict(result)
    display.pop("manifest", None)
    print(json.dumps(display, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


def cmd_backup_restore(args, config):
    if not args.yes:
        print("backup restore requires --yes", file=sys.stderr)
        return 2
    try:
        result = restore_backup(
            args.archive,
            args.target_root,
            redis=backup_redis_client(config) if args.restore_redis else None,
            restore_files=not args.skip_files,
            restore_redis=args.restore_redis,
            redis_conflict=args.redis_conflict,
            preserve_owner=args.preserve_owner,
            confirmed=True,
            live=args.live,
        )
    except Exception as exc:
        print("backup restore failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))


def _policy_bundle_from_args(args, config):
    path = args.file or config.get("policy_as_code", {}).get("bundle_path")
    if not path:
        raise PolicyBundleError("policy bundle path is required")
    return path, load_bundle(path)


def cmd_policy_export(args, config):
    bundle = export_bundle(redis_client(config))
    rendered = dump_bundle(bundle, output_format=args.format)
    if args.output == "-":
        sys.stdout.write(rendered)
    else:
        _write_private_file(args.output, rendered)
        print("Policy bundle exported: {}".format(args.output))


def cmd_policy_validate(args, config):
    try:
        path, bundle = _policy_bundle_from_args(args, config)
        result = validate_bundle(bundle)
    except (OSError, ValueError, PolicyBundleError) as exc:
        print("policy validation failed: {}".format(exc), file=sys.stderr)
        return 2
    result["path"] = path
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


def cmd_policy_diff(args, config):
    try:
        path, bundle = _policy_bundle_from_args(args, config)
        changes = plan_bundle(redis_client(config), bundle, prune=args.prune)
    except (OSError, ValueError, PolicyBundleError) as exc:
        print("policy diff failed: {}".format(exc), file=sys.stderr)
        return 2
    output = {"path": path, "prune": bool(args.prune), "change_count": change_count(changes), "changes": changes}
    print(json.dumps(output, indent=2, sort_keys=True))


def cmd_policy_apply(args, config):
    policy_cfg = config.get("policy_as_code", {})
    if policy_cfg.get("require_confirmation", True) and not args.dry_run and not args.yes:
        print("policy apply requires --yes; use --dry-run to preview changes", file=sys.stderr)
        return 2
    try:
        path, bundle = _policy_bundle_from_args(args, config)
        redis = redis_client(config)
        changes = plan_bundle(redis, bundle, prune=args.prune)
        if not args.dry_run and change_count(changes):
            backup_dir = policy_cfg.get("backup_dir") or os.path.join(config.get("data_root", "/opt/auth"), "backups")
            stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
            backup_path = os.path.join(backup_dir, "policy-{}.yml".format(stamp))
            _write_private_file(backup_path, dump_bundle(export_bundle(redis), output_format="yaml"))
        else:
            backup_path = None
        changes = apply_bundle(redis, bundle, prune=args.prune, dry_run=args.dry_run)
    except (OSError, ValueError, PolicyBundleError) as exc:
        print("policy apply failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps({
        "applied": not args.dry_run,
        "backup_path": backup_path,
        "change_count": change_count(changes),
        "changes": changes,
        "source": path,
    }, indent=2, sort_keys=True))


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
            key_name = _redis_key_name(key)
            grant = json.loads(decode(redis.get(key)))
            if key_name.startswith("grant_"):
                grant["id"] = key_name.replace("grant_", "", 1)
            elif key_name.startswith("policy_"):
                grant["id"] = key_name
            grants.append(grant)
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


def _print_notification_warnings(result):
    for error in result.get("errors") or []:
        print("notification warning: {}".format(error), file=sys.stderr)


def _record_notification_status(redis, request_id, result=None, error=None):
    if error:
        set_notification_status(redis, request_id, {"ok": False, "errors": [str(error)], "sent": []})
    elif result is not None:
        set_notification_status(redis, request_id, {"ok": not bool(result.get("errors")), "errors": result.get("errors") or [], "sent": result.get("sent") or []})


def _load_cli_identity():
    return load_verified_identity(load_config())


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
        identity = load_verified_identity(config)
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
        save_token_cache(tokens, identity)
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


def _str2bool(value):
    if value is None:
        return None
    value = str(value).strip().lower()
    if value in ("1", "true", "yes", "y", "on"):
        return True
    if value in ("0", "false", "no", "n", "off"):
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def cmd_host_list(args, config):
    rows = list_hosts(redis_client(config), project=args.project, query=args.query)
    if args.json:
        print(json.dumps(rows, indent=2, sort_keys=True))
    else:
        print(format_hosts_table(rows))


def cmd_host_show(args, config):
    host = get_host(redis_client(config), args.server_id)
    if host is None:
        print("Host not found: {}".format(args.server_id), file=sys.stderr)
        return 2
    print(json.dumps(host, indent=2, sort_keys=True))


def cmd_host_update(args, config):
    redis = redis_client(config)
    updates = {
        "project_name": args.project,
        "server_name": args.name,
        "server_ip": args.ip,
        "server_port": args.port,
        "server_user": args.user,
        "server_nosudo": args.nosudo,
        "server_vip": args.vip,
        "server_services": args.services,
        "server_note": args.note,
        "privileged_access_provider": args.privileged_provider,
        "privileged_access_url": args.privileged_url,
        "privileged_access_hint": args.privileged_hint,
        "proxy_id": args.proxy_id,
    }
    try:
        host = update_host(redis, args.server_id, updates, updated_by=os.getenv("USER") or os.getenv("USERNAME"))
    except (HostValidationError, ValueError) as exc:
        print("host update failed: {}".format(exc), file=sys.stderr)
        return 2
    if host is None:
        print("Host not found: {}".format(args.server_id), file=sys.stderr)
        return 2
    print(json.dumps(host, indent=2, sort_keys=True))


def cmd_grant_explain(args, config):
    redis = redis_client(config)
    host = get_host(redis, args.host) if args.host else None
    if args.host and host is None:
        host = {"server_id": args.host, "server_name": args.host}
    project = args.project or (host or {}).get("project_name")

    identity = {"username": args.user, "groups": args.group or [], "roles": args.role or []}
    if not args.group:
        try:
            current = load_verified_identity(config)
            if not args.user or args.user == current.get("username"):
                identity = current
        except IdentityError:
            pass
    if args.user:
        identity["username"] = args.user

    try:
        decision = resolve_grant(
            identity,
            project=project,
            host=host,
            grants=load_grants(redis),
            project_sets=load_project_sets(redis),
            defaults={**config.get("policy", {}), **config.get("ssh", {})},
        )
        matched = decision.get("matched_rule") or {}
        output = {
            "allowed": True,
            "user": identity.get("username"),
            "groups": identity.get("groups") or [],
            "project": project,
            "host": host,
            "remote_user": decision.get("remote_user"),
            "sudo_mode": decision.get("sudo_mode"),
            "allowed_actions": decision.get("allowed_actions"),
            "matched_grant": {
                "id": matched.get("id"),
                "subject": matched.get("subject"),
                "name": matched.get("name"),
                "host": matched.get("host") or matched.get("host_id") or matched.get("server_id"),
                "project": matched.get("project"),
                "project_glob": matched.get("project_glob"),
                "project_set": matched.get("project_set"),
            },
        }
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except PolicyDenied as exc:
        output = {
            "allowed": False,
            "user": identity.get("username"),
            "groups": identity.get("groups") or [],
            "project": project,
            "host": host,
            "reason": str(exc),
            "suggested_request": "isolate access request --project {}{} --reason <reason>".format(
                project or "<project>",
                " --host {}".format(args.host) if args.host else "",
            ),
        }
        print(json.dumps(output, indent=2, sort_keys=True))
        return 2


def cmd_history(args, config):
    try:
        identity = load_verified_identity(config)
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
    try:
        record = create_access_request(
            redis,
            identity,
            project=args.project,
            host=args.host,
            remote_user=args.remote_user,
            sudo_mode=args.sudo_mode,
            reason=args.reason,
            ticket=args.ticket,
            template=args.template,
            config=config,
        )
    except AccessDenied as exc:
        print("access request failed: {}".format(exc), file=sys.stderr)
        return 2
    try:
        notify_result = notify_access_event(config, "access_request_created", record, actor=identity)
        _record_notification_status(redis, record["id"], result=notify_result)
        record = get_access_request(redis, record["id"]) or record
        _print_notification_warnings(notify_result)
    except NotificationError as exc:
        _record_notification_status(redis, record["id"], error=exc)
        print("access request notification failed: {}".format(exc), file=sys.stderr)
        return 2
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
    records = list_access_requests(redis, status=args.status, user=user, project=args.project, ticket=args.ticket)
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
            comment=args.comment,
        )
    except (AccessDenied, IdentityError, ValueError) as exc:
        print("access approve failed: {}".format(exc), file=sys.stderr)
        return 2
    if record is None:
        print("Access request not found: {}".format(args.id), file=sys.stderr)
        return 2
    try:
        notify_result = notify_access_event(config, "access_request_approved", record, actor=approver, extra={"grant": grant})
        _record_notification_status(redis, record["id"], result=notify_result)
        record = get_access_request(redis, record["id"]) or record
        _print_notification_warnings(notify_result)
    except NotificationError as exc:
        _record_notification_status(redis, record["id"], error=exc)
        print("access approve notification failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps({"request": record, "grant": grant}, indent=2, sort_keys=True))


def cmd_access_deny(args, config):
    redis = redis_client(config)
    try:
        approver = _require_access_admin(config)
        record = deny_access_request(redis, args.id, approver, reason=args.reason, comment=args.comment)
    except (AccessDenied, IdentityError) as exc:
        print("access deny failed: {}".format(exc), file=sys.stderr)
        return 2
    if record is None:
        print("Access request not found: {}".format(args.id), file=sys.stderr)
        return 2
    try:
        notify_result = notify_access_event(config, "access_request_denied", record, actor=approver)
        _record_notification_status(redis, record["id"], result=notify_result)
        record = get_access_request(redis, record["id"]) or record
        _print_notification_warnings(notify_result)
    except NotificationError as exc:
        _record_notification_status(redis, record["id"], error=exc)
        print("access deny notification failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2, sort_keys=True))


def cmd_access_comment(args, config):
    redis = redis_client(config)
    try:
        identity = _load_cli_identity()
    except IdentityError as exc:
        print("isolate identity unavailable: {}; run isolate login".format(exc), file=sys.stderr)
        return 2
    record = get_access_request(redis, args.id)
    if record is None:
        print("Access request not found: {}".format(args.id), file=sys.stderr)
        return 2
    admin = is_access_admin(identity, config.get("access", {}).get("admin_groups") or [])
    if record.get("requester") != identity.get("username") and not admin:
        print("access comment denied: other users are visible only to admins", file=sys.stderr)
        return 2
    record = comment_access_request(redis, args.id, identity, args.text)
    print(json.dumps(record, indent=2, sort_keys=True))


def cmd_access_repeat(args, config):
    redis = redis_client(config)
    try:
        identity = _load_cli_identity()
    except IdentityError as exc:
        print("isolate identity unavailable: {}; run isolate login".format(exc), file=sys.stderr)
        return 2
    old = get_access_request(redis, args.id)
    if old is None:
        print("Access request not found: {}".format(args.id), file=sys.stderr)
        return 2
    admin = is_access_admin(identity, config.get("access", {}).get("admin_groups") or [])
    if old.get("requester") != identity.get("username") and not admin:
        print("access repeat denied: other users are visible only to admins", file=sys.stderr)
        return 2
    try:
        record = repeat_access_request(redis, args.id, identity, reason=args.reason, ticket=args.ticket, config=config)
    except AccessDenied as exc:
        print("access repeat failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2, sort_keys=True))


def cmd_command_log_append(args, config):
    try:
        record = append_command_event(
            config["logging"]["base_path"],
            args.connection_id,
            args.command,
            cwd=args.cwd,
            exit_code=args.exit_code,
            project=args.project,
            host_id=args.host_id,
            shell=args.shell,
            source=args.source,
            config=config,
        )
    except (CommandAuditError, ValueError) as exc:
        print("command audit failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2, sort_keys=True))


def cmd_jwks_refresh(args, config):
    try:
        jwks = refresh_jwks_cache(config.get("keycloak", {}))
    except IdentityError as exc:
        print("jwks refresh failed: {}".format(exc), file=sys.stderr)
        return 2
    print(json.dumps({"keys": len(jwks.get("keys") or []), "cache_path": config.get("keycloak", {}).get("jwks_cache_path")}, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(prog="isolate")
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login")
    login.set_defaults(func=cmd_login)

    whoami = sub.add_parser("whoami")
    whoami.set_defaults(func=cmd_whoami)

    logout = sub.add_parser("logout")
    logout.set_defaults(func=cmd_logout)

    config_cmd = sub.add_parser("config")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    config_validate = config_sub.add_parser("validate")
    config_validate.add_argument("--check-paths", action="store_true")
    config_validate.add_argument("--json", action="store_true")
    config_validate.set_defaults(func=cmd_config_validate)

    health = sub.add_parser("health")
    health.add_argument("--json", action="store_true")
    health.set_defaults(func=cmd_health)

    audit = sub.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_verify = audit_sub.add_parser("verify")
    audit_verify.add_argument("--path", required=True)
    audit_verify.add_argument("--key-file")
    audit_verify.set_defaults(func=cmd_audit_verify)

    backup = sub.add_parser("backup")
    backup_sub = backup.add_subparsers(dest="backup_command", required=True)
    backup_create = backup_sub.add_parser("create")
    backup_create.add_argument("--output")
    backup_create.add_argument("--include-logs", action="store_true", default=None)
    backup_create.set_defaults(func=cmd_backup_create)
    backup_list = backup_sub.add_parser("list")
    backup_list.add_argument("--json", action="store_true")
    backup_list.set_defaults(func=cmd_backup_list)
    backup_verify = backup_sub.add_parser("verify")
    backup_verify.add_argument("--archive", required=True)
    backup_verify.set_defaults(func=cmd_backup_verify)
    backup_restore = backup_sub.add_parser("restore")
    backup_restore.add_argument("--archive", required=True)
    backup_restore.add_argument("--target-root", required=True)
    backup_restore.add_argument("--restore-redis", action="store_true")
    backup_restore.add_argument("--skip-files", action="store_true")
    backup_restore.add_argument("--redis-conflict", choices=["abort", "replace", "skip"], default="abort")
    backup_restore.add_argument("--preserve-owner", action="store_true")
    backup_restore.add_argument("--live", action="store_true")
    backup_restore.add_argument("--yes", action="store_true")
    backup_restore.set_defaults(func=cmd_backup_restore)

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

    policy_export = policy_sub.add_parser("export")
    policy_export.add_argument("--output", default="-")
    policy_export.add_argument("--format", choices=["yaml", "json"], default="yaml")
    policy_export.set_defaults(func=cmd_policy_export)

    policy_validate = policy_sub.add_parser("validate")
    policy_validate.add_argument("--file")
    policy_validate.set_defaults(func=cmd_policy_validate)

    policy_diff = policy_sub.add_parser("diff")
    policy_diff.add_argument("--file")
    policy_diff.add_argument("--prune", action="store_true")
    policy_diff.set_defaults(func=cmd_policy_diff)

    policy_apply = policy_sub.add_parser("apply")
    policy_apply.add_argument("--file")
    policy_apply.add_argument("--prune", action="store_true")
    policy_apply.add_argument("--dry-run", action="store_true")
    policy_apply.add_argument("--yes", action="store_true")
    policy_apply.set_defaults(func=cmd_policy_apply)

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

    grant_explain = grant_sub.add_parser("explain")
    grant_explain.add_argument("--user", required=True)
    grant_explain.add_argument("--group", action="append")
    grant_explain.add_argument("--role", action="append")
    grant_explain.add_argument("--project")
    grant_explain.add_argument("--host")
    grant_explain.set_defaults(func=cmd_grant_explain)

    host = sub.add_parser("host")
    host_sub = host.add_subparsers(dest="host_command", required=True)
    host_list = host_sub.add_parser("list")
    host_list.add_argument("--project")
    host_list.add_argument("--query")
    host_list.add_argument("--json", action="store_true")
    host_list.set_defaults(func=cmd_host_list)

    host_show = host_sub.add_parser("show")
    host_show.add_argument("server_id")
    host_show.set_defaults(func=cmd_host_show)

    host_update = host_sub.add_parser("update")
    host_update.add_argument("server_id")
    host_update.add_argument("--project")
    host_update.add_argument("--name")
    host_update.add_argument("--ip")
    host_update.add_argument("--port", type=int)
    host_update.add_argument("--user")
    host_update.add_argument("--nosudo", type=_str2bool)
    host_update.add_argument("--vip", type=_str2bool)
    host_update.add_argument("--services")
    host_update.add_argument("--note")
    host_update.add_argument("--privileged-provider")
    host_update.add_argument("--privileged-url")
    host_update.add_argument("--privileged-hint")
    host_update.add_argument("--proxy-id")
    host_update.set_defaults(func=cmd_host_update)

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

    command_log = sub.add_parser("command-log")
    command_log_sub = command_log.add_subparsers(dest="command_log_command", required=True)
    command_append = command_log_sub.add_parser("append")
    command_append.add_argument("--connection-id", required=True)
    command_append.add_argument("--host-id")
    command_append.add_argument("--project")
    command_append.add_argument("--cwd")
    command_append.add_argument("--exit-code", type=int)
    command_append.add_argument("--shell", default="unknown")
    command_append.add_argument("--source", default="target-shell-hook")
    command_append.add_argument("--command", required=True)
    command_append.set_defaults(func=cmd_command_log_append)

    access = sub.add_parser("access")
    access_sub = access.add_subparsers(dest="access_command", required=True)
    access_request = access_sub.add_parser("request")
    access_request.add_argument("--project", required=True)
    access_request.add_argument("--host")
    access_request.add_argument("--remote-user")
    access_request.add_argument("--sudo-mode")
    access_request.add_argument("--reason", required=True)
    access_request.add_argument("--ticket")
    access_request.add_argument("--template")
    access_request.set_defaults(func=cmd_access_request)

    access_list = access_sub.add_parser("list")
    access_list.add_argument("--status", choices=["pending", "approved", "denied"])
    access_list.add_argument("--user")
    access_list.add_argument("--project")
    access_list.add_argument("--ticket")
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
    access_approve.add_argument("--comment")
    access_approve.set_defaults(func=cmd_access_approve)

    access_deny = access_sub.add_parser("deny")
    access_deny.add_argument("--id", required=True)
    access_deny.add_argument("--reason", required=True)
    access_deny.add_argument("--comment")
    access_deny.set_defaults(func=cmd_access_deny)

    access_comment = access_sub.add_parser("comment")
    access_comment.add_argument("--id", required=True)
    access_comment.add_argument("--text", required=True)
    access_comment.set_defaults(func=cmd_access_comment)

    access_repeat = access_sub.add_parser("repeat")
    access_repeat.add_argument("--id", required=True)
    access_repeat.add_argument("--reason")
    access_repeat.add_argument("--ticket")
    access_repeat.set_defaults(func=cmd_access_repeat)

    jwks = sub.add_parser("jwks")
    jwks_sub = jwks.add_subparsers(dest="jwks_command", required=True)
    jwks_refresh = jwks_sub.add_parser("refresh")
    jwks_refresh.set_defaults(func=cmd_jwks_refresh)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = load_config()
    return args.func(args, config) or 0


if __name__ == "__main__":
    sys.exit(main())
