#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Isolate v2 administrative CLI."""

import argparse
import json
import os
import sys

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

    ps_remove = project_set_sub.add_parser("remove-project")
    ps_remove.add_argument("name")
    ps_remove.add_argument("project")
    ps_remove.set_defaults(func=cmd_project_set_remove_project)

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
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = load_config()
    return args.func(args, config) or 0


if __name__ == "__main__":
    sys.exit(main())
