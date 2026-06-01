#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Isolate v2 administrative CLI."""

import argparse
import json
import os
import sys

from redis import Redis

from isolate_config import load_config
from isolate_identity import IdentityError, KeycloakDeviceClient, decode_jwt_payload, normalize_claims
from isolate_policy import PolicyDenied, resolve_policy


def redis_client(config):
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
        print(json.dumps(identity, indent=2, sort_keys=True))
    except IdentityError as exc:
        print("isolate login failed: {}".format(exc), file=sys.stderr)
        return 2


def build_parser():
    parser = argparse.ArgumentParser(prog="isolate")
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login")
    login.set_defaults(func=cmd_login)

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
