#!/usr/bin/env python3
"""Explicit authoritative-state initialization, migration and recovery tools."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "shared"))

from isolate_config import load_config
from isolate_redis import create_ephemeral_redis_client, create_redis_client
from isolate_state import SQLState, StateError
from isolate_state_migration import (abort_migration, activate_restored, cutover,
    freeze_source, import_source, plan_migration, restore_snapshot, verify_migration,
    write_snapshot)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="trusted server config; DSNs remain in protected files")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="explicitly create a versioned SQL state schema")
    initialize.add_argument("--empty-installation", action="store_true", help="activate a new empty installation; never use for migration")
    initialize.add_argument("--yes", action="store_true")
    commands.add_parser("plan", help="read-only migration dry run and checksum")
    commands.add_parser("status", help="schema/generation/status only; never credential values")
    for name in ("freeze", "import", "cutover", "abort", "restore", "activate-restored"):
        command = commands.add_parser(name)
        command.add_argument("--yes", action="store_true")
        command.add_argument("--writers-stopped", action="store_true")
        command.add_argument("--legacy-acl-fenced", action="store_true")
        command.add_argument("--all-ingress-drained", action="store_true")
        if name in ("freeze", "cutover", "activate-restored"):
            command.add_argument("--actor", required=True)
        if name == "restore":
            command.add_argument("--input", required=True)
        if name == "activate-restored":
            command.add_argument("--reason", required=True)
    commands.add_parser("verify", help="compare the frozen Redis source with the imported SQL target")
    export = commands.add_parser("export", help="write a private SQL state snapshot, including revisions/tombstones")
    export.add_argument("--output", required=True)
    rotate = commands.add_parser("rotate-epoch", help="fence old tickets and sessions after recovery")
    rotate.add_argument("--actor", required=True)
    rotate.add_argument("--reason", required=True)
    rotate.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    config = load_config(path=args.config, use_env=False)
    options = config.get("state") or {}
    try:
        target = SQLState(options)
        if args.command == "status":
            result = target.metadata()
        elif args.command == "plan":
            result = plan_migration(create_ephemeral_redis_client(config), target)
        elif args.command == "init":
            if not args.yes:
                parser.error("schema initialization requires --yes")
            result = target.initialize(active=args.empty_installation)
        elif args.command == "verify":
            result = verify_migration(create_ephemeral_redis_client(config), target)
        elif args.command == "export":
            result = write_snapshot(target, args.output)
        elif args.command == "rotate-epoch":
            if not args.yes:
                parser.error("epoch rotation requires --yes")
            from isolate_recovery import rotate_authority_epoch
            epoch = rotate_authority_epoch(create_redis_client(config), config, args.actor, args.reason)
            result = {"epoch_rotated": True, "epoch": epoch}
        else:
            acknowledged = (args.yes and args.writers_stopped and args.legacy_acl_fenced and args.all_ingress_drained)
            if not acknowledged:
                parser.error("this action requires --yes --writers-stopped --legacy-acl-fenced --all-ingress-drained")
            if args.command == "restore":
                result = restore_snapshot(target, args.input, external_fence=True)
            elif args.command == "activate-restored":
                result = activate_restored(target, args.actor, args.reason, external_fence=True)
            else:
                redis = create_ephemeral_redis_client(config)
                if args.command == "freeze":
                    result = freeze_source(redis, args.actor, external_fence=True)
                elif args.command == "import":
                    result = import_source(redis, target, external_fence=True)
                elif args.command == "cutover":
                    result = cutover(redis, target, args.actor, external_fence=True)
                else:
                    result = abort_migration(redis, target, external_fence=True)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (StateError, OSError, ValueError) as exc:
        print("state operation failed: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
