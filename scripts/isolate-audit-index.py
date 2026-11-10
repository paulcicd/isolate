#!/usr/bin/env python3
"""Manage the optional audit index using trusted, service-owned configuration."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "shared"))
from isolate_audit_index import AuditIndex
from isolate_config import load_config


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("init")
    commands.add_parser("publish", help="Retry committed workflow evidence publication without repeating mutations")
    replay = commands.add_parser("import")
    replay.add_argument("path", help="JSONL evidence file; event_id deduplication makes imports repeatable")
    args = parser.parse_args()
    config = load_config()
    index = AuditIndex(config.get("audit_index", {}))
    if args.action == "init":
        print(json.dumps(index.initialize()))
    elif args.action == 'publish':
        from isolate_redis import create_redis_client
        from isolate_workflow_audit import publish_pending
        result = publish_pending(create_redis_client(config), config, limit=1000)
        print(json.dumps(result))
        return 1 if result['failed'] else 0
    else:
        print(json.dumps({"imported": index.import_jsonl(args.path)}))


if __name__ == "__main__":
    raise SystemExit(main())
