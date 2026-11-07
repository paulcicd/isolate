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
    replay = commands.add_parser("import")
    replay.add_argument("path", help="JSONL evidence file; event_id deduplication makes imports repeatable")
    args = parser.parse_args()
    index = AuditIndex(load_config().get("audit_index", {}))
    if args.action == "init":
        print(json.dumps(index.initialize()))
    else:
        print(json.dumps({"imported": index.import_jsonl(args.path)}))


if __name__ == "__main__":
    main()
