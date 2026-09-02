#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safely prune expired Isolate session directories; dry-run by default."""

import argparse
import os
import shutil
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "shared"))

from isolate_config import load_config
from isolate_retention import expired_session_dirs


def main():
    config = load_config()
    parser = argparse.ArgumentParser(description="Prune expired Isolate session directories")
    parser.add_argument("--days", type=int, default=int(config.get("logging", {}).get("retention_days", 90)))
    parser.add_argument("--apply", action="store_true", help="delete results; without this flag only print them")
    args = parser.parse_args()
    if args.days < 1:
        parser.error("--days must be greater than zero")
    paths = expired_session_dirs(config["logging"]["base_path"], args.days)
    for path in paths:
        print("{} {}".format("delete" if args.apply else "would-delete", path))
        if args.apply:
            shutil.rmtree(path)
    print("{} session directories {}".format(len(paths), "deleted" if args.apply else "matched"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
