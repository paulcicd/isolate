#!/usr/bin/env python3
"""Run queued Isolate command jobs."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))

from isolate_config import load_config
from isolate_jobs import run_worker
from isolate_redis import create_redis_client


def main():
    config = load_config()
    if not config.get("command_execution", {}).get("enabled", False):
        raise SystemExit("command_execution.enabled is false")
    run_worker(config, create_redis_client(config), once="--once" in sys.argv[1:])


if __name__ == "__main__":
    main()
