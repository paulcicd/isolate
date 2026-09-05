#!/usr/bin/env python3
"""Run queued Isolate command and runbook jobs."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))

from isolate_config import load_config
from isolate_jobs import run_worker
from isolate_redis import create_redis_client


def main():
    config = load_config()
    commands_enabled = config.get("command_execution", {}).get("enabled", False)
    runbooks_enabled = config.get("runbooks", {}).get("enabled", False)
    if not commands_enabled and not runbooks_enabled:
        raise SystemExit("command_execution.enabled and runbooks.enabled are both false")
    run_worker(config, create_redis_client(config), once="--once" in sys.argv[1:])


if __name__ == "__main__":
    main()
