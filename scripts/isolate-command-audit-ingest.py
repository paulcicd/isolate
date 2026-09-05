#!/usr/bin/env python3
"""Restricted SSH forced-command entry point for target command audit hooks."""

import os
import shlex
import subprocess
import sys


ISOLATE_CLI = "/opt/auth/shared/isolate.py"
MAX_ORIGINAL_COMMAND = 16384


def main():
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not original or len(original) > MAX_ORIGINAL_COMMAND:
        print("command audit ingest denied: invalid command", file=sys.stderr)
        return 2
    try:
        argv = shlex.split(original, posix=True)
    except ValueError:
        print("command audit ingest denied: malformed command", file=sys.stderr)
        return 2
    if argv[:3] != ["isolate", "command-log", "append"]:
        print("command audit ingest denied: unsupported command", file=sys.stderr)
        return 2
    completed = subprocess.run(
        [sys.executable, ISOLATE_CLI] + argv[1:],
        stdin=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
