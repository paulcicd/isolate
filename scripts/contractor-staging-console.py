#!/usr/bin/python3 -I
"""Restricted SSH entry while contractor realm/access enrollment is pending.

This console intentionally has no subprocess, eval, file access or target
connection capability. Replace the SSH ForceCommand only after enrollment.
"""

import os
import pwd
import sys


STATUS = "Keycloak realm and target access are not configured. Target connections are disabled."


def main():
    username = pwd.getpwuid(os.getuid()).pw_name
    if username not in ("apexdata-1", "apexdata-2"):
        print("Access denied.", file=sys.stderr)
        return 1
    # Reject exec and subsystem requests, including SFTP, instead of executing
    # SSH_ORIGINAL_COMMAND through a shell.
    if os.environ.get("SSH_ORIGINAL_COMMAND"):
        print("Remote commands and file transfer are disabled.", file=sys.stderr)
        return 1
    print("Isolate staging bastion: " + username)
    print(STATUS)
    print("Available commands: status, help, exit")
    while True:
        try:
            print("isolate-staging> ", end="", flush=True)
            line = sys.stdin.readline(1026)
        except (KeyboardInterrupt, EOFError):
            return 0
        if not line:
            return 0
        if len(line) > 1024:
            print("Input too long; connection closed.")
            return 1
        command = line.strip()
        if command == "exit":
            return 0
        if command == "status":
            print(STATUS)
        elif command == "help":
            print("status: enrollment status; help: available commands; exit: disconnect")
        elif command:
            print("Command unavailable. " + STATUS)


if __name__ == "__main__":
    raise SystemExit(main())
