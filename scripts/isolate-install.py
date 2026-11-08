#!/usr/bin/env python3
"""Stage, verify and select Isolate code without restoring application state."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from isolate_install import InstallError, activate_release, plan_release, rollback_release, stage_release, status, verify_release


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="absolute dedicated installation directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    for name in ("plan", "stage", "verify", "activate", "rollback"):
        command = commands.add_parser(name)
        command.add_argument("--version", required=True)
        if name in ("plan", "stage"):
            command.add_argument("--source", required=True)
        if name != "verify":
            command.add_argument("--config", required=True)
            command.add_argument("--service-user", default="auth")
        if name == "stage":
            command.add_argument("--expected-source-sha256", required=True)
        if name in ("verify", "activate", "rollback"):
            command.add_argument("--expected-release-sha256", required=True)
        if name in ("activate", "rollback"):
            command.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            value = status(args.root)
        elif args.command == "plan":
            value = plan_release(args.root, args.source, args.version, args.config, args.service_user)
            value.pop("files")
        elif args.command == "stage":
            value = stage_release(args.root, args.source, args.version, args.config, args.expected_source_sha256, service_user=args.service_user)
        elif args.command == "verify":
            manifest = verify_release(args.root, args.version, args.expected_release_sha256)
            value = {"verified": True, "version": manifest["version"], "source_sha256": manifest["source_sha256"]}
        else:
            if not args.yes:
                parser.error("code selection requires --yes after reviewing checksums and preflight")
            operation = rollback_release if args.command == "rollback" else activate_release
            value = operation(args.root, args.version, args.config, args.expected_release_sha256, args.service_user)
        print(json.dumps(value, sort_keys=True, indent=2))
        return 0
    except (InstallError, OSError, ValueError) as exc:
        print("release operation failed: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
