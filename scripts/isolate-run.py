#!/usr/bin/env python3
"""Resolve one selected release before exec so live workers keep immutable paths."""
import argparse
import json
import os
from pathlib import Path
import re
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("component", choices=("dashboard", "gateway", "jobs", "recordings"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root)
    if not root.is_absolute() or not Path(args.config).is_absolute():
        parser.error("installation root and config must be absolute")
    selection = root / ("current/selection.json" if os.name == "posix" else "current.json")
    value = json.loads(selection.read_text(encoding="utf-8"))
    version = value.get("version", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]{0,63})?", version):
        parser.error("invalid selected release")
    release = (root / "releases" / version).resolve(strict=True)
    if release.parent != (root / "releases").resolve(strict=True):
        parser.error("selected release is outside installation root")
    python = release / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    command = [str(python), "-I", "-B", str(release / "scripts/isolate-service.py"), args.component, "--config", args.config]
    if args.check:
        command.append("--check")
    os.execv(str(python), command)


if __name__ == "__main__":
    main()
