#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small, non-sensitive build metadata surface for operators."""

import datetime
import os
import platform
import subprocess
import time


def _git_revision(data_root):
    try:
        result = subprocess.run(
            ["git", "-C", data_root, "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    revision = (result.stdout or "").strip()
    return revision if result.returncode == 0 and revision else None


def _iso_timestamp(value):
    if value in (None, ""):
        return None
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        return str(value)
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def get_build_info(config=None, started_at=None):
    config = config or {}
    build = config.get("build", {}) or {}
    data_root = config.get("data_root") or "/opt/auth"
    revision = os.getenv("ISOLATE_BUILD_SHA") or build.get("revision") or _git_revision(data_root)
    built_at = os.getenv("ISOLATE_BUILD_DATE") or build.get("built_at") or os.getenv("SOURCE_DATE_EPOCH")
    result = {
        "product": "Isolate Bastion Platform",
        "version": os.getenv("ISOLATE_VERSION") or build.get("version") or "2.1.0-dev",
        "revision": revision,
        "revision_short": revision[:12] if revision else "unknown",
        "built_at": _iso_timestamp(built_at) or "source checkout",
        "schema_version": config.get("schema_version"),
        "python": platform.python_version(),
    }
    if started_at:
        result["started_at"] = _iso_timestamp(started_at)
        result["uptime_seconds"] = max(0, int(time.time() - float(started_at)))
    return result
