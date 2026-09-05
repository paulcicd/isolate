#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Typed, built-in diagnostic and operational runbooks."""

import copy
import hashlib
import json
import re
import shlex


class RunbookError(ValueError):
    pass


SERVICE_PATTERN = r"^[A-Za-z0-9@_.:-]{1,128}$"


BUILTIN_RUNBOOKS = {
    "uptime": {
        "title": "System uptime and load",
        "class": "read_only",
        "description": "Show uptime and load averages.",
        "commands": [["/usr/bin/uptime"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "disk-usage": {
        "title": "Filesystem usage",
        "class": "read_only",
        "description": "Show filesystem type and human-readable space usage.",
        "commands": [["/usr/bin/df", "-hT"]],
        "parameters": {},
        "default_timeout": 60,
    },
    "inode-usage": {
        "title": "Filesystem inode usage",
        "class": "read_only",
        "description": "Show inode consumption for mounted filesystems.",
        "commands": [["/usr/bin/df", "-ih"]],
        "parameters": {},
        "default_timeout": 60,
    },
    "memory": {
        "title": "Memory usage",
        "class": "read_only",
        "description": "Show memory and swap usage in MiB.",
        "commands": [["/usr/bin/free", "-m"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "cpu-processes": {
        "title": "Top CPU processes",
        "class": "read_only",
        "description": "Show a bounded snapshot of processes sorted by CPU usage.",
        "commands": [["/usr/bin/ps", "-eo", "pid,ppid,user,stat,%cpu,%mem,etime,comm", "--sort=-%cpu"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "memory-processes": {
        "title": "Top memory processes",
        "class": "read_only",
        "description": "Show a bounded snapshot of processes sorted by memory usage.",
        "commands": [["/usr/bin/ps", "-eo", "pid,ppid,user,stat,%cpu,%mem,rss,etime,comm", "--sort=-%mem"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "top-snapshot": {
        "title": "Top snapshot",
        "class": "read_only",
        "description": "Capture one non-interactive top snapshot.",
        "commands": [["/usr/bin/top", "-b", "-n", "1", "-w", "160"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "atop-snapshot": {
        "title": "Atop snapshot",
        "class": "read_only",
        "description": "Capture one parseable CPU, memory, disk, and network atop sample.",
        "commands": [["/usr/bin/atop", "-P", "CPU,MEM,DSK,NET", "1", "1"]],
        "parameters": {},
        "default_timeout": 45,
    },
    "service-status": {
        "title": "Service status",
        "class": "read_only",
        "description": "Show full systemd status for one validated unit.",
        "commands": [["/usr/bin/systemctl", "--no-pager", "--full", "status", "--", "{service}"]],
        "parameters": {"service": {"type": "string", "pattern": SERVICE_PATTERN, "required": True}},
        "default_timeout": 30,
    },
    "service-active": {
        "title": "Service active state",
        "class": "read_only",
        "description": "Check whether one validated systemd unit is active.",
        "commands": [["/usr/bin/systemctl", "is-active", "--", "{service}"]],
        "parameters": {"service": {"type": "string", "pattern": SERVICE_PATTERN, "required": True}},
        "default_timeout": 30,
    },
    "journal-tail": {
        "title": "Service journal tail",
        "class": "read_only",
        "description": "Show the latest journal entries for one validated systemd unit.",
        "commands": [["/usr/bin/journalctl", "--no-pager", "-u", "{service}", "-n", "{lines}"]],
        "parameters": {
            "service": {"type": "string", "pattern": SERVICE_PATTERN, "required": True},
            "lines": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200},
        },
        "default_timeout": 60,
    },
    "failed-services": {
        "title": "Failed services",
        "class": "read_only",
        "description": "List failed systemd units.",
        "commands": [["/usr/bin/systemctl", "--no-pager", "--failed"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "listening-sockets": {
        "title": "Listening sockets",
        "class": "read_only",
        "description": "Show listening TCP and UDP sockets and owning processes when permitted.",
        "commands": [["/usr/bin/ss", "-lntup"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "network-addresses": {
        "title": "Network addresses",
        "class": "read_only",
        "description": "Show a compact list of network interfaces and addresses.",
        "commands": [["/usr/sbin/ip", "-brief", "address"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "network-routes": {
        "title": "Network routes",
        "class": "read_only",
        "description": "Show the current network routing table.",
        "commands": [["/usr/sbin/ip", "route", "show"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "service-restart": {
        "title": "Restart service",
        "class": "operational",
        "description": "Restart one validated systemd unit.",
        "commands": [["/usr/bin/systemctl", "restart", "--", "{service}"]],
        "parameters": {"service": {"type": "string", "pattern": SERVICE_PATTERN, "required": True}},
        "default_timeout": 120,
    },
    "dns-cache-flush": {
        "title": "Flush system DNS cache",
        "class": "operational",
        "description": "Flush the systemd-resolved DNS cache.",
        "commands": [["/usr/bin/resolvectl", "flush-caches"]],
        "parameters": {},
        "default_timeout": 30,
    },
    "deploy-diagnostics": {
        "title": "Deployment diagnostics",
        "class": "operational",
        "description": "Collect bounded service, journal, disk, and memory diagnostics after a deployment.",
        "commands": [
            ["/usr/bin/systemctl", "--no-pager", "--full", "status", "--", "{service}"],
            ["/usr/bin/journalctl", "--no-pager", "-u", "{service}", "-n", "{lines}"],
            ["/usr/bin/df", "-hT"],
            ["/usr/bin/free", "-m"],
        ],
        "parameters": {
            "service": {"type": "string", "pattern": SERVICE_PATTERN, "required": True},
            "lines": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200},
        },
        "default_timeout": 120,
    },
}


def _definition_hash(runbook):
    payload = json.dumps(runbook, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def list_runbooks(config, classes=None):
    disabled = set((config.get("runbooks", {}) or {}).get("disabled") or [])
    selected_classes = set(classes or ("read_only", "operational"))
    rows = []
    for runbook_id, source in BUILTIN_RUNBOOKS.items():
        if runbook_id in disabled or source["class"] not in selected_classes:
            continue
        record = copy.deepcopy(source)
        record.update({"id": runbook_id, "definition_sha256": _definition_hash(source)})
        rows.append(record)
    rows.sort(key=lambda item: (item["class"], item["id"]))
    return rows


def get_runbook(config, runbook_id):
    for record in list_runbooks(config):
        if record["id"] == runbook_id:
            return record
    return None


def _normalize_parameter(name, value, specification):
    value_type = specification.get("type")
    if value_type == "integer":
        try:
            normalized = int(value)
        except (TypeError, ValueError) as exc:
            raise RunbookError("parameter {} must be an integer".format(name)) from exc
        if normalized < int(specification.get("minimum", normalized)):
            raise RunbookError("parameter {} is below the minimum".format(name))
        if normalized > int(specification.get("maximum", normalized)):
            raise RunbookError("parameter {} exceeds the maximum".format(name))
        return str(normalized)
    normalized = str(value or "").strip()
    if not normalized:
        raise RunbookError("parameter {} is required".format(name))
    pattern = specification.get("pattern")
    if pattern and re.fullmatch(pattern, normalized) is None:
        raise RunbookError("parameter {} has an invalid value".format(name))
    return normalized


def render_runbook(config, runbook_id, parameters=None):
    runbook = get_runbook(config, str(runbook_id or "").strip())
    if runbook is None:
        raise RunbookError("runbook is unknown or disabled")
    supplied = parameters or {}
    if not isinstance(supplied, dict):
        raise RunbookError("parameters must be an object")
    definitions = runbook.get("parameters") or {}
    unknown = sorted(set(supplied) - set(definitions))
    if unknown:
        raise RunbookError("unknown runbook parameter: {}".format(unknown[0]))
    normalized = {}
    for name, specification in definitions.items():
        if name in supplied:
            value = supplied[name]
        elif "default" in specification:
            value = specification["default"]
        elif specification.get("required"):
            raise RunbookError("parameter {} is required".format(name))
        else:
            continue
        normalized[name] = _normalize_parameter(name, value, specification)

    rendered_commands = []
    for command in runbook.get("commands") or []:
        if not command or not str(command[0]).startswith("/"):
            raise RunbookError("runbook command must use an absolute executable path")
        argv = []
        for token in command:
            rendered = str(token)
            for name, value in normalized.items():
                rendered = rendered.replace("{{{}}}".format(name), value)
            if re.search(r"\{[A-Za-z0-9_]+\}", rendered):
                raise RunbookError("runbook command contains an unresolved parameter")
            argv.append(rendered)
        rendered_commands.append(" ".join(shlex.quote(token) for token in argv))
    if not rendered_commands:
        raise RunbookError("runbook does not contain commands")
    return {
        "runbook": runbook,
        "parameters": normalized,
        "command": "; ".join(rendered_commands),
        "policy_action": "runbook" if runbook["class"] == "read_only" else "operate",
    }
