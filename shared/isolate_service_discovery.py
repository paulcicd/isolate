"""Opt-in, read-only discovery of running systemd services over SSH."""

import json
import re
import subprocess
import time

from isolate_ssh import build_ssh_argv


REMOTE_COMMAND = "LC_ALL=C systemctl list-units --type=service --state=running --plain --no-legend --no-pager"


def discover_services(host, config, proxy=None, runner=None):
    options = config.get("service_discovery", {}) or {}
    user = options.get("remote_user")
    if not user:
        raise ValueError("service_discovery.remote_user is required")
    timeout = max(1, min(int(options.get("timeout", 10)), 60))
    ssh_config = dict(config.get("ssh", {}), allocate_tty=False)
    argv = build_ssh_argv(ssh_config, {
        "hostname": host["server_ip"], "port": host.get("server_port") or 22, "user": user,
    }, proxy=proxy, remote_command=REMOTE_COMMAND)
    argv[1:1] = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout={}".format(timeout), "-o", "RequestTTY=no"]
    record = {"host_id": str(host["server_id"]), "attempted_at": int(time.time()), "ok": False, "source": "systemd"}
    try:
        result = (runner or subprocess.run)(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, timeout=timeout, check=False)
        if result.returncode:
            # Do not persist remote stderr, which may contain sensitive banner text.
            raise ValueError("service discovery SSH exit code {}".format(result.returncode))
        output = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
        if len(output) > 1024 * 1024:
            raise ValueError("service discovery output is too large")
        services = set()
        for line in output.splitlines():
            if not line.strip():
                continue
            columns = line.split()
            if len(columns) < 4 or not re.fullmatch(r"[A-Za-z0-9_.@:\\-]+\.service", columns[0]) or columns[2:4] != ["active", "running"]:
                raise ValueError("unexpected systemctl service output")
            services.add(columns[0])
        record.update(ok=True, services=sorted(services), checked_at=record["attempted_at"])
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError) as exc:
        record["error"] = str(exc)
    return record


def get_discovery(redis, host_id):
    raw = redis.get("host_services_{}".format(host_id))
    return json.loads(raw) if raw else None


def save_discovery(redis, record):
    """Retain the last successful snapshot on failures; never alter manual inventory."""
    previous = get_discovery(redis, record["host_id"]) or {}
    if not record["ok"]:
        record = dict(previous, **record)
    redis.set("host_services_{}".format(record["host_id"]), json.dumps(record, sort_keys=True))
    return record


def service_display(host, snapshot):
    manual = str(host.get("server_services") or "")
    if not snapshot or "services" not in snapshot:
        return manual
    detected = ", ".join(snapshot["services"]) or "none"
    checked = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(snapshot.get("checked_at") or 0))
    label = "auto/systemd, {}".format(checked)
    if not snapshot.get("ok"):
        label += ", latest scan failed"
    return "{}{}{}: {}".format(manual, "; " if manual else "", label, detected)
