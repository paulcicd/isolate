#!/usr/bin/env python3
"""Refresh explicitly selected hosts; run as an optional systemd timer."""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))

from isolate_config import load_config
from isolate_inventory import get_host
from isolate_redis import create_redis_client
from isolate_service_discovery import discover_services, save_discovery
from isolate_ssh import SSHArgumentError


def main():
    config = load_config()
    options = config.get("service_discovery", {}) or {}
    if not options.get("enabled", False):
        print("Service discovery is disabled")
        return 0
    ids = options.get("host_ids") or []
    if not isinstance(ids, list) or not ids or not options.get("remote_user"):
        raise ValueError("service_discovery requires remote_user and a nonempty host_ids list")
    redis = create_redis_client(config)
    failed = False
    for host_id in ids:
        host = get_host(redis, host_id)
        if host is None:
            print("Host {}: missing".format(host_id))
            failed = True
            continue
        proxy = None
        if host.get("proxy_id"):
            proxy_host = get_host(redis, host["proxy_id"])
            if not proxy_host:
                print("Host {}: proxy missing".format(host_id))
                failed = True
                continue
            proxy = {"host": proxy_host["server_ip"], "port": proxy_host.get("server_port") or 22, "user": options["remote_user"]}
        try:
            result = discover_services(host, config, proxy=proxy)
        except (SSHArgumentError, ValueError) as exc:
            result = {"host_id": str(host_id), "ok": False, "error": str(exc)}
        save_discovery(redis, result)
        print("Host {}: {}".format(host_id, "ok" if result["ok"] else result["error"]))
        failed = failed or not result["ok"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
