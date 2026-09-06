#!/usr/bin/env python3
"""End-to-end infrastructure smoke checks for the disposable Docker demo."""

import json
import socket
import subprocess
import sys
import urllib.request

import redis


TARGETS = [
    ("172.30.50.11", "support"),
    ("172.30.50.11", "dev"),
    ("172.30.50.13", "dba"),
]


def check(name, callback):
    callback()
    print("[ok] {}".format(name))


def check_redis():
    client = redis.Redis(host="redis", decode_responses=True)
    if not client.ping():
        raise RuntimeError("Redis ping failed")
    hosts = [key for key in client.scan_iter("server_[0-9]*")]
    grants = [key for key in client.scan_iter("grant_[0-9]*")]
    if len(hosts) != 5 or len(grants) != 3:
        raise RuntimeError("expected 5 hosts and 3 grants, got {} and {}".format(len(hosts), len(grants)))
    vip = json.loads(client.get("server_10005"))
    if not vip.get("server_vip"):
        raise RuntimeError("VIP demo host is not marked")


def check_http(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("{} returned {}".format(url, response.status))


def check_port(host, port):
    with socket.create_connection((host, port), timeout=3):
        return


def check_ssh(host, username):
    command = [
        "ssh",
        "-i", "/home/auth/.ssh/id_ed25519",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "{}@{}".format(username, host),
        "whoami",
    ]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    if result.returncode != 0 or result.stdout.strip() != username:
        raise RuntimeError("SSH {}@{} failed: {}".format(username, host, result.stderr.strip()))


def main():
    checks = [
        ("Redis inventory and grants", check_redis),
        ("Keycloak discovery", lambda: check_http("http://localhost:18080/realms/isolate-demo/.well-known/openid-configuration")),
        ("Dashboard health", lambda: check_http("http://localhost:18081/health")),
        ("Bastion SSH", lambda: check_port("127.0.0.1", 22)),
    ]
    checks.extend(
        ("SSH key mapping {}@{}".format(username, host), lambda host=host, username=username: check_ssh(host, username))
        for host, username in TARGETS
    )
    try:
        for name, callback in checks:
            check(name, callback)
    except Exception as exc:
        print("[failed] {}".format(exc), file=sys.stderr)
        return 1
    print("All Isolate Docker demo smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

