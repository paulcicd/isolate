#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safe SSH argv construction for Isolate v2."""

import re
import socket


class SSHArgumentError(Exception):
    pass


SAFE_USER_RE = re.compile(r"^[A-Za-z0-9_,.-]{1,48}$")


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except OSError:
        return False


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except OSError:
        return False


def is_valid_fqdn(hostname):
    hostname = str(hostname).lower()
    if len(hostname) > 255 or not hostname or hostname[0] == "." or hostname[-1] == ".":
        return False
    if hostname.startswith("-"):
        return False
    return re.match(r"^([a-z0-9-.]+)$", hostname) is not None


def validate_host(hostname):
    if is_valid_ipv4_address(hostname) or is_valid_ipv6_address(hostname) or is_valid_fqdn(hostname):
        return hostname
    raise SSHArgumentError("invalid host")


def validate_user(user):
    if user is None:
        return None
    if SAFE_USER_RE.match(str(user)) is None or str(user).startswith("-"):
        raise SSHArgumentError("invalid user")
    return str(user)


def validate_port(port):
    if port is None:
        return None
    port = int(port)
    if port <= 0 or port > 65535:
        raise SSHArgumentError("invalid port")
    return port


def filter_extra_args(extra_args, allowed):
    allowed = set(allowed or [])
    result = []
    for arg in extra_args or []:
        if arg not in allowed:
            raise SSHArgumentError("SSH argument '{}' is not allowed".format(arg))
        result.append(arg)
    return result


def build_ssh_argv(config, host, extra_args=None, proxy=None, remote_command=None):
    ssh = config.get("binary", "/usr/bin/ssh")
    argv = [ssh, "-e", "none", "-F", config.get("config_path", "/opt/auth/configs/defaults.conf")]
    if config.get("allocate_tty", True):
        argv.append("-tt")
    argv.extend(filter_extra_args(extra_args, config.get("allowed_extra_args")))

    proxy = proxy or {}
    if proxy.get("host"):
        proxy_argv = [ssh, "-e", "none", "-F", config.get("config_path", "/opt/auth/configs/defaults.conf")]
        if proxy.get("user"):
            proxy_argv.extend(["-l", validate_user(proxy["user"])])
        if proxy.get("port"):
            proxy_argv.extend(["-p", str(validate_port(proxy["port"]))])
        proxy_argv.extend([validate_host(proxy["host"]), "nc", "%h", "%p"])
        argv.extend(["-o", "ProxyCommand=" + " ".join(proxy_argv)])

    if host.get("debug"):
        argv.append("-v")
    if host.get("user"):
        argv.extend(["-l", validate_user(host["user"])])
    if host.get("port"):
        argv.extend(["-p", str(validate_port(host["port"]))])
    argv.append(validate_host(host["hostname"]))
    if remote_command:
        argv.append(remote_command)
    return argv
