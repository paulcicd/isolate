"""Inventory-bound SSH jump chains and explicitly pinned forwarding targets."""

import ipaddress
import re
import uuid

from isolate_connection_auth import ConnectionDenied, policy_for_host
from isolate_identity_security import assert_identity_active
from isolate_inventory import get_host


def proxy_chain(store, config, identity, target, token):
    chain, seen, current = [], {str(target["server_id"])}, target
    features = config.get("gateway", {}).get("ssh_features", {})
    maximum = max(1, min(5, int(features.get("max_proxy_hops", 3))))
    while current.get("proxy_id"):
        if not features.get("proxy_hops") or not config.get("connection_authorization", {}).get("allow_proxy"):
            raise ConnectionDenied("gateway proxy hops are disabled")
        identifier = str(current["proxy_id"])
        if identifier in seen or len(chain) >= maximum:
            raise ConnectionDenied("SSH proxy chain contains a cycle or exceeds its limit")
        seen.add(identifier)
        host = get_host(store, identifier)
        if host is None:
            raise ConnectionDenied("SSH proxy is missing")
        ipaddress.ip_address(host["server_ip"])
        port = int(host.get("server_port") or 22)
        ports = config.get("connection_authorization", {}).get("allowed_target_ports") or []
        if ports and port not in ports:
            raise ConnectionDenied("proxy port is not permitted")
        decision = policy_for_host(store, config, identity, host)
        if decision.get("sudo_mode") not in ("none", "sudo-i"):
            raise ConnectionDenied("unsupported proxy privilege profile")
        assert_identity_active(store, config, identity, token=token, host=host, decision=decision)
        chain.append({"host": host, "decision": decision, "identity": identity,
            "connection_id": uuid.uuid4().hex})
        current = host
    return list(reversed(chain))


def chain_revision(chain):
    return [{"id": str(hop["host"]["server_id"]), "ip": hop["host"]["server_ip"],
        "port": hop["host"].get("server_port"), "project": hop["host"]["project_name"],
        "proxy": hop["host"].get("proxy_id"), "decision": hop["decision"]} for hop in chain]


def forwarding_destination(config, host_id, destination):
    if not isinstance(destination, dict) or set(destination) != {"host", "port"}:
        raise ConnectionDenied("invalid forwarding destination")
    hostname, port = destination["host"], destination["port"]
    if (not isinstance(hostname, str) or not 1 <= len(hostname) <= 253 or hostname.startswith("-")
            or not re.fullmatch(r"[A-Za-z0-9_.:-]+", hostname) or type(port) is not int or not 1 <= port <= 65535):
        raise ConnectionDenied("invalid forwarding destination")
    for allowed in config.get("gateway", {}).get("forwarding_targets", {}).get(str(host_id), []):
        if allowed.get("host") == hostname and allowed.get("port") == port:
            # Network selection is always a deployment-pinned IP. No client DNS
            # name, DNS rebinding, wildcard destination or upstream config wins.
            address = str(ipaddress.ip_address(allowed["address"]))
            return {"host": address, "port": port}
    raise ConnectionDenied("forwarding destination is not permitted")
