"""Validation for optional gateway, API, identity and SQL services."""

import os
from urllib.parse import urlsplit


def validate_runtime_config(config, check_paths=False):
    errors, warnings = [], []
    sections = {}
    for name in ("api", "gateway", "credentials", "identity_security", "protocols", "audit_index", "cluster"):
        value = config.get(name, {})
        if not isinstance(value, dict):
            errors.append(name + " must be an object")
            value = {}
        sections[name] = value
        if "enabled" in value and not isinstance(value["enabled"], bool):
            errors.append(name + ".enabled must be a boolean")
    api, gateway = sections["api"], sections["gateway"]
    identity = sections["identity_security"]
    keycloak = config.get("keycloak") or {}
    if isinstance(keycloak, dict):
        if keycloak.get("token_kind", "id_token") not in ("id_token", "access_token"):
            errors.append("keycloak.token_kind must be id_token or access_token")
    else:
        keycloak = {}
    enabled = bool(api.get("enabled") or gateway.get("enabled") or sections["protocols"].get("enabled"))
    if enabled:
        issuer = urlsplit(str(keycloak.get("issuer") or ""))
        if (issuer.scheme != "https" or not issuer.hostname or issuer.username or issuer.password
                or issuer.query or issuer.fragment or not keycloak.get("verify_tokens", True) or not keycloak.get("tls_verify", True)):
            errors.append("API/gateway require a verified HTTPS Keycloak issuer")
        if not (keycloak.get("expected_audience") or keycloak.get("client_id")):
            errors.append("API/gateway require a Keycloak audience")
    if gateway.get("enabled") and not api.get("enabled"):
        errors.append("gateway requires api.enabled for authenticated ticket issuance")
    if sections["protocols"].get("enabled") and not gateway.get("enabled"):
        errors.append("protocol adapters require an enabled gateway")
    def integer(section, key, default, minimum, maximum):
        value = sections[section].get(key, default)
        try:
            valid = not isinstance(value, bool) and minimum <= int(value) <= maximum
        except (TypeError, ValueError):
            valid = False
        if not valid:
            errors.append("{}.{} must be between {} and {}".format(section, key, minimum, maximum))
    for section, key, default, low, high in (("api", "ticket_ttl", 60, 10, 120),
            ("gateway", "ssh_port", 2222, 1, 65535), ("gateway", "web_port", 8092, 1, 65535),
            ("gateway", "max_connections", 100, 1, 4096), ("gateway", "recheck_interval", 2, 1, 10),
            ("cluster", "lease_ttl", 30, 10, 300), ("cluster", "node_ttl", 30, 10, 300)):
        integer(section, key, default, low, high)
    if gateway.get("enabled"):
        try:
            if int(sections["cluster"].get("lease_ttl", 30)) <= int(gateway.get("recheck_interval", 2)) + 5:
                errors.append("cluster.lease_ttl must exceed gateway.recheck_interval by more than 5 seconds")
        except (TypeError, ValueError):
            pass
        for key in ("host_key_file", "known_hosts"):
            path = gateway.get(key)
            if not path or not os.path.isabs(str(path)):
                errors.append("gateway.{} must be an absolute path".format(key))
            elif check_paths and not os.path.isfile(path):
                errors.append("gateway.{} is missing".format(key))
        origins = gateway.get("allowed_origins", [])
        if not isinstance(origins, list):
            errors.append("gateway.allowed_origins must be a list")
        else:
            for value in origins:
                parsed = urlsplit(str(value))
                if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
                        or parsed.password or parsed.path or parsed.query or parsed.fragment or "*" in str(value)):
                    errors.append("gateway.allowed_origins must contain exact origins")
    for key in ("step_up", "backchannel_logout", "introspection"):
        if not isinstance(identity.get(key, {}), dict):
            errors.append("identity_security.{} must be an object".format(key))
    introspection = identity.get("introspection", {})
    if isinstance(introspection, dict) and introspection.get("enabled"):
        if keycloak.get("token_kind", "id_token") != "access_token" or not keycloak.get("client_secret"):
            errors.append("online introspection requires access_token and a confidential Keycloak client")
    step = identity.get("step_up", {})
    if isinstance(step, dict) and step.get("enabled"):
        if not (step.get("acr_values") or step.get("required_amr")):
            errors.append("step-up requires explicit accepted acr_values or required_amr")
    index = sections["audit_index"]
    if index.get("enabled"):
        if index.get("driver", "sqlite") not in ("sqlite", "postgresql"):
            errors.append("audit_index.driver must be sqlite or postgresql")
        key = "dsn_file" if index.get("driver") == "postgresql" else "path"
        if not index.get(key) or not os.path.isabs(str(index.get(key))):
            errors.append("audit_index.{} must be an absolute path".format(key))
    targets = sections["protocols"].get("targets", {})
    if not isinstance(targets, dict):
        errors.append("protocols.targets must be an object")
    elif sections["protocols"].get("enabled"):
        for identifier, target in targets.items():
            if not str(identifier).isdigit() or not isinstance(target, dict):
                errors.append("protocol target entries must map numeric host IDs to objects")
                continue
            from isolate_protocols import ProtocolError, resolve_target
            try:
                # Validate independently of inventory without allowing a DNS
                # lookup to choose a target. Runtime pins the real IP again.
                parsed = urlsplit(str(target.get("upstream") or ""))
                import ipaddress
                try:
                    address = str(ipaddress.ip_address(parsed.hostname))
                except ValueError:
                    address = "192.0.2.1"
                resolve_target(config, {"server_id": str(identifier), "project_name": target.get("project"), "server_ip": address}, target.get("protocol"))
            except (ProtocolError, ValueError, TypeError):
                errors.append("protocol target {} is invalid".format(identifier))
    return {"errors": errors, "warnings": warnings}
