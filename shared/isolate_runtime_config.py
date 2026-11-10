"""Validation for optional gateway, API, identity and SQL services."""

import os
from urllib.parse import urlsplit


def validate_runtime_config(config, check_paths=False):
    errors, warnings = [], []
    from isolate_config import canonical_identity_config
    try:
        config = canonical_identity_config(config)
    except Exception:
        return {"errors": ["identity provider configuration is invalid"], "warnings": []}
    provider = config.get("keycloak", {})
    if provider.get("provider") == "oidc":
        try:
            from isolate_oidc import validate_endpoint, read_client_secret
            validate_endpoint(provider, provider.get("issuer"))
            if provider.get("verify_tokens", True) is not True or provider.get("tls_verify", True) is not True:
                raise ValueError("verification is required")
            if not provider.get("client_id") or not (provider.get("expected_audience") or provider.get("client_id")):
                raise ValueError("client and audience are required")
            if check_paths:
                read_client_secret(provider)
        except Exception:
            errors.append("generic OIDC requires a trusted HTTPS issuer, verified tokens, client/audience and safe credential files")
    sections = {}
    for name in ("api", "gateway", "credentials", "identity_security", "protocols", "audit_index", "cluster", "state", "recordings", "admission", "web_apps", "governance", "campaigns", "runbooks", "command_execution"):
        value = config.get(name, {})
        if not isinstance(value, dict):
            errors.append(name + " must be an object")
            value = {}
        sections[name] = value
        if "enabled" in value and not isinstance(value["enabled"], bool):
            errors.append(name + ".enabled must be a boolean")
    api, gateway = sections["api"], sections["gateway"]
    for section, field, default, low, high in (('governance', 'review_interval_days', 90, 1, 365),
            ('campaigns', 'max_hosts', 100, 1, 1000), ('campaigns', 'max_batch_size', 50, 1, 50)):
        value = sections[section].get(field, default)
        if type(value) is not int or not low <= value <= high:
            errors.append(section + '.' + field + ' is outside the supported range')
    if sections['campaigns'].get('enabled'):
        delegation = sections['identity_security'].get('delegation', {})
        if not (api.get('enabled') and sections['runbooks'].get('enabled')
                and sections['command_execution'].get('enabled')
                and isinstance(delegation, dict) and delegation.get('enabled')):
            errors.append('campaigns require the API, runbooks, command execution and bounded live delegation')
    applications = sections["web_apps"]
    if applications.get("enabled") and not (api.get("enabled") and gateway.get("enabled") and sections["protocols"].get("enabled")):
        errors.append("web_apps requires enabled API, gateway and protocol resources")
    for key, default, low, high in (("launch_ttl", 30, 5, 60), ("session_ttl_seconds", 3600, 30, 28800),
                                  ("idle_timeout_seconds", 900, 10, 28800), ("max_sessions", 100, 1, 4096),
                                  ("max_requests_per_session", 16, 1, 128)):
        value = applications.get(key, default)
        if type(value) is not int or not low <= value <= high:
            errors.append("web_apps." + key + " is outside the supported range")
    features = gateway.get("ssh_features", {})
    if not isinstance(features, dict):
        errors.append("gateway.ssh_features must be an object")
        features = {}
    for name in ("multiple_channels", "sftp", "scp", "forwarding", "proxy_hops"):
        if name in features and not isinstance(features[name], bool):
            errors.append("gateway.ssh_features." + name + " must be a boolean")
    for name, low, high, default in (("max_channels", 1, 32, 8), ("max_proxy_hops", 1, 5, 3)):
        if type(features.get(name, default)) is not int or not low <= features.get(name, default) <= high:
            errors.append("gateway.ssh_features." + name + " is outside the supported range")
    forwards = gateway.get("forwarding_targets", {})
    if not isinstance(forwards, dict):
        errors.append("gateway.forwarding_targets must be an object")
    else:
        import ipaddress
        import re
        for host_id, destinations in forwards.items():
            if not str(host_id).isdigit() or not isinstance(destinations, list) or len(destinations) > 100:
                errors.append("forwarding targets require inventory IDs and bounded destination lists")
                continue
            for destination in destinations:
                try:
                    if (not isinstance(destination, dict) or set(destination) != {"host", "port", "address"}
                            or not isinstance(destination["host"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", destination["host"])
                            or type(destination["port"]) is not int or not 1 <= destination["port"] <= 65535):
                        raise ValueError("invalid destination")
                    ipaddress.ip_address(destination["address"])
                except (ValueError, KeyError, TypeError):
                    errors.append("forwarding destinations require an exact host, port and pinned IP address")
    browser_auth = gateway.get("browser_auth", {})
    if not isinstance(browser_auth, dict):
        errors.append("gateway.browser_auth must be an object")
    elif browser_auth.get("enabled"):
        parsed = urlsplit(str(config.get("dashboard", {}).get("public_url") or ""))
        if parsed.scheme != "https" or not parsed.hostname or not api.get("enabled") or not gateway.get("enabled"):
            errors.append("browser SSH sign-in requires API, gateway and a public HTTPS dashboard")
        timeout = browser_auth.get("timeout_seconds", 120)
        if type(timeout) is not int or not 30 <= timeout <= 300:
            errors.append("browser SSH sign-in timeout must be between 30 and 300 seconds")
    identity = sections["identity_security"]
    state = sections["state"]
    backend = state.get("backend", "redis")
    if backend not in ("redis", "postgresql", "sqlite"):
        errors.append("state.backend must be redis, postgresql, or sqlite")
    if backend in ("postgresql", "sqlite"):
        if state.get("require_tls", True) is False:
            warnings.append("state.require_tls is disabled; use only an explicitly isolated test network")
        name = "dsn_file" if backend == "postgresql" else "sqlite_path"
        path = state.get(name)
        if not path or not os.path.isabs(str(path)):
            errors.append("state.{} must be an absolute path".format(name))
        elif check_paths and backend == "postgresql":
            try:
                from isolate_state import _protected_dsn
                _protected_dsn(path)
            except Exception:
                errors.append("state.dsn_file is missing or has unsafe ownership/permissions")
        if backend == "sqlite":
            warnings.append("SQLite state is intended for development or a single installation, not a multi-node cluster")
    for name in ("membership", "delegation", "workloads"):
        if not isinstance(identity.get(name, {}), dict):
            errors.append("identity_security.{} must be an object".format(name))
    membership = identity.get("membership", {})
    if isinstance(membership, dict) and membership.get("enabled"):
        if config.get("keycloak", {}).get("provider") == "oidc":
            errors.append("Keycloak Admin membership is unavailable for a generic OIDC provider; disable it or use the Keycloak adapter")
        if membership.get("source", "keycloak-admin") != "keycloak-admin":
            errors.append("authoritative membership requires the Keycloak Admin source")
        if not membership.get("token_file") and not (membership.get("client_id") and membership.get("client_secret_file")):
            errors.append("membership requires token_file or a client_id and protected client_secret_file")
    recording = sections["recordings"]
    if recording.get("enabled"):
        if recording.get("backend", "s3") != "s3" or not recording.get("bucket"):
            errors.append("shared recordings require an S3 bucket")
        if backend == "redis":
            errors.append("shared recordings require authoritative SQL state for publication pointers")
        for name in ("capture_path", "outbox_path", "cache_path", "signing_key_file"):
            if not recording.get(name) or not os.path.isabs(str(recording[name])):
                errors.append("recordings.{} must be an absolute path".format(name))
        endpoint = urlsplit(str(recording.get("endpoint_url") or "https://s3.amazonaws.com"))
        if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            errors.append("recordings.endpoint_url must use verified HTTPS")
        if check_paths:
            try:
                from isolate_recordings import RecordingArchive
                RecordingArchive(config)
            except Exception:
                errors.append("recordings private directories or signing key are unavailable or unsafe")
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
        if keycloak.get("token_kind", "id_token") != "access_token" or not (keycloak.get("client_secret") or keycloak.get("client_secret_file")):
            errors.append("online introspection requires access_token and a confidential OIDC client")
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
                resolved = resolve_target(config, {"server_id": str(identifier), "project_name": target.get("project"), "server_ip": address}, target.get("protocol"))
                if check_paths and (target.get("database_proxy") or {}).get("enabled"):
                    from isolate_database_proxy import validate_database_target
                    validate_database_target(resolved, check_paths=True)
                if check_paths and (target.get("kubernetes") or {}).get("enabled"):
                    from isolate_credentials import _read_file
                    _read_file(target.get("bearer_token_file"), secret=True, maximum=65536)
                    for name in ("ca_file", "client_cert_file", "client_key_file"):
                        if target.get(name):
                            _read_file(target[name], secret=name == "client_key_file")
            except (ProtocolError, ValueError, TypeError, OSError):
                errors.append("protocol target {} is invalid".format(identifier))
    return {"errors": errors, "warnings": warnings}
