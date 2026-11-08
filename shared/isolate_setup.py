"""Operator setup and redacted diagnostics, independent of a particular IdP."""
import json
import os
import secrets
import stat
from pathlib import Path
from urllib.parse import urlsplit

from isolate_identity import IdentityError


def installation_config(*, provider, issuer, client_id, public_url, data_root, dsn_file,
                        redis_host, redis_ca, redis_password_file=None, client_secret_file=None,
                        audience=None, admin_group=None):
    from isolate_oidc import validate_endpoint
    if provider not in ("keycloak", "oidc"):
        raise ValueError("provider must be keycloak or oidc")
    validate_endpoint({"issuer": issuer}, issuer)
    parsed = urlsplit(public_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("public_url must be an HTTPS origin")
    if not isinstance(client_id, str) or not client_id.strip() or len(client_id) > 256:
        raise ValueError("an OIDC client ID is required")
    for name, value in (("data_root", data_root), ("dsn_file", dsn_file), ("redis_ca", redis_ca),
                        ("redis_password_file", redis_password_file), ("client_secret_file", client_secret_file)):
        if value is not None and not os.path.isabs(value):
            raise ValueError(name + " must be an absolute path")
    if not data_root or not dsn_file or not redis_ca or not redis_host:
        raise ValueError("private data root, SQL DSN file, Redis host and Redis CA are required")
    root = Path(data_root)
    selected = {"provider": provider, "issuer": issuer, "client_id": client_id,
        "expected_audience": audience or client_id, "client_secret_file": client_secret_file,
        "scopes": ["openid", "profile", "email"], "verify_tokens": True, "tls_verify": True,
        "token_kind": "id_token", "jwks_cache_path": str(root / "cache" / "oidc-jwks.json")}
    result = {"schema_version": 2, "data_root": data_root,
        "state": {"backend": "postgresql", "require_tls": True, "dsn_file": dsn_file},
        "redis": {"host": redis_host, "ssl": True, "ssl_check_hostname": True,
                  "ssl_ca_certs": redis_ca, "password_file": redis_password_file},
        "api": {"enabled": True},
        "dashboard": {"enabled": True, "listen_host": "0.0.0.0", "public_url": public_url.rstrip("/"),
            "secret_key_file": str(root / "keys" / "dashboard_secret"), "admin_groups": [admin_group] if admin_group else []},
        "ssh": {"config_path": str(root / "configs" / "defaults.conf"), "require_known_hosts": True},
        "credentials": {"known_hosts": str(root / "known_hosts")},
        "gateway": {"enabled": False, "host_key_file": str(root / "keys" / "gateway_ed25519"),
                    "known_hosts": str(root / "known_hosts")},
        "logging": {"base_path": str(root / "logs"), "fail_closed": True,
            "integrity": {"enabled": True, "key_file": str(root / "keys" / "audit_hmac.key")}},
        "command_execution": {"signing_key_file": str(root / "keys" / "jobs_hmac.key")},
        "recordings": {"capture_path": str(root / "spool" / "evidence"),
            "outbox_path": str(root / "spool" / "recordings"), "cache_path": str(root / "cache" / "recordings"),
            "signing_key_file": str(root / "keys" / "recordings_hmac.key")}}
    result[provider] = dict(selected, enabled=True) if provider == "oidc" else selected
    return result


def write_installation(path, config, *, provision_keys=False):
    """Create a new private config; never overwrite an existing config or key."""
    from isolate_oidc import read_client_secret
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        raise ValueError("configuration already exists; inspect and edit it explicitly")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix":
        current = path.parent
        while True:
            info = current.lstat()
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if (current.is_symlink() or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022 and not sticky):
                raise ValueError("configuration ancestors require trusted ownership and no group/world writes")
            if sticky or current.parent == current:
                break
            current = current.parent
    if provision_keys:
        root = Path(config["data_root"])
        for relative in ("keys", "cache", "logs", "spool", "spool/evidence", "spool/recordings", "configs"):
            target = root / relative
            target.mkdir(parents=True, mode=0o700, exist_ok=True)
            if target.is_symlink():
                raise ValueError("runtime directories must not be symlinks")
        keydir = root / "keys"
        # Validate the ancestor chain before creating any secrets.
        from isolate_recordings import capture_root
        capture_root({"recordings": {"capture_path": str(keydir)}})
        for name in ("dashboard_secret", "audit_hmac.key", "jobs_hmac.key", "recordings_hmac.key"):
            key = keydir / name
            if key.exists():
                read_client_secret({"client_secret_file": str(key)})
                continue
            with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="ascii") as output:
                output.write(secrets.token_hex(32) + "\n")
        gateway_key = keydir / "gateway_ed25519"
        if not gateway_key.exists():
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            material = Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
            with os.fdopen(os.open(gateway_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
                output.write(material)
    # The config itself may contain sensitive deployment topology.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as output:
        json.dump(config, output, indent=2, ensure_ascii=False)
        output.write("\n")
    return str(path)


def diagnose(config, *, offline=False, redis_factory=None, discovery=None):
    from isolate_config import canonical_identity_config
    from isolate_health import validate_config, run_health_checks
    from isolate_oidc import identity_provider_config, discover_provider, provider_capabilities, read_client_secret
    from isolate_identity_binding import provider_binding, BINDING_KEY
    config = canonical_identity_config(config)
    provider = identity_provider_config(config)
    validation = validate_config(config, check_paths=True)
    checks = {"configuration": {"ok": validation["valid"], "errors": validation["errors"], "warnings": validation["warnings"]}}
    try:
        read_client_secret(provider)
        checks["client_credentials"] = {"ok": True, "mode": "private_file" if provider.get("client_secret_file") else "confidential" if provider.get("client_secret") else "public"}
    except IdentityError:
        checks["client_credentials"] = {"ok": False, "error": "client secret file is unavailable or unsafe"}
    report = {"provider": provider["provider"], "issuer": provider.get("issuer"),
              "callback_url": str(config.get("dashboard", {}).get("public_url") or "").rstrip("/") + "/auth/callback",
              "checks": checks, "offline": bool(offline)}
    if not offline:
        from isolate_redis import create_redis_client
        factory = redis_factory or create_redis_client
        checks.update(run_health_checks(config, redis_factory=factory)["checks"])
        try:
            metadata = (discovery or discover_provider)(provider)
            caps = provider_capabilities(provider, metadata)
            checks["oidc_discovery"] = {"ok": True, "capabilities": caps}
            if config.get("dashboard", {}).get("enabled") and not (caps["authorization_code"] and caps["pkce_s256"]):
                checks["oidc_discovery"].update(ok=False, error="browser login requires authorization code and PKCE S256")
            for feature, capability in (("introspection", "introspection"), ("backchannel_logout", "backchannel_logout")):
                if config.get("identity_security", {}).get(feature, {}).get("enabled") and not caps[capability]:
                    checks["oidc_" + feature] = {"ok": False, "error": "enabled identity control is not advertised by the configured provider"}
            from isolate_identity import load_jwks
            keys = load_jwks(provider)
            checks["oidc_signing_keys"] = {"ok": bool(keys.get("keys")), "key_count": len(keys.get("keys", []))}
        except Exception:
            checks["oidc_discovery"] = {"ok": False, "error": "verified discovery or signing keys unavailable; check issuer, CA, endpoint origins and network"}
        try:
            store = factory(config)
            raw = store.get(BINDING_KEY)
            actual = json.loads(raw) if raw else {}
            expected = provider_binding(config)
            same = actual.get("fingerprint") == expected["fingerprint"]
            checks["identity_binding"] = {"ok": same or not raw and provider["provider"] == "keycloak",
                "state": "bound" if same else "legacy_pending" if not raw and provider["provider"] == "keycloak" else "operator_binding_required"}
        except Exception:
            checks["identity_binding"] = {"ok": False, "error": "control store binding is unavailable"}
    report["ok"] = all(check.get("ok") for check in checks.values())
    return report
