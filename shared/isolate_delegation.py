"""Bound, encrypted and short-lived authorization for asynchronous operations.

No refresh token is retained. A worker can act only within the signed token's
lifetime and the configured delegation window. It re-verifies signature, IdP
lifecycle, live membership, current grants and route before and during execution.
Public job records contain only an opaque reference and a bounded deadline.
"""

import base64
import hashlib
import json
import os
import secrets
import stat
import time

from isolate_identity import IdentityError, normalize_claims, verify_jwt_claims
from isolate_identity_security import assert_workload_action, refresh_identity, step_up_required
from isolate_policy import PolicyDenied, resolve_grant


class DelegationDenied(IdentityError):
    pass


def options(config):
    return (config.get("identity_security") or {}).get("delegation") or {}


def lifecycle_required(config, host=None, decision=None):
    security = config.get("identity_security") or {}
    return bool(any((security.get(name) or {}).get("enabled") for name in
                    ("backchannel_logout", "introspection", "membership"))
                or step_up_required(config, host, decision))


def _encryption_key(config):
    path = (config.get("command_execution") or {}).get("signing_key_file")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise DelegationDenied("a protected job signing key is required for delegation")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or os.path.islink(path):
                raise DelegationDenied("unsafe delegation key file")
            if os.name == "posix" and (info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o077):
                raise DelegationDenied("unsafe delegation key permissions")
            material = source.read(65537).strip()
        if len(material) < 32 or len(material) > 65536:
            raise DelegationDenied("delegation key must contain at least 32 bytes")
    except (OSError, TypeError) as exc:
        raise DelegationDenied("delegation key is unavailable") from exc
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"isolate:job-delegation:aes-gcm:v1").derive(material)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _binding(record):
    from isolate_jobs import _signature_payload
    return hashlib.sha256(_signature_payload(record)).hexdigest()


def _epoch(redis, config):
    if (config.get("state") or {}).get("backend", "redis") == "redis":
        return None
    from isolate_recovery import authority_epoch
    return authority_epoch(redis, config)


def _grant(redis, config, identity, host, action):
    from isolate import load_grants, load_project_sets
    from isolate_governance import check_governance_access
    check_governance_access(redis, identity, host.get('project_name'))
    return resolve_grant(identity, project=host.get("project_name"), host=host,
        grants=load_grants(redis), project_sets=load_project_sets(redis),
        defaults={**config.get("policy", {}), **config.get("ssh", {})}, action=action)


def verified_token(config, token, expected_audience=None):
    """Select only server-configured audiences, then verify signature and claims.

    An unverified payload can never expand this allowlist. MCP bearer tokens
    legitimately have a different audience from browser/CLI identity tokens.
    The selected verified audience is encrypted with the bound delegation.
    """
    from isolate_identity_security import _trusted_idp
    from isolate_oidc import identity_provider_config
    from isolate_config import with_identity_provider
    primary = identity_provider_config(config)
    candidates = [primary]
    mcp = config.get("mcp") or {}
    if mcp.get("enabled") and mcp.get("expected_audience"):
        if mcp.get("issuer") is not None and mcp["issuer"] != primary.get("issuer"):
            raise DelegationDenied("MCP and delegated jobs must use the selected identity issuer")
        alternative = dict(primary)
        for name in ("issuer", "expected_audience", "jwks_uri", "jwks_cache_path", "jwks_cache_ttl", "tls_verify"):
            if mcp.get(name) is not None:
                alternative[name] = mcp[name]
        candidates.append(alternative)
    for keycloak in candidates:
        audience = keycloak.get("expected_audience") or keycloak.get("client_id")
        if expected_audience is not None and audience != expected_audience:
            continue
        effective_config = with_identity_provider(config, keycloak)
        try:
            _trusted_idp(effective_config)
            identity = normalize_claims(verify_jwt_claims(token, keycloak), keycloak)
            return identity, effective_config, audience
        except IdentityError:
            continue
    raise DelegationDenied("job token does not match a trusted issuer, audience or signature")


def submission_identity(redis, config, identity, token, host, decision, action):
    """Return current verified identity and decision or refuse unsupported delegation."""
    if not token:
        if lifecycle_required(config, host, decision):
            raise DelegationDenied("a verified token and enabled delegation are required for this job")
        if identity.get("principal_type") == "service":
            raise DelegationDenied("workload operations require a verified delegated access token")
        return identity, decision
    if host.get("proxy_id"):
        raise DelegationDenied("delegated proxy-hop jobs require a separate hop authorization")
    if not options(config).get("enabled"):
        if lifecycle_required(config, host, decision):
            raise DelegationDenied("job delegation is disabled")
        # A provided token never becomes trusted just because lifecycle checks
        # are disabled. Verify it and resolve its current policy in all cases.
    effective, identity_config, _ = verified_token(config, token)
    if effective.get("keycloak_sub") != identity.get("keycloak_sub"):
        raise DelegationDenied("job token subject differs from the submitter")
    effective = refresh_identity(redis, identity_config, effective, token)
    assert_workload_action(config, effective, action)
    selected = _grant(redis, config, effective, host, action)
    refresh_identity(redis, identity_config, effective, token, host=host, decision=selected)
    if selected.get("remote_user") != decision.get("remote_user") or selected.get("sudo_mode") != decision.get("sudo_mode"):
        raise DelegationDenied("job remote identity differs from current policy")
    return effective, selected


def attach_delegation(redis, config, record, identity, token, host, decision):
    if not token or not options(config).get("enabled"):
        if lifecycle_required(config, host, decision):
            raise DelegationDenied("job requires a bounded live delegation")
        return record
    now = int(time.time())
    maximum = int(options(config).get("max_seconds", 300))
    if not 1 <= maximum <= 3600:
        raise DelegationDenied("delegation max_seconds must be between 1 and 3600")
    deadline = min(int(identity.get("exp") or 0), now + maximum)
    grant_expiry = (decision.get("matched_rule") or {}).get("expires_at")
    if grant_expiry:
        deadline = min(deadline, int(grant_expiry))
    if step_up_required(config, host, decision):
        freshness = int(((config.get("identity_security") or {}).get("step_up") or {}).get("max_age_seconds", 300))
        deadline = min(deadline, int((identity.get("raw_claims") or {}).get("auth_time") or 0) + freshness)
    if deadline <= now:
        raise DelegationDenied("job delegation has expired")
    reference = secrets.token_hex(32)
    record.update(schema_version=max(3, int(record.get('schema_version') or 1)), delegation_id=reference, delegation_expires_at=deadline,
                  principal_type=identity.get("principal_type", "human"), service_client_id=identity.get("service_client_id"),
                  delegation_epoch=_epoch(redis, config))
    _, _, audience = verified_token(config, token)
    associated = {"version": 1, "id": reference, "binding": _binding(record), "expires_at": deadline,
                  "epoch": record["delegation_epoch"]}
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    plaintext = _canonical({"token": token, "sub": identity["keycloak_sub"], "audience": audience})
    ciphertext = AESGCM(_encryption_key(config)).encrypt(nonce, plaintext, _canonical(associated))
    private = dict(associated, nonce=base64.b64encode(nonce).decode(), ciphertext=base64.b64encode(ciphertext).decode())
    if not redis.set("delegated_identity_" + reference, json.dumps(private, sort_keys=True), nx=True, ex=deadline - now):
        raise DelegationDenied("could not reserve job delegation")
    return record


def recheck_delegation(redis, config, record, host):
    """Return a verified effective identity and policy, never the bearer token."""
    reference = record.get("delegation_id")
    if not reference:
        raise DelegationDenied("job has no live delegation")
    if not options(config).get("enabled"):
        raise DelegationDenied("job delegation was disabled")
    try:
        if not isinstance(reference, str) or len(reference) != 64 or any(c not in "0123456789abcdef" for c in reference):
            raise DelegationDenied("invalid job delegation reference")
        raw = redis.get("delegated_identity_" + reference)
        if raw is None:
            raise DelegationDenied("job delegation expired or was revoked")
        private = json.loads(raw)
        deadline = int(private["expires_at"])
        if deadline <= time.time() or deadline != record.get("delegation_expires_at") or private["binding"] != _binding(record):
            raise DelegationDenied("job delegation binding or lifetime differs")
        associated = {key: private[key] for key in ("version", "id", "binding", "expires_at", "epoch")}
        if associated["epoch"] != record.get("delegation_epoch") or associated["epoch"] != _epoch(redis, config):
            raise DelegationDenied("job delegation authority generation changed")
        if associated["id"] != reference or associated["version"] != 1:
            raise DelegationDenied("job delegation context differs")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        plaintext = AESGCM(_encryption_key(config)).decrypt(base64.b64decode(private["nonce"], validate=True),
            base64.b64decode(private["ciphertext"], validate=True), _canonical(associated))
        secret = json.loads(plaintext)
        token = secret["token"]
        identity, identity_config, _ = verified_token(config, token, expected_audience=secret.get("audience"))
        if identity.get("keycloak_sub") != record.get("keycloak_sub") or secret["sub"] != identity.get("keycloak_sub"):
            raise DelegationDenied("job delegation subject differs")
        identity = refresh_identity(redis, identity_config, identity, token)
        if identity.get("principal_type", "human") != record.get("principal_type", "human") or identity.get("service_client_id") != record.get("service_client_id"):
            raise DelegationDenied("job principal type differs")
        action = record.get("policy_action") or "command"
        assert_workload_action(config, identity, action, record.get("runbook_class"))
        decision = _grant(redis, config, identity, host, action)
        refresh_identity(redis, identity_config, identity, token, host=host, decision=decision)
        if (str(host.get("server_id")) != record.get("host_id") or host.get("project_name") != record.get("project")
                or host.get("proxy_id") != record.get("proxy_id")
                or host.get("server_ip") != record.get("target_host")
                or int(host.get("server_port") or 22) != int(record.get("target_port") or 22)
                or decision.get("remote_user") != record.get("remote_user") or decision.get("sudo_mode") != record.get("sudo_mode")):
            raise DelegationDenied("job route or remote policy identity changed")
        return identity, decision
    except DelegationDenied:
        raise
    except (IdentityError, PolicyDenied) as exc:
        raise DelegationDenied("delegated identity or current policy is no longer authorized") from exc
    except Exception as exc:
        raise DelegationDenied("job delegation could not be verified") from exc


def revoke_delegation(redis, reference):
    if isinstance(reference, str) and len(reference) == 64:
        return redis.delete("delegated_identity_" + reference)
    return 0
