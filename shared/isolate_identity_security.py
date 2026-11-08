"""Additional checks for an already signature-verified Keycloak identity.

The caller must obtain ``identity`` from a verified token, never a request body.
Revocations are authoritative Redis records, checked on every authorization and
session recheck; no allow-cache or Pub/Sub delivery is involved.
"""

import fnmatch
import hashlib
import json
import os
import ssl
import stat
import threading
import time
from urllib import error, parse, request
from urllib.parse import urlsplit

from isolate_identity import (
    IdentityError, KeycloakDeviceClient, _verify_jwt_signature, load_jwks,
    refresh_jwks_for_unknown_kid,
)
from isolate_oidc import identity_provider_config, validate_endpoint


LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
_ADMIN_TOKENS = {}
_ADMIN_TOKEN_LOCK = threading.Lock()


class StepUpRequired(IdentityError):
    """The IdP must issue a fresh token at the configured assurance level."""

    def __init__(self, acr_values=(), max_age=None):
        self.acr_values = list(acr_values)
        self.max_age = max_age
        super().__init__("fresh step-up authentication is required")


class IdentityStoreUnavailable(IdentityError):
    """The callback must return a retriable 503 without acknowledging logout."""


def _options(config):
    return config.get("identity_security") or {}


def _trusted_idp(config):
    keycloak = identity_provider_config(config)
    issuer = str(keycloak.get("issuer") or "")
    parsed = urlsplit(issuer)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or not keycloak.get("verify_tokens", True)
            or not keycloak.get("tls_verify", True)):
        raise IdentityError("verified Keycloak HTTPS identity is required")
    audience = keycloak.get("expected_audience") or keycloak.get("client_id")
    if not audience:
        raise IdentityError("Keycloak audience is required")
    jwks_uri = keycloak.get("jwks_uri")
    if jwks_uri:
        if keycloak.get("provider") == "oidc":
            validate_endpoint(keycloak, jwks_uri)
        parsed_jwks = urlsplit(jwks_uri)
        if parsed_jwks.scheme != "https" or not parsed_jwks.hostname or parsed_jwks.username or parsed_jwks.password:
            raise IdentityError("Keycloak signing keys require HTTPS")
    return keycloak, issuer, audience


def _raw_subject(identity):
    return identity.get("oidc_sub") or (identity.get("raw_claims") or {}).get("sub") or identity.get("keycloak_sub")


def _key(issuer, kind, value):
    material = json.dumps([issuer, kind, value], separators=(",", ":"))
    return "identity_revocation_" + hashlib.sha256(material.encode()).hexdigest()


def _integer(value, message):
    if isinstance(value, bool) or not isinstance(value, int):
        raise IdentityError(message)
    return value


def step_up_required(config, host=None, decision=None):
    options = _options(config).get("step_up") or {}
    if not options.get("enabled", False):
        return False
    project = str((host or {}).get("project_name") or "")
    privileged = ((decision or {}).get("remote_user") == "root"
                  or (decision or {}).get("sudo_mode") == "sudo-i")
    return bool(options.get("all_connections")
                or options.get("require_privileged", True) and privileged
                or project in (options.get("required_projects") or [])
                or any(fnmatch.fnmatchcase(project, pattern)
                       for pattern in options.get("required_project_globs") or []))


def check_step_up(config, identity, host=None, decision=None, now=None):
    if not step_up_required(config, host, decision):
        return
    _trusted_idp(config)
    options = _options(config).get("step_up") or {}
    claims = identity.get("raw_claims") or {}
    accepted_acr = options.get("acr_values") or []
    required_amr = options.get("required_amr") or []
    maximum_age = int(options.get("max_age_seconds", 300))
    if (not isinstance(accepted_acr, list) or not isinstance(required_amr, list)
            or not all(isinstance(x, str) and x for x in accepted_acr + required_amr)
            or not (accepted_acr or required_amr) or maximum_age <= 0):
        raise IdentityError("step-up assurance and a positive maximum age must be configured")
    now = int(time.time() if now is None else now)
    auth_time = claims.get("auth_time")
    amr = claims.get("amr")
    if (isinstance(auth_time, bool) or not isinstance(auth_time, int)
            or auth_time > now or now - auth_time > maximum_age
            or accepted_acr and claims.get("acr") not in accepted_acr
            or required_amr and (not isinstance(amr, list) or not all(isinstance(value, str) for value in amr)
                                 or not set(required_amr).issubset(amr))):
        raise StepUpRequired(accepted_acr, maximum_age)


def assert_identity_active(redis, config, identity, token=None, host=None, decision=None, now=None):
    """Reject revoked identities and enforce opt-in introspection and step-up.

    ``token`` must be the same verified bearer token represented by ``identity``.
    Introspection is deliberately uncached: an inactive token must never be
    accepted because another node cached a previous active response.
    """
    now = int(time.time() if now is None else now)
    options = _options(config)
    logout = options.get("backchannel_logout") or {}
    introspection = options.get("introspection") or {}
    claims = identity.get("raw_claims") or {}
    if logout.get("enabled", False):
        _, issuer, _ = _trusted_idp(config)
        if claims.get("iss") != issuer or not identity.get("keycloak_sub"):
            raise IdentityError("revocation checks require a verified issuer and subject")
        issued = _integer(claims.get("iat"), "token issue time is required for revocation checks")
        expires = _integer(claims.get("exp"), "token expiry is required for revocation checks")
        maximum_lifetime = int(logout.get("max_token_lifetime_seconds", 86400))
        if (maximum_lifetime <= 0 or expires <= now or issued > now
                or expires - issued > maximum_lifetime or expires <= issued):
            raise IdentityError("token lifetime is not permitted for revocation checks")
        if redis is None:
            raise IdentityError("revocation store is unavailable")
        sid = claims.get("sid") or claims.get("session_state")
        if sid and redis.get(_key(issuer, "sid", sid)) is not None:
            raise IdentityError("Keycloak session has been revoked")
        cutoff = redis.get(_key(issuer, "sub", _raw_subject(identity)))
        authenticated = claims.get("auth_time", issued)
        authenticated = _integer(authenticated, "invalid token authentication time")
        if authenticated > issued:
            raise IdentityError("token authentication time is not permitted")
        if cutoff is not None and authenticated <= int(cutoff):
            raise IdentityError("Keycloak subject sessions have been revoked")
    if introspection.get("enabled", False):
        keycloak, issuer, audience = _trusted_idp(config)
        if keycloak.get("token_kind", "id_token") != "access_token":
            raise IdentityError("Keycloak introspection requires token_kind: access_token")
        if not token:
            raise IdentityError("a verified bearer token is required for introspection")
        endpoint = keycloak.get("introspection_endpoint")
        if endpoint:
            parsed = urlsplit(endpoint)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise IdentityError("Keycloak introspection requires HTTPS")
        response = KeycloakDeviceClient(keycloak).introspect(token)
        if not isinstance(response, dict) or response.get("active") is not True:
            raise IdentityError("Keycloak token is not active")
        if response.get("sub") != _raw_subject(identity):
            raise IdentityError("introspection subject differs from the verified identity")
        if response.get("iss", issuer) != issuer:
            raise IdentityError("introspection issuer differs from the verified identity")
        audiences = response.get("aud")
        if audiences is not None and audience not in (audiences if isinstance(audiences, list) else [audiences]):
            raise IdentityError("introspection audience differs from the verified identity")
    check_step_up(config, identity, host, decision, now)
    return identity


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _membership_bearer(path):
    """Read only a protected server-owned management credential."""
    if not isinstance(path, str) or not os.path.isabs(path):
        raise IdentityError("a protected membership credential file is required")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or os.path.islink(path):
                raise IdentityError("unsafe membership credential file")
            if os.name == "posix" and (info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o077):
                raise IdentityError("unsafe membership credential permissions")
            token = source.read(32769).decode().strip()
    except (OSError, UnicodeError) as exc:
        raise IdentityError("membership credential is unavailable") from exc
    if not token or len(token) > 32768 or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise IdentityError("membership credential is invalid")
    return token


def _membership_get(config, endpoint, bearer, deadline):
    options = _options(config).get("membership") or {}
    context = ssl.create_default_context(cafile=options.get("ca_file"))
    opener = request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise IdentityError("authoritative membership lookup timed out")
    req = request.Request(endpoint, headers={"Authorization": "Bearer " + bearer, "Accept": "application/json"})
    try:
        with opener.open(req, timeout=max(0.1, min(5.0, remaining))) as response:
            raw = response.read(2097153)
        if len(raw) > 2097152:
            raise IdentityError("authoritative membership response is too large")
        return json.loads(raw)
    except IdentityError:
        raise
    except (error.URLError, OSError, ValueError) as exc:
        if isinstance(exc, error.HTTPError) and exc.code in (401, 403):
            with _ADMIN_TOKEN_LOCK:
                for key in [key for key, value in _ADMIN_TOKENS.items() if value[0] == bearer]:
                    _ADMIN_TOKENS.pop(key, None)
        # Neither response bodies nor management credentials belong in logs.
        raise IdentityError("authoritative membership lookup failed") from exc


def _management_token(config, issuer):
    options = _options(config).get("membership") or {}
    if options.get("token_file"):
        return _membership_bearer(options["token_file"])
    client_id = options.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        raise IdentityError("membership requires a read-only service credential")
    secret = _membership_bearer(options.get("client_secret_file"))
    cache_key = hashlib.sha256(_canonical_management([issuer, client_id, secret])).hexdigest()
    with _ADMIN_TOKEN_LOCK:
        cached = _ADMIN_TOKENS.get(cache_key)
        if cached and cached[1] > time.monotonic():
            return cached[0]
    context = ssl.create_default_context(cafile=options.get("ca_file"))
    opener = request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())
    req = request.Request(issuer + "/protocol/openid-connect/token",
        data=parse.urlencode({"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with opener.open(req, timeout=5) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError()
        result = json.loads(raw)
        bearer = result["access_token"]
        lifetime = int(result["expires_in"])
        if (not isinstance(bearer, str) or not bearer or len(bearer) > 32768 or lifetime <= 0
                or any(ord(char) < 33 or ord(char) > 126 for char in bearer)
                or str(result.get("token_type", "")).lower() != "bearer"):
            raise ValueError()
    except (error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
        raise IdentityError("membership service authentication failed") from exc
    # Only the management credential is cached. Every authorization still asks
    # Keycloak for the user's current enabled/groups/roles model.
    with _ADMIN_TOKEN_LOCK:
        _ADMIN_TOKENS[cache_key] = (bearer, time.monotonic() + max(0, min(60, lifetime - 5)))
    return bearer


def _canonical_management(value):
    return json.dumps(value, separators=(",", ":")).encode()


def _live_membership(config, identity):
    """Query Keycloak's current user model, never the old token's group snapshot.

    Introspection of a self-contained access token is not assumed to refresh its
    authorization claims. A dedicated read-only Admin REST service credential
    is required, and absence of that authority is a denial rather than fallback.
    """
    provider, issuer, _ = _trusted_idp(config)
    if provider.get("provider") != "keycloak":
        raise IdentityError("the selected OIDC provider does not support Keycloak Admin membership")
    options = _options(config).get("membership") or {}
    if options.get("source", "keycloak-admin") != "keycloak-admin":
        raise IdentityError("unsupported authoritative membership source")
    parts = issuer.rsplit("/realms/", 1)
    if len(parts) != 2 or not parts[1] or "/" in parts[1]:
        raise IdentityError("Keycloak issuer must identify one realm")
    subject = _raw_subject(identity)
    if not isinstance(subject, str) or not subject or len(subject) > 1024:
        raise IdentityError("verified membership subject is required")
    base = parts[0] + "/admin/realms/" + parse.quote(parse.unquote(parts[1]), safe="")
    base += "/users/" + parse.quote(subject, safe="")
    bearer = _management_token(config, issuer)
    budget = float(options.get("timeout_seconds", 10))
    if not 0 < budget <= 30:
        raise IdentityError("membership timeout must be greater than zero and at most 30 seconds")
    deadline = time.monotonic() + budget
    user = _membership_get(config, base, bearer, deadline)
    if not isinstance(user, dict) or user.get("id") != subject or user.get("enabled") is not True:
        raise IdentityError("Keycloak user is disabled, missing or differs from the verified subject")
    maximum = int(options.get("max_groups", 1000))
    if not 1 <= maximum <= 10000:
        raise IdentityError("membership max_groups is outside the supported range")
    style = options.get("group_name_style", "name")
    if style not in ("name", "path"):
        raise IdentityError("membership group_name_style must be name or path")
    groups, offset = [], 0
    while True:
        page = _membership_get(config, base + "/groups?" + parse.urlencode({"first": offset, "max": 100,
            "briefRepresentation": "true"}), bearer, deadline)
        if not isinstance(page, list) or len(page) > 100:
            raise IdentityError("invalid authoritative group response")
        for group in page:
            value = group.get(style) if isinstance(group, dict) else None
            if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
                raise IdentityError("authoritative group name is missing or invalid")
            groups.append(value)
        if len(groups) > maximum:
            raise IdentityError("authoritative group membership exceeds the configured limit")
        if len(page) < 100:
            break
        offset += len(page)
    roles = []
    if options.get("include_realm_roles", True):
        assigned = _membership_get(config, base + "/role-mappings/realm/composite", bearer, deadline)
        if not isinstance(assigned, list) or len(assigned) > 10000:
            raise IdentityError("invalid authoritative role response")
        for role in assigned:
            value = role.get("name") if isinstance(role, dict) else None
            if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
                raise IdentityError("authoritative role name is missing or invalid")
            roles.append(value)
    return sorted(set(groups)), sorted(set(roles))


def classify_principal(config, identity):
    """Service accounts only match explicitly pinned service grants, not humans."""
    result = dict(identity)
    claims = identity.get("raw_claims") or {}
    marker = claims.get("isolate_principal_type")
    registered = ((_options(config).get("workloads") or {}).get("clients") or {})
    client = claims.get("azp") or claims.get("client_id")
    if marker != "service":
        if client in registered or any(isinstance(entry, dict) and entry.get("sub") == _raw_subject(identity) for entry in registered.values()):
            raise IdentityError("registered workload requires an explicit signed service principal marker")
        result["principal_type"] = "human"
        return result
    options = _options(config).get("workloads") or {}
    allowed = (options.get("clients") or {}).get(client)
    if (not options.get("enabled") or not isinstance(allowed, dict)
            or allowed.get("sub") != _raw_subject(identity)
            or identity_provider_config(config).get("token_kind", "id_token") != "access_token"
            or not (_options(config).get("introspection") or {}).get("enabled")):
        raise IdentityError("workload identity is not explicitly registered")
    required = allowed.get("required_scopes") or []
    scope = claims.get("scope") or ""
    if not isinstance(scope, str) or not isinstance(required, list) or not required or not set(required).issubset(scope.split()):
        raise IdentityError("workload identity lacks its required scopes")
    result.update(principal_type="service", service_client_id=client, groups=[], roles=[])
    return result


def assert_workload_action(config, identity, action, runbook_class=None):
    if identity.get("principal_type") != "service":
        return
    client = identity.get("service_client_id")
    allowed = ((_options(config).get("workloads") or {}).get("clients") or {}).get(client) or {}
    if action not in (allowed.get("allowed_actions") or []):
        raise IdentityError("workload client is not allowed to perform this action")
    scopes = str((identity.get("raw_claims") or {}).get("scope") or "").split()
    config_key, default = {"command": ("execute_scope", "isolate.execute"), "runbook": ("runbook_scope", "isolate.runbook"),
                          "operate": ("operate_scope", "isolate.operate")}.get(action, (None, "isolate." + action))
    required = (config.get("mcp") or {}).get(config_key, default) if config_key else default
    if required not in scopes:
        raise IdentityError("workload token lacks the action scope")
    if runbook_class is not None and runbook_class not in (allowed.get("allowed_runbook_classes") or []):
        raise IdentityError("workload client is not allowed to run this runbook class")


def workload_identity(config, token):
    """Authenticate a registered service account without human impersonation."""
    from isolate_identity import normalize_claims, verify_jwt_claims
    keycloak, _, _ = _trusted_idp(config)
    identity = classify_principal(config, normalize_claims(verify_jwt_claims(token, keycloak), keycloak))
    if identity.get("principal_type") != "service":
        raise IdentityError("a registered workload token is required")
    return identity


def refresh_identity(redis, config, identity, token, host=None, decision=None, now=None):
    """Refresh a signature-verified identity from the live configured authority.

    Identity display and stable subject come from the verified token. Current
    authorization membership comes from the server's trusted Keycloak Admin API,
    if enabled. Network failure never revives an old allowed group snapshot.
    """
    from isolate_identity_binding import ensure_provider_binding
    ensure_provider_binding(config, redis)
    assert_identity_active(redis, config, identity, token=token, host=host, decision=decision, now=now)
    effective = classify_principal(config, identity)
    membership = _options(config).get("membership") or {}
    if membership.get("enabled"):
        groups, roles = _live_membership(config, identity)
        if effective["principal_type"] != "service":
            effective.update(groups=groups, roles=roles)
        effective["membership_checked_at"] = int(time.time() if now is None else now)
    return effective


def process_backchannel_logout(redis, config, logout_token, now=None):
    """Validate OIDC Logout Token and atomically persist revocation plus replay ID.

    No administrator bearer token or CSRF cookie is required on the callback:
    the OP's asymmetric signature authenticates this request. A normal access or
    ID token cannot be used as a logout token, nor a logout token as an identity.
    """
    options = _options(config).get("backchannel_logout") or {}
    if not options.get("enabled", False):
        raise IdentityError("Keycloak backchannel logout is disabled")
    keycloak, issuer, audience = _trusted_idp(config)
    audience = keycloak.get("client_id") or audience
    if not isinstance(logout_token, str) or len(logout_token) > 65536:
        raise IdentityError("invalid logout token")
    try:
        jwks = refresh_jwks_for_unknown_kid(logout_token, keycloak, load_jwks(keycloak))
        claims = _verify_jwt_signature(logout_token, jwks)
    except Exception as exc:
        raise IdentityError("invalid logout token signature") from exc
    now = int(time.time() if now is None else now)
    audiences = claims.get("aud")
    if claims.get("iss") != issuer or audience not in (audiences if isinstance(audiences, list) else [audiences]):
        raise IdentityError("invalid logout token issuer or audience")
    issued = _integer(claims.get("iat"), "logout token issue time is required")
    maximum_age = int(options.get("max_logout_age_seconds", 300))
    if maximum_age <= 0 or issued > now or now - issued > maximum_age:
        raise IdentityError("logout token is stale or not valid yet")
    if "exp" in claims and _integer(claims["exp"], "invalid logout token expiry") <= now:
        raise IdentityError("logout token has expired")
    events = claims.get("events")
    if (not isinstance(events, dict) or not isinstance(events.get(LOGOUT_EVENT), dict)
            or "nonce" in claims):
        raise IdentityError("invalid logout token events or nonce")
    sub, sid, jti = claims.get("sub"), claims.get("sid"), claims.get("jti")
    if (not any(isinstance(value, str) and value for value in (sub, sid))
            or any(value is not None and (not isinstance(value, str) or not value or len(value) > 1024)
                   for value in (sub, sid))
            or not isinstance(jti, str) or not jti or len(jti) > 1024):
        raise IdentityError("logout token subject/session and replay identifier are required")
    # sid restricts the logout to that session, even when a sub is also present.
    kind, value = ("sid", sid) if sid else ("sub", sub)
    revocation_key, replay_key = _key(issuer, kind, value), _key(issuer, "jti", jti)
    lifetime = int(options.get("max_token_lifetime_seconds", 86400))
    if lifetime <= 0:
        raise IdentityError("a positive maximum token lifetime is required")
    # Older valid logout deliveries cannot lower a subject's revocation cutoff.
    # Keep the marker beyond the longest token that could predate this logout.
    retention = lifetime + maximum_age + 60
    try:
        from redis.exceptions import WatchError
        for _ in range(8):
            try:
                with redis.pipeline() as pipe:
                    pipe.watch(revocation_key, replay_key)
                    if pipe.get(replay_key) is not None:
                        raise IdentityError("logout token has already been processed")
                    previous = pipe.get(revocation_key)
                    cutoff = max(issued, int(previous) if previous is not None else issued)
                    pipe.multi()
                    pipe.set(revocation_key, str(cutoff), ex=retention)
                    pipe.set(replay_key, "1", ex=maximum_age + 60)
                    pipe.execute()
                    return {"revoked": kind, "issued_at": issued}
            except WatchError:
                continue
    except IdentityError:
        raise
    except Exception as exc:
        raise IdentityStoreUnavailable("cannot persist Keycloak logout") from exc
    raise IdentityStoreUnavailable("Keycloak logout persistence conflicted; retry delivery")
