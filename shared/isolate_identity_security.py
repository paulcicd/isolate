"""Additional checks for an already signature-verified Keycloak identity.

The caller must obtain ``identity`` from a verified token, never a request body.
Revocations are authoritative Redis records, checked on every authorization and
session recheck; no allow-cache or Pub/Sub delivery is involved.
"""

import fnmatch
import hashlib
import json
import time
from urllib.parse import urlsplit

from isolate_identity import (
    IdentityError, KeycloakDeviceClient, _verify_jwt_signature, load_jwks,
    refresh_jwks_for_unknown_kid,
)


LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


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
    keycloak = config.get("keycloak") or {}
    issuer = str(keycloak.get("issuer") or "").rstrip("/")
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
        parsed_jwks = urlsplit(jwks_uri)
        if parsed_jwks.scheme != "https" or not parsed_jwks.hostname or parsed_jwks.username or parsed_jwks.password:
            raise IdentityError("Keycloak signing keys require HTTPS")
    return keycloak, issuer, audience


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
        cutoff = redis.get(_key(issuer, "sub", identity["keycloak_sub"]))
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
        if response.get("sub") != identity.get("keycloak_sub"):
            raise IdentityError("introspection subject differs from the verified identity")
        if response.get("iss", issuer) != issuer:
            raise IdentityError("introspection issuer differs from the verified identity")
        audiences = response.get("aud")
        if audiences is not None and audience not in (audiences if isinstance(audiences, list) else [audiences]):
            raise IdentityError("introspection audience differs from the verified identity")
    check_step_up(config, identity, host, decision, now)
    return identity


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
