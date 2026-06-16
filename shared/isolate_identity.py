#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identity helpers for Keycloak/OIDC-backed bastion sessions."""

import json
import base64
import os
import ssl
import time
import uuid
from urllib import error, parse, request


class IdentityError(Exception):
    pass


def normalize_claims(claims):
    """Return the stable identity fields Isolate uses in policy/logging."""
    claims = claims or {}
    groups = claims.get("groups") or claims.get("group") or []
    if isinstance(groups, str):
        groups = [groups]

    roles = []
    realm_access = claims.get("realm_access") or {}
    if isinstance(realm_access, dict):
        roles.extend(realm_access.get("roles") or [])

    return {
        "session_id": claims.get("isolate_session_id") or str(uuid.uuid4()),
        "keycloak_sub": claims.get("sub"),
        "username": claims.get("preferred_username") or claims.get("email") or claims.get("sub"),
        "email": claims.get("email"),
        "groups": sorted(set(groups)),
        "roles": sorted(set(roles)),
        "exp": claims.get("exp"),
        "raw_claims": claims,
    }


def local_identity(username, groups=None):
    return normalize_claims(
        {
            "sub": "local:{}".format(username),
            "preferred_username": username,
            "groups": groups or [],
        }
    )


def decode_jwt_payload(token):
    """Decode JWT payload claims. Signature verification belongs to IdP/introspection."""
    if not token or token.count(".") < 2:
        return {}
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))


def identity_cache_path(path=None):
    if path:
        return path
    override = os.getenv("ISOLATE_IDENTITY_PATH")
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".isolate", "identity.json")


def save_identity(identity, path=None):
    path = identity_cache_path(path)
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass

    tmp_path = "{}.tmp".format(path)
    with open(tmp_path, "w", encoding="utf-8") as identity_f:
        json.dump(identity, identity_f, indent=2, sort_keys=True)
        identity_f.write("\n")
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:
        pass
    os.replace(tmp_path, path)
    return path


def save_token_cache(tokens, identity=None, path=None):
    identity = identity or {}
    claims = identity.get("raw_claims") or {}
    expires_at = claims.get("exp")
    if expires_at is None and tokens.get("expires_in"):
        expires_at = int(time.time()) + int(tokens["expires_in"])
    cache = {
        "schema_version": 3,
        "id_token": tokens.get("id_token"),
        "access_token": tokens.get("access_token"),
        "token_type": tokens.get("token_type", "Bearer"),
        "expires_at": expires_at,
        "session_id": identity.get("session_id"),
        "cached_display": {
            "username": identity.get("username"),
            "email": identity.get("email"),
        },
    }
    return save_identity(cache, path=path)


def load_cached_identity(path=None, now=None, require_valid=True):
    path = identity_cache_path(path)
    if not os.path.exists(path):
        raise IdentityError("no isolate identity found; run isolate login")

    with open(path, "r", encoding="utf-8") as identity_f:
        identity = json.load(identity_f)

    if require_valid:
        exp = identity.get("exp")
        if exp is None:
            exp = (identity.get("raw_claims") or {}).get("exp")
        if exp is not None and int(exp) <= int(now if now is not None else time.time()):
            raise IdentityError("isolate identity expired; run isolate login")
    return identity


def load_verified_identity(config, path=None, now=None):
    cache = _load_token_cache(path=path)
    token = cache.get("id_token")
    if not token:
        raise IdentityError("legacy or incomplete identity cache; run isolate login")
    claims = verify_jwt_claims(token, config.get("keycloak", {}), now=now)
    identity = normalize_claims(claims)
    identity["session_id"] = cache.get("session_id") or identity.get("session_id")
    return identity


def _load_token_cache(path=None):
    path = identity_cache_path(path)
    if not os.path.exists(path):
        raise IdentityError("no isolate identity found; run isolate login")
    with open(path, "r", encoding="utf-8") as identity_f:
        cache = json.load(identity_f)
    if cache.get("schema_version") != 3:
        raise IdentityError("legacy identity cache is not trusted; run isolate login")
    return cache


def verify_jwt_claims(token, keycloak_config, now=None):
    if not keycloak_config.get("verify_tokens", True):
        return decode_jwt_payload(token)
    try:
        from authlib.jose import JsonWebKey, JsonWebToken
    except ImportError:
        raise IdentityError("Authlib is required for JWT verification")

    jwks = load_jwks(keycloak_config)
    try:
        key_set = JsonWebKey.import_key_set(jwks)
        jwt = JsonWebToken(["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"])
        claims = jwt.decode(token, key_set)
        claims.validate()
    except Exception as exc:
        raise IdentityError("invalid identity token: {}".format(exc))

    claims = dict(claims)
    _validate_claims(claims, keycloak_config, now=now)
    return claims


def _validate_claims(claims, keycloak_config, now=None):
    now = int(now if now is not None else time.time())
    issuer = (keycloak_config.get("issuer") or "").rstrip("/")
    if issuer and claims.get("iss") != issuer:
        raise IdentityError("invalid token issuer")
    exp = claims.get("exp")
    if exp is None or int(exp) <= now:
        raise IdentityError("identity token expired")
    nbf = claims.get("nbf")
    if nbf is not None and int(nbf) > now:
        raise IdentityError("identity token is not valid yet")
    expected_audience = keycloak_config.get("expected_audience") or keycloak_config.get("client_id")
    if expected_audience:
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        azp = claims.get("azp")
        if expected_audience not in audiences and expected_audience != azp:
            raise IdentityError("invalid token audience")


def load_jwks(keycloak_config):
    cache_path = keycloak_config.get("jwks_cache_path")
    cache_ttl = int(keycloak_config.get("jwks_cache_ttl", 3600))
    cached = _read_jwks_cache(cache_path, cache_ttl)
    if cached is not None:
        return cached
    jwks = _fetch_jwks(keycloak_config)
    _write_jwks_cache(cache_path, jwks)
    return jwks


def refresh_jwks_cache(keycloak_config):
    jwks = _fetch_jwks(keycloak_config)
    _write_jwks_cache(keycloak_config.get("jwks_cache_path"), jwks)
    return jwks


def _read_jwks_cache(path, ttl):
    if not path or not os.path.exists(path):
        return None
    if not _is_safe_cache_path(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as cache_f:
            cache = json.load(cache_f)
    except (OSError, ValueError):
        return None
    if int(cache.get("fetched_at", 0)) + int(ttl) <= int(time.time()):
        return None
    return cache.get("jwks")


def _write_jwks_cache(path, jwks):
    if not path:
        return
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, mode=0o750, exist_ok=True)
        tmp_path = "{}.tmp".format(path)
        with open(tmp_path, "w", encoding="utf-8") as cache_f:
            json.dump({"fetched_at": int(time.time()), "jwks": jwks}, cache_f, sort_keys=True)
            cache_f.write("\n")
        if os.name == "posix":
            os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
    except OSError:
        return


def _is_safe_cache_path(path):
    if os.name != "posix":
        return True
    try:
        directory = os.path.dirname(path)
        for candidate in (directory, path):
            if not os.path.exists(candidate):
                continue
            mode = os.stat(candidate).st_mode
            if mode & 0o022:
                return False
    except OSError:
        return False
    return True


def _fetch_jwks(keycloak_config):
    jwks_uri = keycloak_config.get("jwks_uri") or _discover_jwks_uri(keycloak_config)
    if not jwks_uri:
        issuer = (keycloak_config.get("issuer") or "").rstrip("/")
        jwks_uri = issuer + "/protocol/openid-connect/certs"
    return _get_json(jwks_uri, tls_verify=bool(keycloak_config.get("tls_verify", True)))


def _discover_jwks_uri(keycloak_config):
    issuer = (keycloak_config.get("issuer") or "").rstrip("/")
    if not issuer:
        return None
    try:
        metadata = _get_json(issuer + "/.well-known/openid-configuration", tls_verify=bool(keycloak_config.get("tls_verify", True)))
        return metadata.get("jwks_uri")
    except IdentityError:
        return None


def _get_json(url, tls_verify=True):
    context = None
    if not tls_verify:
        context = ssl._create_unverified_context()
    req = request.Request(url, headers={"Accept": "application/json", "User-Agent": "isolate-bastion/2.0"})
    try:
        with request.urlopen(req, timeout=15, context=context) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        raise IdentityError(KeycloakDeviceClient._format_http_error(exc))
    except error.URLError as exc:
        raise IdentityError("Keycloak request failed: {}".format(exc.reason))


def clear_cached_identity(path=None):
    path = identity_cache_path(path)
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False


class KeycloakDeviceClient(object):
    """Small Device Authorization Grant client using stdlib HTTP."""

    def __init__(self, config):
        self.config = config or {}
        issuer = (self.config.get("issuer") or "").rstrip("/")
        self.client_id = self.config.get("client_id")
        self.client_secret = self.config.get("client_secret")
        self.scopes = self.config.get("scopes") or ["openid", "profile", "email"]
        self.device_endpoint = self.config.get("device_authorization_endpoint") or (
            issuer + "/protocol/openid-connect/auth/device"
        )
        self.token_endpoint = self.config.get("token_endpoint") or (
            issuer + "/protocol/openid-connect/token"
        )
        self.poll_timeout = int(self.config.get("poll_timeout", 300))
        self.tls_verify = bool(self.config.get("tls_verify", True))

    def start(self):
        payload = {
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        return self._post(self.device_endpoint, payload)

    def poll(self, device_code, interval=5):
        deadline = time.time() + self.poll_timeout
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": self.client_id,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret

        while time.time() < deadline:
            response = self._post(self.token_endpoint, payload, allow_error=True)
            if "id_token" in response or "access_token" in response:
                return response
            error = response.get("error")
            if error == "authorization_pending":
                time.sleep(interval)
                continue
            if error == "slow_down":
                interval += 5
                time.sleep(interval)
                continue
            raise IdentityError(response.get("error_description") or error or "device flow failed")
        raise IdentityError("device flow timed out")

    def introspect(self, token):
        endpoint = self.config.get("introspection_endpoint")
        issuer = (self.config.get("issuer") or "").rstrip("/")
        if endpoint is None and issuer:
            endpoint = issuer + "/protocol/openid-connect/token/introspect"
        if endpoint is None:
            return None
        payload = {
            "token": token,
            "client_id": self.client_id,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        response = self._post(endpoint, payload)
        if response.get("active") is False:
            raise IdentityError("token is not active")
        return response

    @staticmethod
    def _format_http_error(exc):
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
            detail = parsed.get("error_description") or parsed.get("error") or body
        except ValueError:
            detail = body
        return "Keycloak HTTP {} {}: {}".format(exc.code, exc.reason, detail.strip())

    def _post(self, url, payload, allow_error=False):
        data = parse.urlencode(payload).encode("utf-8")
        req = request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "isolate-bastion/2.0",
            },
        )
        context = None
        if not self.tls_verify:
            context = ssl._create_unverified_context()
        try:
            with request.urlopen(req, timeout=15, context=context) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as exc:
            if allow_error:
                body = exc.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(body)
                except ValueError:
                    raise IdentityError("Keycloak HTTP {} {}: {}".format(exc.code, exc.reason, body.strip()))
            raise IdentityError(self._format_http_error(exc))
        except error.URLError as exc:
            raise IdentityError("Keycloak request failed: {}".format(exc.reason))
