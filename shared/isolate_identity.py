#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identity helpers for Keycloak/OIDC-backed bastion sessions."""

import json
import math
import base64
import hashlib
import os
import ssl
import tempfile
import threading
import time
import uuid
import warnings
from urllib import error, parse, request


class IdentityError(Exception):
    pass


_JWKS_REFRESH_LOCK = threading.Lock()
_JWKS_REFRESH_ATTEMPTS = {}


def normalize_claims(claims, provider_config=None):
    """Return the stable identity fields Isolate uses in policy/logging."""
    if provider_config is not None:
        from isolate_oidc import normalize_identity_claims
        return normalize_identity_claims(claims, provider_config)
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
    from isolate_oidc import identity_provider_config
    cache = _load_token_cache(path=path)
    provider = identity_provider_config(config)
    token_kind = provider.get("token_kind", "id_token")
    if token_kind not in ("id_token", "access_token"):
        raise IdentityError("Keycloak token_kind must be id_token or access_token")
    token = cache.get(token_kind)
    if not token:
        raise IdentityError("legacy or incomplete identity cache; run isolate login")
    claims = verify_jwt_claims(token, provider, now=now)
    identity = normalize_claims(claims, provider)
    identity["session_id"] = cache.get("session_id") or identity.get("session_id")
    security = config.get("identity_security") or {}
    if config.get("api", {}).get("client_url"):
        from isolate_client import verify_client_identity
        identity = verify_client_identity(config, token, identity)
    elif provider.get("provider") == "oidc" or any((security.get(name) or {}).get("enabled") for name in ("backchannel_logout", "introspection", "membership", "workloads")):
        # Import lazily to preserve login/offline CLI behavior when these
        # optional server-side identity checks are disabled.
        from isolate_identity_security import refresh_identity
        from isolate_redis import create_redis_client
        try:
            identity = refresh_identity(create_redis_client(config), config, identity, token=token, now=now)
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError("cannot verify identity revocation state") from exc
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
    if keycloak_config.get("provider") == "oidc" and (not keycloak_config.get("verify_tokens", True)
            or keycloak_config.get("tls_verify", True) is not True):
        raise IdentityError("OIDC requires verified tokens and TLS")
    if not isinstance(token, str) or len(token) > 65536:
        raise IdentityError("invalid identity token")
    if not keycloak_config.get("verify_tokens", True):
        return decode_jwt_payload(token)
    try:
        jwks = load_jwks(keycloak_config)
        jwks = refresh_jwks_for_unknown_kid(token, keycloak_config, jwks)
        claims = _verify_jwt_signature(token, jwks)
    except ImportError:
        raise IdentityError("joserfc or Authlib is required for JWT verification")
    except Exception as exc:
        raise IdentityError("invalid identity token") from exc

    _validate_claims(claims, keycloak_config, now=now)
    return claims


def _verify_jwt_signature(token, jwks):
    algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    try:
        from joserfc import jwt
        from joserfc.jwk import KeySet

        decoded = jwt.decode(token, KeySet.import_key_set(jwks), algorithms=algorithms)
        return dict(decoded.claims)
    except ImportError:
        # Rolling upgrades can load new code before dependencies are refreshed.
        # Keep the verified Authlib path as a silent compatibility fallback.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message="authlib.jose module is deprecated.*",
                category=DeprecationWarning,
            )
            from authlib.jose import JsonWebKey, JsonWebToken

        key_set = JsonWebKey.import_key_set(jwks)
        legacy_jwt = JsonWebToken(algorithms)
        claims = legacy_jwt.decode(token, key_set)
        claims.validate()
        return dict(claims)


def _validate_claims(claims, keycloak_config, now=None):
    now = int(now if now is not None else time.time())
    if "http://schemas.openid.net/event/backchannel-logout" in (claims.get("events") or {}):
        raise IdentityError("a logout token cannot authenticate a user")
    issuer = keycloak_config.get("issuer") or ""
    if keycloak_config.get("provider") != "oidc":
        issuer = issuer.rstrip("/")
    if issuer and claims.get("iss") != issuer:
        raise IdentityError("invalid token issuer")
    if keycloak_config.get("provider") == "oidc":
        for name in ("exp", "nbf", "iat"):
            value = claims.get(name)
            required = name == "exp" or name == "iat" and keycloak_config.get("token_kind", "id_token") == "id_token"
            if value is None and not required:
                continue
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise IdentityError("invalid OIDC numeric date: " + name)
        if claims.get("iat", now) > now:
            raise IdentityError("identity token was issued in the future")
        aud = claims.get("aud")
        if not (isinstance(aud, str) and aud or isinstance(aud, list) and aud
                and all(isinstance(item, str) and item for item in aud)):
            raise IdentityError("invalid token audience")
        if keycloak_config.get("token_kind", "id_token") == "id_token":
            client_id = keycloak_config.get("client_id")
            if ((isinstance(aud, list) and len(aud) > 1 or "azp" in claims)
                    and claims.get("azp") != client_id):
                raise IdentityError("invalid ID token authorized party")
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
        if expected_audience not in audiences:
            raise IdentityError("invalid token audience")


def load_jwks(keycloak_config):
    if keycloak_config.get("provider") == "oidc":
        from isolate_oidc import validate_endpoint
        validate_endpoint(keycloak_config, keycloak_config.get("issuer"))
        if keycloak_config.get("tls_verify", True) is not True:
            raise IdentityError("OIDC TLS verification cannot be disabled")
    cache_path = keycloak_config.get("jwks_cache_path")
    cache_ttl = int(keycloak_config.get("jwks_cache_ttl", 3600))
    cached = _read_jwks_cache(cache_path, cache_ttl, keycloak_config)
    if cached is not None:
        return cached
    jwks = _fetch_jwks(keycloak_config)
    _write_jwks_cache(cache_path, jwks, keycloak_config)
    return jwks


def refresh_jwks_cache(keycloak_config):
    jwks = _fetch_jwks(keycloak_config)
    _write_jwks_cache(keycloak_config.get("jwks_cache_path"), jwks, keycloak_config)
    return jwks


def refresh_jwks_for_unknown_kid(token, keycloak_config, jwks):
    """Retry cached keys once for a rotated Keycloak signing key.

    Only an unknown, explicit kid using an allowed asymmetric algorithm can
    trigger refresh. Known-key bad signatures cannot force outbound requests.
    The process-wide rate limit also bounds attacker-generated kid traffic.
    With no on-disk cache ``load_jwks`` already fetched current keys, so it is
    never fetched a second time here.
    """
    path = keycloak_config.get("jwks_cache_path")
    if not path or not os.path.isfile(path):
        return jwks
    try:
        encoded = token.split(".", 1)[0]
        header = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (AttributeError, ValueError, TypeError):
        return jwks
    kid = header.get("kid") if isinstance(header, dict) else None
    if (not isinstance(kid, str) or not kid or len(kid) > 256
            or header.get("alg") not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
            or any(key.get("kid") == kid for key in (jwks.get("keys") or []) if isinstance(key, dict))):
        return jwks
    key = (str(keycloak_config.get("issuer") or ""), os.path.abspath(path))
    interval = max(5, min(300, float(keycloak_config.get("jwks_unknown_kid_refresh_seconds", 30))))
    now = time.monotonic()
    with _JWKS_REFRESH_LOCK:
        previous = _JWKS_REFRESH_ATTEMPTS.get(key)
        if previous is not None and now - previous < interval:
            # A parallel verifier may already have refreshed the shared file.
            return _read_jwks_cache(path, int(keycloak_config.get("jwks_cache_ttl", 3600)), keycloak_config) or jwks
        _JWKS_REFRESH_ATTEMPTS[key] = now
    return refresh_jwks_cache(keycloak_config)


def _jwks_cache_binding(config):
    if not config or config.get("provider") != "oidc":
        return None
    fields = {name: config.get(name) for name in ("issuer", "jwks_uri", "discovery_url", "trusted_endpoint_origins", "ca_file", "ca_bundle")}
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _read_jwks_cache(path, ttl, provider_config=None):
    if not path or not os.path.exists(path):
        return None
    if not _is_safe_cache_path(path):
        return None
    try:
        if provider_config and provider_config.get("provider") == "oidc":
            from isolate_oidc import _protected_file
            raw = _protected_file(path, 1048576)
        else:
            with open(path, "rb") as cache_f:
                raw = cache_f.read(1048577)
        if len(raw) > 1048576:
            return None
        cache = json.loads(raw)
        if not isinstance(cache, dict) or (provider_config and provider_config.get("provider") == "oidc"
                and cache.get("provider_binding") != _jwks_cache_binding(provider_config)):
            return None
        if int(cache.get("fetched_at", 0)) + max(0, min(86400, int(ttl))) <= int(time.time()):
            return None
    except (OSError, ValueError, TypeError, RecursionError):
        return None
    jwks = cache.get("jwks")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or len(jwks["keys"]) > 100:
        return None
    return jwks


def _write_jwks_cache(path, jwks, provider_config=None):
    if not path:
        return
    directory = os.path.dirname(path)
    tmp_path = None
    try:
        os.makedirs(directory, mode=0o750, exist_ok=True)
        if not _is_safe_cache_path(path):
            return
        descriptor, tmp_path = tempfile.mkstemp(prefix=".jwks-", dir=directory)
        with os.fdopen(descriptor, "w", encoding="utf-8") as cache_f:
            json.dump({"fetched_at": int(time.time()), "jwks": jwks,
                "provider_binding": _jwks_cache_binding(provider_config)}, cache_f, sort_keys=True)
            cache_f.write("\n")
        if os.name == "posix":
            os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
    except OSError:
        return
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _is_safe_cache_path(path):
    if os.path.islink(path) or os.path.islink(os.path.dirname(path)):
        return False
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
    if keycloak_config.get("provider") == "oidc" or keycloak_config.get("ca_file") or keycloak_config.get("ca_bundle"):
        from isolate_oidc import discover_provider, _request_json
        uri = discover_provider(keycloak_config)["jwks_uri"]
        jwks = _request_json(keycloak_config, request.Request(uri, headers={"Accept": "application/json"}))
        if not isinstance(jwks.get("keys"), list) or not jwks["keys"] or len(jwks["keys"]) > 100:
            raise IdentityError("OIDC signing key set is invalid")
        return jwks
    jwks_uri = keycloak_config.get("jwks_uri") or _discover_jwks_uri(keycloak_config)
    if not jwks_uri:
        issuer = (keycloak_config.get("issuer") or "").rstrip("/")
        jwks_uri = issuer + "/protocol/openid-connect/certs"
    return _get_json(jwks_uri, tls_verify=bool(keycloak_config.get("tls_verify", True)))


def _discover_jwks_uri(keycloak_config):
    if keycloak_config.get("provider") == "oidc":
        from isolate_oidc import discover_provider
        return discover_provider(keycloak_config)["jwks_uri"]
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

    def __new__(cls, config):
        from isolate_oidc import identity_provider_config, OIDCDeviceClient
        selected = identity_provider_config(config) if "oidc" in (config or {}) or "keycloak" in (config or {}) else config or {}
        if selected.get("provider") == "oidc":
            return OIDCDeviceClient(selected)
        return super().__new__(cls)

    def __init__(self, config):
        from isolate_oidc import identity_provider_config
        self.config = identity_provider_config(config) if "oidc" in (config or {}) or "keycloak" in (config or {}) else config or {}
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

    def start(self, acr_values=None, max_age=None):
        payload = {
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
        }
        # These request an IdP-specific device-flow step-up policy. Resource
        # authorization still checks the resulting signed acr/auth_time claims;
        # sending a request parameter never proves that MFA actually happened.
        if acr_values is not None:
            if not isinstance(acr_values, (list, tuple)) or not all(isinstance(value, str) and value for value in acr_values):
                raise IdentityError("acr_values must be a list of nonempty strings")
            payload["acr_values"] = " ".join(acr_values)
        if max_age is not None:
            if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
                raise IdentityError("max_age must be a nonnegative integer")
            payload["max_age"] = max_age
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
        if self.config.get("client_secret_file"):
            from isolate_oidc import read_client_secret
            payload = dict(payload, client_secret=read_client_secret(self.config))
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
        if self.config.get("ca_file") or self.config.get("ca_bundle"):
            from isolate_oidc import _request_json
            return _request_json(self.config, req, allow_oauth_error=allow_error)
        context = None
        if not self.tls_verify:
            context = ssl._create_unverified_context()
        try:
            timeout = max(1, min(60, float(self.config.get("http_read_timeout", 15))))
            with request.urlopen(req, timeout=timeout, context=context) as resp:
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
