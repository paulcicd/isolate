"""Provider-neutral OIDC configuration, discovery and RFC 8628 transport.

Only deployment configuration chooses an issuer and endpoint origins. Token
headers/claims never choose a metadata, token or signing-key URL. Keycloak is a
backwards-compatible provider adapter, rather than the protocol abstraction.
"""

import base64
import copy
import hashlib
import json
import math
import os
import ssl
import stat
import threading
import time
import uuid
from urllib import error, parse, request

from isolate_identity import IdentityError


_CACHE = {}
_CACHE_LOCK = threading.Lock()
_ENDPOINTS = ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint",
    "device_authorization_endpoint", "introspection_endpoint", "revocation_endpoint", "end_session_endpoint")
_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
_OAUTH_ERRORS = frozenset(("authorization_pending", "slow_down", "access_denied", "expired_token",
    "invalid_client", "invalid_grant", "invalid_request", "unauthorized_client", "unsupported_grant_type", "invalid_scope"))


def _https_url(value, *, query=False):
    if (not isinstance(value, str) or not value or len(value) > 4096 or "\\" in value
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
        raise IdentityError("OIDC URLs must be explicit HTTPS URLs")
    try:
        parsed = parse.urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment or parsed.query and not query or parsed.port == 0):
            raise ValueError("unsafe URL")
        return parsed
    except ValueError as exc:
        raise IdentityError("OIDC URLs must be explicit HTTPS URLs without credentials or fragments") from exc


def _origin(value):
    parsed = _https_url(value, query=True)
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    return "https://" + host + (":" + str(parsed.port) if parsed.port not in (None, 443) else "")


def _trusted_origins(config):
    issuer = config.get("issuer")
    result = {_origin(issuer)}
    configured = config.get("trusted_endpoint_origins") or []
    if not isinstance(configured, (tuple, list)) or len(configured) > 16:
        raise IdentityError("OIDC trusted_endpoint_origins must be a bounded list")
    for value in configured:
        parsed = _https_url(value)
        if parsed.path not in ("", "/"):
            raise IdentityError("OIDC trusted endpoint origins must not contain paths")
        result.add(_origin(value))
    return result


def validate_endpoint(config, value):
    """Validate a deployment/discovery URL, never a token-supplied URL."""
    _https_url(value)
    if _origin(value) not in _trusted_origins(config):
        raise IdentityError("OIDC endpoint origin is not explicitly trusted")
    return value


def identity_provider_config(config):
    """Select one canonical provider without merging two issuers' credentials.

    ``keycloak`` remains the source when ``oidc`` is absent/disabled. An enabled
    ``oidc`` section is complete and never inherits issuer/secret/endpoints from
    the legacy section, even when both exist in a merged default config.
    """
    config = config or {}
    oidc = config.get("oidc")
    if oidc is not None and not isinstance(oidc, dict):
        raise IdentityError("oidc must be an object")
    enabled = bool(oidc and oidc.get("enabled", bool(oidc.get("issuer"))))
    if oidc and "enabled" in oidc and not isinstance(oidc["enabled"], bool):
        raise IdentityError("oidc.enabled must be a boolean")
    section = oidc if enabled else config.get("keycloak") or {}
    if not isinstance(section, dict):
        raise IdentityError("identity provider configuration must be an object")
    result = copy.deepcopy(section)
    provider = section.get("provider", "oidc" if enabled else "keycloak")
    if provider not in ("oidc", "keycloak"):
        raise IdentityError("identity provider must be oidc or keycloak")
    result["provider"] = provider
    result["identity_provider"] = provider
    result["enabled"] = enabled or bool(result.get("issuer"))
    result.setdefault("display_name", "Keycloak" if provider == "keycloak" else "OpenID Connect")
    result.setdefault("token_kind", "id_token")
    result.setdefault("verify_tokens", True)
    result.setdefault("tls_verify", True)
    result.setdefault("claim_mapping", {})
    if result.get("issuer") and provider == "keycloak":
        result["issuer"] = str(result["issuer"]).rstrip("/")
    if result["token_kind"] not in ("id_token", "access_token"):
        raise IdentityError("OIDC token_kind must be id_token or access_token")
    return result


def _provider(config):
    return identity_provider_config(config) if "oidc" in config or "keycloak" in config else dict(config)


def _claim(claims, path):
    if not isinstance(path, str) or not path or len(path) > 512:
        raise IdentityError("OIDC claim paths must be nonempty strings")
    if path.startswith("/"):
        segments = [segment.replace("~1", "/").replace("~0", "~") for segment in path[1:].split("/")]
    else:
        segments = path.split(".")
    value = claims
    for segment in segments:
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    return value


def _strings(value, name):
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if (not isinstance(value, list) or len(value) > 1000
            or any(not isinstance(item, str) or not item or len(item) > 256
                   or any(ord(char) < 32 or ord(char) == 127 for char in item) for item in value)):
        raise IdentityError("OIDC " + name + " claim must contain bounded strings")
    return sorted(set(value))


def _mapped(claims, configured, default):
    paths = configured if configured is not None else default
    paths = [paths] if isinstance(paths, str) else paths
    if not isinstance(paths, list) or not paths or len(paths) > 16:
        raise IdentityError("OIDC claim mapping must contain a path or bounded fallback paths")
    for path in paths:
        value = _claim(claims, path)
        if value not in (None, "", []):
            return value
    return None


def normalize_identity_claims(claims, provider_config):
    """Normalize already verified claims, preserving the raw OIDC subject too.

    Generic issuers receive an issuer+subject namespace in legacy ``keycloak_sub``
    fields. An IdP migration can therefore never silently reuse another issuer's
    subject grants, preferences, bookmarks or ownership records.
    """
    config = _provider(provider_config or {})
    if not isinstance(claims, dict):
        raise IdentityError("OIDC claims must be an object")
    issuer = config.get("issuer") or claims.get("iss")
    provider = config.get("provider", "keycloak")
    if provider == "oidc" and not config.get("issuer"):
        raise IdentityError("OIDC issuer must be explicitly configured")
    if config.get("issuer") and claims.get("iss") != config["issuer"]:
        raise IdentityError("OIDC claims belong to a different issuer")
    if provider == "oidc":
        _https_url(issuer)
    subject = claims.get("sub")
    if (not isinstance(subject, str) or not subject or len(subject) > 512
            or any(ord(char) < 32 or ord(char) == 127 for char in subject)):
        raise IdentityError("OIDC subject is missing or invalid")
    mapping = config.get("claim_mapping") or {}
    if not isinstance(mapping, dict) or set(mapping) - {"username", "email", "groups", "roles"}:
        raise IdentityError("OIDC claim_mapping contains unsupported fields")
    username = _mapped(claims, mapping.get("username"), ["preferred_username", "email", "sub"])
    email = _mapped(claims, mapping.get("email"), ["email"])
    if (not isinstance(username, str) or not username or len(username) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in username)):
        raise IdentityError("OIDC username is missing or invalid")
    if email is not None and (not isinstance(email, str) or len(email) > 512 or any(ord(char) < 32 for char in email)):
        raise IdentityError("OIDC email claim is invalid")
    groups = _strings(_mapped(claims, mapping.get("groups"), ["groups", "group"] if provider == "keycloak" else ["groups"]), "groups")
    roles = _strings(_mapped(claims, mapping.get("roles"), ["realm_access.roles"] if provider == "keycloak" else ["roles"]), "roles")
    material = json.dumps([issuer, subject], separators=(",", ":"), ensure_ascii=True).encode()
    canonical = "oidc:" + hashlib.sha256(material).hexdigest() if provider == "oidc" else subject
    return {"session_id": claims.get("isolate_session_id") or str(uuid.uuid4()),
        "keycloak_sub": canonical, "subject_id": canonical, "oidc_sub": subject,
        "issuer": issuer, "identity_provider": provider, "username": username, "email": email,
        "groups": groups, "roles": roles, "exp": claims.get("exp"), "raw_claims": claims}


def read_client_secret(config):
    """Read a private client-secret file only when client authentication needs it."""
    path = config.get("client_secret_file")
    if not path:
        value = config.get("client_secret")
        if value is not None and (not isinstance(value, str) or not value or len(value) > 16384
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise IdentityError("OIDC client secret is invalid")
        return value
    try:
        material = _protected_file(path, 16384, private=True)
        value = material.decode("utf-8").strip()
        if not value or len(material) > 16384 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("invalid secret content")
        return value
    except (OSError, UnicodeError, ValueError) as exc:
        raise IdentityError("OIDC client secret file is unavailable or unsafe") from exc


def _protected_file(path, maximum, *, private=False):
    """Use the validated descriptor's bytes, preventing a path reread race."""
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError("an absolute protected file is required")
    current = os.path.dirname(path)
    if os.name == "posix":
        while True:
            info = os.lstat(current)
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022 and not sticky):
                raise OSError("unsafe protected file ancestor")
            parent = os.path.dirname(current)
            if parent == current or sticky:
                break
            current = parent
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or os.path.islink(path)
                or os.name == "posix" and (info.st_uid not in (0, os.geteuid())
                    or info.st_mode & (0o077 if private else 0o022))):
            raise OSError("unsafe protected file permissions")
        material = source.read(maximum + 1)
    if len(material) > maximum:
        raise ValueError("protected file is too large")
    return material


def _bounded_number(config, key, default, low, high):
    value = config.get(key, default)
    if isinstance(value, bool):
        raise IdentityError("invalid OIDC " + key)
    try:
        value = float(value)
    except (ValueError, TypeError) as exc:
        raise IdentityError("invalid OIDC " + key) from exc
    if not math.isfinite(value) or not low <= value <= high:
        raise IdentityError("invalid OIDC " + key)
    return value


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _transport(config):
    if config.get("tls_verify", True) is not True:
        raise IdentityError("OIDC TLS verification cannot be disabled")
    try:
        path = config.get("ca_file") or config.get("ca_bundle")
        context = ssl.create_default_context(cadata=_protected_file(path, 1048576).decode("ascii")) if path else ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except (OSError, ValueError) as exc:
        raise IdentityError("OIDC trust configuration is unavailable") from exc
    return request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())


def _request_json(config, req, *, allow_oauth_error=False):
    validate_endpoint(config, req.full_url)
    timeout = _bounded_number(config, "http_read_timeout", 5, .1, 10)
    opener = _transport(config)
    try:
        with opener.open(req, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise IdentityError("OIDC response exceeds the supported size")
            if status != 200:
                raise IdentityError("OIDC request returned an unexpected HTTP status")
    except error.HTTPError as exc:
        if not allow_oauth_error or exc.code not in (400, 401):
            raise IdentityError("OIDC request failed (HTTP {})".format(exc.code)) from None
        raw = exc.read(1048577)
        if len(raw) > 1048576:
            raise IdentityError("OIDC response exceeds the supported size") from None
    except (error.URLError, OSError, TimeoutError) as exc:
        raise IdentityError("OIDC provider is unavailable") from exc
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IdentityError("OIDC provider returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise IdentityError("OIDC response must be a JSON object")
    if "error" in payload:
        name = payload["error"]
        if allow_oauth_error and isinstance(name, str) and name in _OAUTH_ERRORS:
            # Never reflect error_description or an arbitrary response body:
            # providers can echo sensitive token/client-secret request fields.
            return {"error": name}
        raise IdentityError("OIDC provider rejected the request")
    return payload


def discover_provider(provider_config, force=False):
    config = _provider(provider_config or {})
    if config.get("tls_verify", True) is not True:
        raise IdentityError("OIDC TLS verification cannot be disabled")
    issuer = config.get("issuer")
    _https_url(issuer)
    url = config.get("discovery_url") or issuer.rstrip("/") + "/.well-known/openid-configuration"
    validate_endpoint(config, url)
    ttl = _bounded_number(config, "discovery_cache_ttl", 300, 0, 3600)
    key = (issuer, url, tuple(sorted(_trusted_origins(config))), config.get("ca_file") or config.get("ca_bundle"))
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if not force and cached and cached["expires_at"] > time.monotonic():
            metadata = copy.deepcopy(cached["metadata"])
        else:
            req = request.Request(url, headers={"Accept": "application/json", "User-Agent": "isolate-oidc/2"})
            metadata = _request_json(config, req)
            if metadata.get("issuer") != issuer:
                raise IdentityError("OIDC discovery issuer differs from configured issuer")
            if not metadata.get("jwks_uri") or not metadata.get("authorization_endpoint") or not metadata.get("token_endpoint"):
                raise IdentityError("OIDC discovery is missing required endpoints")
            for name in _ENDPOINTS:
                if metadata.get(name) is not None:
                    validate_endpoint(config, metadata[name])
            if len(_CACHE) >= 32 and key not in _CACHE:
                _CACHE.pop(next(iter(_CACHE)))
            _CACHE[key] = {"metadata": copy.deepcopy(metadata), "expires_at": time.monotonic() + ttl}
    # Only explicit deployment endpoints override discovered values. Their
    # validation is repeated even when metadata came from the public cache.
    for name in _ENDPOINTS:
        if config.get(name) is not None:
            metadata[name] = validate_endpoint(config, config[name])
    return metadata


def provider_capabilities(provider_config, metadata=None):
    config = _provider(provider_config or {})
    metadata = discover_provider(config) if metadata is None else metadata
    grants = metadata.get("grant_types_supported") or []
    scopes = metadata.get("scopes_supported") or []
    return {"authorization_code": bool(metadata.get("authorization_endpoint") and metadata.get("token_endpoint")),
        "device_authorization": bool(metadata.get("device_authorization_endpoint")),
        "introspection": bool(metadata.get("introspection_endpoint")),
        "backchannel_logout": metadata.get("backchannel_logout_supported") is True,
        "keycloak_admin": config.get("provider", "keycloak") == "keycloak",
        "pkce_s256": "S256" in (metadata.get("code_challenge_methods_supported") or []),
        "refresh_token": "refresh_token" in grants, "offline_access": "offline_access" in scopes}


class OIDCDeviceClient:
    """RFC 8628 client with lazy Discovery and bounded, non-redirecting HTTPS."""

    def __init__(self, config):
        self.config = _provider(config or {})
        self.client_id = self.config.get("client_id")
        if not isinstance(self.client_id, str) or not self.client_id or len(self.client_id) > 512:
            raise IdentityError("OIDC client_id is required")
        _https_url(self.config.get("issuer"))
        self.scopes = self.config.get("scopes") or ["openid", "profile", "email"]
        if (not isinstance(self.scopes, list) or "openid" not in self.scopes or len(self.scopes) > 64
                or any(not isinstance(value, str) or not value or any(char.isspace() or ord(char) < 32 for char in value) for value in self.scopes)):
            raise IdentityError("OIDC scopes must be a bounded list including openid")
        self.poll_timeout = _bounded_number(self.config, "poll_timeout", 300, 1, 900)
        self.device_endpoint = self.config.get("device_authorization_endpoint")
        self.token_endpoint = self.config.get("token_endpoint")
        self.tls_verify = self.config.get("tls_verify", True)
        self._device_expiry = {}

    def _endpoint(self, name):
        value = self.config.get(name)
        if value is None:
            value = discover_provider(self.config).get(name)
        if not value:
            raise IdentityError("OIDC provider does not advertise " + name)
        return validate_endpoint(self.config, value)

    def start(self, acr_values=None, max_age=None):
        payload = {"client_id": self.client_id, "scope": " ".join(self.scopes)}
        if acr_values is not None:
            if not isinstance(acr_values, (tuple, list)) or not acr_values or any(not isinstance(value, str) or not value or any(char.isspace() for char in value) for value in acr_values):
                raise IdentityError("OIDC acr_values must contain nonempty assurance values")
            payload["acr_values"] = " ".join(acr_values)
        if max_age is not None:
            if type(max_age) is not int or max_age < 0:
                raise IdentityError("OIDC max_age must be a nonnegative integer")
            payload["max_age"] = max_age
        self.device_endpoint = self._endpoint("device_authorization_endpoint")
        response = self._post(self.device_endpoint, payload)
        for name, maximum in (("device_code", 8192), ("user_code", 256)):
            if not isinstance(response.get(name), str) or not response[name] or len(response[name]) > maximum:
                raise IdentityError("OIDC device response is invalid")
        _https_url(response.get("verification_uri"), query=True)
        if response.get("verification_uri_complete"):
            _https_url(response["verification_uri_complete"], query=True)
        expiry, interval = response.get("expires_in"), response.get("interval", 5)
        if type(expiry) is not int or not 1 <= expiry <= 86400 or type(interval) is not int or not 1 <= interval <= 60:
            raise IdentityError("OIDC device response contains invalid polling bounds")
        self._device_expiry[response["device_code"]] = time.monotonic() + min(expiry, self.poll_timeout)
        if len(self._device_expiry) > 16:
            self._device_expiry.pop(next(iter(self._device_expiry)))
        return response

    def poll(self, device_code, interval=5):
        if not isinstance(device_code, str) or not device_code or len(device_code) > 8192:
            raise IdentityError("OIDC device code is invalid")
        if type(interval) not in (int, float) or not math.isfinite(interval) or not 1 <= interval <= 60:
            raise IdentityError("OIDC polling interval is invalid")
        self.token_endpoint = self._endpoint("token_endpoint")
        deadline = min(time.monotonic() + self.poll_timeout, self._device_expiry.get(device_code, float("inf")))
        payload = {"grant_type": _DEVICE_GRANT, "device_code": device_code, "client_id": self.client_id}
        while time.monotonic() < deadline:
            response = self._post(self.token_endpoint, payload, allow_error=True)
            if "id_token" in response or "access_token" in response:
                for name in ("id_token", "access_token"):
                    if name in response and (not isinstance(response[name], str) or not response[name] or len(response[name]) > 65536):
                        raise IdentityError("OIDC token response is invalid")
                self._device_expiry.pop(device_code, None)
                return response
            name = response.get("error")
            if name not in ("authorization_pending", "slow_down"):
                raise IdentityError("OIDC device authorization failed" + (": " + name if isinstance(name, str) and name in _OAUTH_ERRORS else ""))
            if name == "slow_down":
                interval += 5
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval, remaining))
        self._device_expiry.pop(device_code, None)
        raise IdentityError("OIDC device authorization timed out")

    def introspect(self, token):
        if not isinstance(token, str) or not token or len(token) > 65536:
            raise IdentityError("OIDC introspection requires a bounded token")
        response = self._post(self._endpoint("introspection_endpoint"), {"token": token, "client_id": self.client_id})
        if response.get("active") is not True:
            raise IdentityError("OIDC token is not active")
        return response

    @staticmethod
    def _format_http_error(exc):
        return "OIDC request failed (HTTP {})".format(exc.code)

    def _post(self, url, payload, allow_error=False):
        validate_endpoint(self.config, url)
        payload = dict(payload)
        if payload.get("client_id", self.client_id) != self.client_id:
            raise IdentityError("OIDC request client_id differs from configuration")
        payload.pop("client_secret", None)
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "isolate-oidc/2"}
        secret = read_client_secret(self.config)
        method = self.config.get("token_endpoint_auth_method", "client_secret_basic" if secret else "none")
        if method == "client_secret_basic":
            if not secret:
                raise IdentityError("OIDC confidential client requires a protected secret")
            material = (parse.quote_plus(self.client_id) + ":" + parse.quote_plus(secret)).encode()
            headers["Authorization"] = "Basic " + base64.b64encode(material).decode()
        elif method == "client_secret_post":
            if not secret:
                raise IdentityError("OIDC confidential client requires a protected secret")
            payload["client_secret"] = secret
        elif method != "none" or secret:
            raise IdentityError("OIDC client authentication method is unsupported or inconsistent")
        req = request.Request(url, data=parse.urlencode(payload).encode(), headers=headers)
        return _request_json(self.config, req, allow_oauth_error=allow_error)
