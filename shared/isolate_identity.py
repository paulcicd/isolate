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
