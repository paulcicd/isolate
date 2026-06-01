#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identity helpers for Keycloak/OIDC-backed bastion sessions."""

import json
import base64
import time
import uuid
from urllib import parse, request


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
    def _post(url, payload, allow_error=False):
        data = parse.urlencode(payload).encode("utf-8")
        req = request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            if allow_error and hasattr(exc, "read"):
                return json.loads(exc.read().decode("utf-8"))
            raise
