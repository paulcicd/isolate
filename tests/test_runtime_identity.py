"""Use real signed Keycloak-shaped tokens across the shared and legacy paths."""

import copy
import fnmatch
import json
import os
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from flask import Flask
from joserfc import jwt
from joserfc.jwk import RSAKey
from isolate_api import register_api_routes
import isolate_connection_auth as legacy
from isolate_config import DEFAULT_CONFIG
import isolate_identity as identity_module
import isolate_identity_security as security
from isolate_runtime import Runtime


class Redis:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def delete(self, key):
        return self.values.pop(key, None) is not None

    def getdel(self, key):
        return self.values.pop(key, None)

    def keys(self, pattern):
        return [key for key in self.values if fnmatch.fnmatchcase(key, pattern)]

    def scan_iter(self, match="*"):
        return iter(self.keys(match))

    def expire(self, key, seconds):
        return key in self.values

    def pipeline(self):
        return Pipeline(self)


class Pipeline:
    def __init__(self, redis):
        self.redis, self.commands = redis, []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def watch(self, *args):
        pass

    def get(self, key):
        return self.redis.get(key)

    def multi(self):
        pass

    def set(self, key, value, **kwargs):
        self.commands.append(lambda: self.redis.set(key, value, **kwargs))

    def delete(self, key):
        self.commands.append(lambda: self.redis.delete(key))

    def expire(self, key, seconds):
        self.commands.append(lambda: self.redis.expire(key, seconds))

    def execute(self):
        return [command() for command in self.commands]


class RuntimeIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSAKey.generate_key(2048, parameters={"kid": "keycloak-key"})

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = int(time.time())
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self.config.update(gateway={"enabled": True}, api={"enabled": True},
                           cluster={"node_id": "test-node"},
                           identity_security={"backchannel_logout": {"enabled": True}})
        self.config["keycloak"].update(issuer="https://id.example/realms/company", client_id="isolate",
            expected_audience="isolate", jwks_cache_path=os.path.join(self.directory.name, "jwks.json"))
        self.config["ssh"]["default_sudo_mode"] = "none"
        self.config["logging"]["base_path"] = os.path.join(self.directory.name, "logs")
        identity_module._write_jwks_cache(self.config["keycloak"]["jwks_cache_path"],
            {"keys": [self.key.as_dict(private=False)]})
        self.claims = {"iss": self.config["keycloak"]["issuer"], "aud": "isolate", "sub": "stable-alice",
            "preferred_username": "alice", "groups": ["Support"], "sid": "keycloak-session",
            "iat": self.now, "auth_time": self.now, "exp": self.now + 600}
        self.redis = Redis()
        self.redis.set("server_10001", json.dumps({"server_id": "10001", "server_name": "prod-one",
            "server_ip": "192.0.2.10", "server_port": 22, "project_name": "prod"}))
        self.redis.set("grant_1", json.dumps({"id": "1", "subject": "group", "name": "Support",
            "project": "prod", "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh"]}))
        self.runtime = Runtime(self.config, self.redis)

    def token(self, **changes):
        return jwt.encode({"alg": "RS256", "kid": "keycloak-key"}, dict(self.claims, **changes), self.key)

    def logout(self):
        return jwt.encode({"alg": "RS256", "kid": "keycloak-key", "typ": "logout+jwt"},
            {"iss": self.claims["iss"], "aud": "isolate", "sid": self.claims["sid"],
             "iat": self.now, "jti": "logout-request", "events": {security.LOGOUT_EVENT: {}}}, self.key)

    def test_logout_denies_live_recheck_new_ticket_and_legacy_connection(self):
        token = self.token()
        context = self.runtime.authorize(token, "10001")
        self.runtime.prepare(context)
        try:
            self.runtime.recheck(context)
            security.process_backchannel_logout(self.redis, self.config, self.logout())
            with self.assertRaisesRegex(identity_module.IdentityError, "revoked"):
                self.runtime.recheck(context)
            with self.assertRaisesRegex(identity_module.IdentityError, "revoked"):
                self.runtime.create_ticket(token, "10001")
            args = SimpleNamespace(host_id="10001", hostname=["192.0.2.10"], port=22,
                user=["support"], nosudo=True, project="prod", human_user="alice",
                keycloak_sub="stable-alice", proxy_host=None, proxy_port=None, proxy_user=None)
            with self.assertRaisesRegex(identity_module.IdentityError, "revoked"):
                legacy.authorize_connection(args, token, self.config, self.redis, "alice")
        finally:
            self.runtime.finish(context)

    def test_step_up_is_required_before_ticket_creation_and_again_on_consumption(self):
        self.config["identity_security"]["step_up"] = {"enabled": True, "required_projects": ["prod"],
            "acr_values": ["2"], "max_age_seconds": 300}
        with self.assertRaises(security.StepUpRequired):
            self.runtime.create_ticket(self.token(acr="1"), "10001")
        issued = self.runtime.create_ticket(self.token(acr="2"), "10001")
        self.config["identity_security"]["step_up"]["acr_values"] = ["3"]
        with self.assertRaises(security.StepUpRequired):
            self.runtime.consume_ticket(issued["ticket"])
        self.assertFalse(any(key.startswith("isolate_ticket_") for key in self.redis.values))

    def test_signature_issuer_and_audience_are_required_for_api_identity(self):
        self.assertEqual(self.runtime.authenticate(self.token())["keycloak_sub"], "stable-alice")
        for changes in ({"aud": "another-client"}, {"iss": "https://attacker.example"}, {"exp": self.now - 1}):
            with self.subTest(changes=changes), self.assertRaises(identity_module.IdentityError):
                self.runtime.authenticate(self.token(**changes))
        with self.assertRaises(identity_module.IdentityError):
            self.runtime.authenticate(self.logout())

    def api(self):
        app = Flask(__name__)
        app.testing = True
        register_api_routes(app, self.config, lambda _: self.redis, lambda: None,
                            lambda: "csrf", lambda: None)
        return app.test_client()

    def test_backchannel_callback_accepts_only_valid_signed_event_and_retriable_failures(self):
        client = self.api()
        response = client.post("/auth/backchannel-logout", data={"logout_token": self.token()})
        self.assertEqual(response.status_code, 400)
        with mock.patch.object(self.redis, "pipeline", side_effect=ConnectionError("store unavailable")):
            response = client.post("/auth/backchannel-logout", data={"logout_token": self.logout()})
        self.assertEqual(response.status_code, 503)
        response = client.post("/auth/backchannel-logout", data={"logout_token": self.logout()})
        self.assertEqual(response.status_code, 200)
        response = client.get("/api/v1/me", headers={"Authorization": "Bearer " + self.token()})
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
