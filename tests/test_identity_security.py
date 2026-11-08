"""Keycloak logout, assurance and online-revocation regressions."""

import copy
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from joserfc import jwt
from joserfc.jwk import RSAKey
import isolate_identity as identity_module
import isolate_identity_security as security


class Redis:
    def __init__(self):
        self.values = {}
        self.expiries = {}
        self.conflict = False

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

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

    def set(self, key, value, ex=None):
        self.commands.append((key, value, ex))

    def execute(self):
        if self.redis.conflict:
            self.redis.conflict = False
            from redis.exceptions import WatchError
            raise WatchError()
        for key, value, expiry in self.commands:
            self.redis.values[key] = value
            self.redis.expiries[key] = expiry


class IdentitySecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSAKey.generate_key(2048)

    def setUp(self):
        self.redis = Redis()
        self.config = {"keycloak": {"issuer": "https://id.example/realms/isolate", "client_id": "isolate"},
                       "identity_security": {"backchannel_logout": {"enabled": True}}}
        self.claims = {"sub": "alice-sub", "preferred_username": "alice", "sid": "session-a",
                       "iss": self.config["keycloak"]["issuer"], "aud": "isolate",
                       "iat": 900, "exp": 1200, "auth_time": 900}
        self.patch = mock.patch.object(security, "load_jwks", return_value={"keys": [self.key.as_dict(private=False)]})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def token(self, changes=None):
        claims = {"iss": self.claims["iss"], "aud": "isolate", "iat": 1000, "jti": "logout-1",
                  "sub": "alice-sub", "sid": "session-a", "events": {security.LOGOUT_EVENT: {}}}
        claims.update(changes or {})
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode({"alg": "RS256", "typ": "logout+jwt"}, claims, self.key)

    def active(self, **changes):
        return security.assert_identity_active(self.redis, self.config,
            identity_module.normalize_claims(dict(self.claims, **changes)), now=1000)

    def test_signed_logout_revokes_matching_session_and_replay_is_rejected(self):
        self.active()
        result = security.process_backchannel_logout(self.redis, self.config, self.token(), now=1000)
        self.assertEqual(result, {"revoked": "sid", "issued_at": 1000})
        with self.assertRaisesRegex(identity_module.IdentityError, "session has been revoked"):
            self.active()
        self.active(sid="another-session")
        with self.assertRaisesRegex(identity_module.IdentityError, "already been processed"):
            security.process_backchannel_logout(self.redis, self.config, self.token(), now=1000)
        self.assertTrue(all(ttl > 0 for ttl in self.redis.expiries.values()))

    def test_subject_logout_allows_only_newly_issued_tokens_and_preserves_cutoff(self):
        security.process_backchannel_logout(self.redis, self.config, self.token({"sid": None}), now=1000)
        with self.assertRaisesRegex(identity_module.IdentityError, "subject sessions"):
            self.active(sid="another-session")
        security.process_backchannel_logout(self.redis, self.config,
            self.token({"sid": None, "iat": 990, "jti": "older-delivery"}), now=1000)
        with self.assertRaises(identity_module.IdentityError):
            self.active(iat=995)
        with self.assertRaises(identity_module.IdentityError):
            security.assert_identity_active(self.redis, self.config,
                identity_module.normalize_claims(dict(self.claims, iat=1001)), now=1001)
        security.assert_identity_active(self.redis, self.config,
            identity_module.normalize_claims(dict(self.claims, iat=1001, auth_time=1001)), now=1001)

    def test_logout_requires_correct_signature_type_claims_and_freshness(self):
        changes = [{"nonce": "bad"}, {"iss": "https://attacker.example"}, {"aud": "other"},
                   {"sid": None, "sub": None}, {"sid": []}, {"iat": 1001}, {"iat": 600},
                   {"iat": "1000"}, {"iat": True}, {"jti": None}, {"events": {}},
                   {"events": {security.LOGOUT_EVENT: True}}, {"exp": 999}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(identity_module.IdentityError):
                security.process_backchannel_logout(self.redis, self.config, self.token(change), now=1000)
        stranger = RSAKey.generate_key(2048)
        altered = jwt.encode({"alg": "RS256"}, self.claims, stranger)
        with self.assertRaisesRegex(identity_module.IdentityError, "signature"):
            security.process_backchannel_logout(self.redis, self.config, altered, now=1000)
        self.assertEqual(self.redis.values, {})

    def test_logout_event_cannot_authenticate_as_an_identity(self):
        with self.assertRaisesRegex(identity_module.IdentityError, "logout token"):
            identity_module._validate_claims(dict(self.claims, events={security.LOGOUT_EVENT: {}}), self.config["keycloak"], now=1000)

    def test_logout_audience_is_the_oidc_client_even_when_access_token_audience_differs(self):
        self.config["keycloak"]["expected_audience"] = "isolate-api"
        security.process_backchannel_logout(self.redis, self.config, self.token(), now=1000)
        with self.assertRaisesRegex(identity_module.IdentityError, "audience"):
            security.process_backchannel_logout(self.redis, self.config,
                self.token({"jti": "api-audience-logout", "aud": "isolate-api"}), now=1000)

    def test_conflicting_atomic_logout_retries_and_store_failures_deny(self):
        self.redis.conflict = True
        security.process_backchannel_logout(self.redis, self.config, self.token(), now=1000)
        with mock.patch.object(self.redis, "pipeline", side_effect=ConnectionError("offline")):
            with self.assertRaisesRegex(identity_module.IdentityError, "persist"):
                security.process_backchannel_logout(self.redis, self.config, self.token({"jti": "new"}), now=1000)

    def test_revocation_requires_bounded_issued_token_and_verified_https(self):
        for change in ({"iat": None}, {"iat": 1001}, {"exp": 90000}, {"exp": 999}):
            with self.subTest(change=change), self.assertRaises(identity_module.IdentityError):
                self.active(**change)
        for change in ({"tls_verify": False}, {"verify_tokens": False}, {"issuer": "http://id.example"}):
            config = copy.deepcopy(self.config)
            config["keycloak"].update(change)
            with self.assertRaises(identity_module.IdentityError):
                security.process_backchannel_logout(self.redis, config, self.token(), now=1000)

    def test_step_up_checks_signed_assurance_auth_time_and_project(self):
        self.config["identity_security"]["backchannel_logout"]["enabled"] = False
        self.config["identity_security"]["step_up"] = {"enabled": True, "required_projects": ["prod"],
            "acr_values": ["2"], "required_amr": ["otp"], "max_age_seconds": 120}
        person = identity_module.normalize_claims(dict(self.claims, acr="2", amr=["pwd", "otp"]))
        security.assert_identity_active(self.redis, self.config, person, host={"project_name": "prod"}, now=1000)
        for change in ({"acr": "1"}, {"amr": ["pwd"]}, {"auth_time": 879}, {"auth_time": 1001}, {"auth_time": None}):
            weak = identity_module.normalize_claims(dict(person["raw_claims"], **change))
            with self.subTest(change=change), self.assertRaises(security.StepUpRequired) as raised:
                security.assert_identity_active(self.redis, self.config, weak, host={"project_name": "prod"}, now=1000)
            self.assertEqual(raised.exception.acr_values, ["2"])
        security.assert_identity_active(self.redis, self.config,
            identity_module.normalize_claims(self.claims), host={"project_name": "stage"}, now=1000)
        with self.assertRaises(security.StepUpRequired):
            security.assert_identity_active(self.redis, self.config,
                identity_module.normalize_claims(self.claims), decision={"sudo_mode": "sudo-i"}, now=1000)

    def test_online_introspection_requires_active_matching_subject(self):
        self.config["identity_security"]["introspection"] = {"enabled": True}
        self.config["keycloak"]["token_kind"] = "access_token"
        person = identity_module.normalize_claims(self.claims)
        with mock.patch.object(security, "KeycloakDeviceClient") as client:
            client.return_value.introspect.return_value = {"active": True, "sub": "alice-sub", "aud": "isolate"}
            security.assert_identity_active(self.redis, self.config, person, token="verified", now=1000)
            client.return_value.introspect.assert_called_once_with("verified")
            for response in ({"active": False}, {"active": True, "sub": "other"},
                             {"active": True, "sub": "alice-sub", "aud": "other"}, {}):
                client.return_value.introspect.return_value = response
                with self.subTest(response=response), self.assertRaises(identity_module.IdentityError):
                    security.assert_identity_active(self.redis, self.config, person, token="verified", now=1000)

    def test_device_login_can_request_step_up_without_changing_default_payload(self):
        client = identity_module.KeycloakDeviceClient(self.config["keycloak"])
        with mock.patch.object(client, "_post", return_value={}) as post:
            client.start()
            self.assertNotIn("acr_values", post.call_args.args[1])
            client.start(acr_values=["2"], max_age=0)
            self.assertEqual(post.call_args.args[1]["acr_values"], "2")
            self.assertEqual(post.call_args.args[1]["max_age"], 0)

    def test_verified_cache_selects_access_token_and_checks_revocation(self):
        self.config["keycloak"]["token_kind"] = "access_token"
        token = jwt.encode({"alg": "RS256"}, self.claims, self.key)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "identity.json")
            with open(path, "w", encoding="utf-8") as output:
                json.dump({"schema_version": 3, "id_token": "must-not-use", "access_token": token}, output)
            with mock.patch.object(identity_module, "load_jwks", return_value={"keys": [self.key.as_dict(private=False)]}), \
                    mock.patch("isolate_redis.create_redis_client", return_value=self.redis):
                result = identity_module.load_verified_identity(self.config, path, now=1000)
                self.assertEqual(result["keycloak_sub"], "alice-sub")
                security.process_backchannel_logout(self.redis, self.config, self.token(), now=1000)
                with self.assertRaisesRegex(identity_module.IdentityError, "revoked"):
                    identity_module.load_verified_identity(self.config, path, now=1000)

    def test_signing_key_rotation_refreshes_cached_jwks_for_unknown_kid(self):
        rotated = RSAKey.generate_key(2048, parameters={"kid": "rotated"})
        current = {"keys": [rotated.as_dict(private=False)]}
        token = jwt.encode({"alg": "RS256", "kid": "rotated"}, self.claims, rotated)
        with tempfile.TemporaryDirectory() as directory:
            kc = dict(self.config["keycloak"], jwks_cache_path=os.path.join(directory, "jwks.json"))
            identity_module._write_jwks_cache(kc["jwks_cache_path"], {"keys": [self.key.as_dict(private=False)]})
            with mock.patch.object(identity_module, "_fetch_jwks", return_value=current) as fetch:
                verified = identity_module.verify_jwt_claims(token, kc, now=1000)
                self.assertEqual(verified["sub"], "alice-sub")
                fetch.assert_called_once()
                identity_module.verify_jwt_claims(token, kc, now=1000)
                fetch.assert_called_once()

    def test_bad_known_key_signatures_do_not_refresh_and_unknown_kids_are_rate_limited(self):
        known = RSAKey.generate_key(2048, parameters={"kid": "known"})
        stranger = RSAKey.generate_key(2048)
        keys = {"keys": [known.as_dict(private=False)]}
        bad_known = jwt.encode({"alg": "RS256", "kid": "known"}, self.claims, stranger)
        bad_unknown = jwt.encode({"alg": "RS256", "kid": "missing"}, self.claims, stranger)
        with tempfile.TemporaryDirectory() as directory:
            kc = dict(self.config["keycloak"], jwks_cache_path=os.path.join(directory, "jwks.json"))
            identity_module._write_jwks_cache(kc["jwks_cache_path"], keys)
            with mock.patch.object(identity_module, "_fetch_jwks", return_value=keys) as fetch:
                with self.assertRaises(identity_module.IdentityError):
                    identity_module.verify_jwt_claims(bad_known, kc, now=1000)
                fetch.assert_not_called()
                for _ in range(2):
                    with self.assertRaises(identity_module.IdentityError):
                        identity_module.verify_jwt_claims(bad_unknown, kc, now=1000)
                fetch.assert_called_once()
            with mock.patch.object(identity_module, "refresh_jwks_cache") as refresh:
                identity_module.refresh_jwks_for_unknown_kid(bad_unknown, self.config["keycloak"], keys)
                refresh.assert_not_called()

    def test_logout_signing_key_rotation_uses_same_bounded_refresh(self):
        rotated = RSAKey.generate_key(2048, parameters={"kid": "rotated-logout"})
        token = jwt.encode({"alg": "RS256", "kid": "rotated-logout", "typ": "logout+jwt"},
            {"iss": self.claims["iss"], "aud": "isolate", "iat": 1000, "jti": "new-key-logout",
             "sid": "session-a", "events": {security.LOGOUT_EVENT: {}}}, rotated)
        with tempfile.TemporaryDirectory() as directory:
            self.config["keycloak"]["jwks_cache_path"] = os.path.join(directory, "jwks.json")
            identity_module._write_jwks_cache(self.config["keycloak"]["jwks_cache_path"],
                {"keys": [self.key.as_dict(private=False)]})
            with mock.patch.object(identity_module, "_fetch_jwks", return_value={"keys": [rotated.as_dict(private=False)]}) as fetch:
                security.process_backchannel_logout(self.redis, self.config, token, now=1000)
                fetch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
