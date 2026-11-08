"""Provider-neutral discovery, claim namespaces and bounded OAuth transport."""

import copy
import datetime
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib import parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from joserfc import jwt
from joserfc.jwk import RSAKey
from isolate_identity import IdentityError, verify_jwt_claims
import isolate_identity as identity_module
import isolate_oidc as oidc


class ClaimsTest(unittest.TestCase):
    def test_generic_numeric_dates_and_id_token_authorized_party_fail_closed(self):
        key = RSAKey.generate_key(2048)
        now = int(time.time())
        base = {"iss": "https://id.example", "sub": "subject", "aud": "isolate", "iat": now, "exp": now + 600}
        config = {"provider": "oidc", "issuer": base["iss"], "client_id": "isolate"}
        for changes in ({"exp": "9999999999"}, {"exp": True}, {"nbf": []}, {"iat": now + 100},
                        {"iat": None}, {"aud": ["isolate", "another"]}, {"azp": "another"}, {"aud": ["isolate", 3]}):
            with self.subTest(changes=changes), mock.patch("isolate_identity.load_jwks", return_value={"keys": [key.as_dict(private=False)]}):
                token = jwt.encode({"alg": "RS256"}, dict(base, **changes), key)
                with self.assertRaises(IdentityError):
                    verify_jwt_claims(token, config)
        token = jwt.encode({"alg": "RS256"}, dict(base, aud=["isolate", "another"], azp="isolate"), key)
        with mock.patch("isolate_identity.load_jwks", return_value={"keys": [key.as_dict(private=False)]}):
            self.assertEqual(verify_jwt_claims(token, config)["azp"], "isolate")

    def test_legacy_provider_is_selected_without_merging_oidc_secret(self):
        result = oidc.identity_provider_config({"keycloak": {"issuer": "https://old.example/realm/", "client_id": "old", "client_secret": "old-secret"},
            "oidc": {"enabled": False, "issuer": "https://new.example", "client_secret": "new-secret"}})
        self.assertEqual(result["provider"], "keycloak")
        self.assertEqual(result["issuer"], "https://old.example/realm")
        new = oidc.identity_provider_config({"keycloak": result, "oidc": {"enabled": True, "issuer": "https://new.example", "client_id": "new"}})
        self.assertEqual(new["provider"], "oidc")
        self.assertNotIn("client_secret", new)
        with self.assertRaises(IdentityError):
            oidc.identity_provider_config({"oidc": {"enabled": "false"}})

    def test_signed_generic_claims_map_nested_and_uri_claims_without_cross_issuer_ownership(self):
        key = RSAKey.generate_key(2048)
        claims = {"iss": "https://id.example/", "aud": "isolate", "sub": "same-sub", "iat": int(time.time()), "exp": int(time.time()) + 600,
            "mail": "alice@example.org", "organization": {"teams": ["Support", "Support"]},
            "https://claims.example/roles": ["reviewer"]}
        config = {"provider": "oidc", "issuer": claims["iss"], "client_id": "isolate",
            "claim_mapping": {"username": "mail", "groups": "organization.teams", "roles": "/https:~1~1claims.example~1roles"}}
        token = jwt.encode({"alg": "RS256"}, claims, key)
        with mock.patch("isolate_identity.load_jwks", return_value={"keys": [key.as_dict(private=False)]}):
            verified = verify_jwt_claims(token, config)
        normalized = oidc.normalize_identity_claims(verified, config)
        self.assertEqual(normalized["groups"], ["Support"])
        self.assertEqual(normalized["roles"], ["reviewer"])
        self.assertEqual(normalized["username"], "alice@example.org")
        self.assertEqual(normalized["oidc_sub"], "same-sub")
        self.assertTrue(normalized["keycloak_sub"].startswith("oidc:"))
        alternate = dict(claims, iss="https://another.example")
        other = oidc.normalize_identity_claims(alternate, dict(config, issuer=alternate["iss"]))
        self.assertNotEqual(normalized["keycloak_sub"], other["keycloak_sub"])
        with self.assertRaises(IdentityError):
            oidc.normalize_identity_claims(alternate, config)
        with self.assertRaises(IdentityError):
            oidc.normalize_identity_claims(claims, {"provider": "oidc"})

    def test_legacy_subject_and_realm_roles_are_preserved_but_generic_roles_are_flat(self):
        claims = {"sub": "stable-old-sub", "iss": "https://id.example/realm", "preferred_username": "alice",
            "groups": ["Support"], "realm_access": {"roles": ["admin"]}, "roles": ["reader"]}
        legacy = oidc.normalize_identity_claims(claims, {"provider": "keycloak", "issuer": claims["iss"]})
        generic = oidc.normalize_identity_claims(claims, {"provider": "oidc", "issuer": claims["iss"]})
        self.assertEqual(legacy["keycloak_sub"], "stable-old-sub")
        self.assertEqual(legacy["roles"], ["admin"])
        self.assertEqual(generic["roles"], ["reader"])

    def test_malformed_privilege_claims_fail_closed(self):
        config = {"provider": "oidc", "issuer": "https://id.example"}
        base = {"iss": config["issuer"], "sub": "a", "preferred_username": "alice"}
        for changes in ({"groups": [1]}, {"roles": {"admin": True}}, {"groups": ["bad\nname"]}, {"sub": ""}):
            with self.subTest(changes=changes), self.assertRaises(IdentityError):
                oidc.normalize_identity_claims(dict(base, **changes), config)


class ProviderTransportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(key, hashes.SHA256()))
        cls.cert = root / "ca.pem"
        cls.cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        private = root / "server.key"
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        owner = cls
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def respond(self, value, code=200):
                material = json.dumps(value).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(material)))
                self.end_headers()
                self.wfile.write(material)
            def do_GET(self):
                owner.calls.append(("GET", self.path, {}, {}))
                if owner.redirect:
                    self.send_response(302)
                    self.send_header("Location", owner.issuer + "/must-not-follow")
                    self.end_headers()
                    return
                self.respond(owner.metadata)
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.calls.append(("POST", self.path, parse.parse_qs(body.decode()), dict(self.headers)))
                if owner.redirect:
                    self.send_response(302)
                    self.send_header("Location", owner.issuer + "/must-not-follow")
                    self.end_headers()
                    return
                value = owner.responses.pop(0)
                self.respond(value, 400 if "error" in value else 200)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert), str(private))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.issuer = "https://localhost:" + str(cls.server.server_port) + "/tenant"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.directory.cleanup()

    def setUp(self):
        cls = type(self)
        cls.calls, cls.responses, cls.redirect = [], [], False
        cls.metadata = {"issuer": cls.issuer, "authorization_endpoint": cls.issuer + "/authorize", "token_endpoint": cls.issuer + "/token",
            "jwks_uri": cls.issuer + "/keys", "device_authorization_endpoint": cls.issuer + "/device",
            "introspection_endpoint": cls.issuer + "/introspection", "code_challenge_methods_supported": ["S256"],
            "backchannel_logout_supported": True, "grant_types_supported": ["authorization_code", "refresh_token"], "scopes_supported": ["openid"]}
        self.config = {"provider": "oidc", "issuer": cls.issuer, "client_id": "test-client", "ca_file": str(cls.cert), "http_read_timeout": 2}
        with oidc._CACHE_LOCK:
            oidc._CACHE.clear()

    def test_real_verified_https_discovery_uses_exact_issuer_and_bounded_cache(self):
        metadata = oidc.discover_provider(self.config)
        self.assertEqual(metadata["issuer"], self.issuer)
        metadata["token_endpoint"] = "https://evil.invalid/token"
        self.assertEqual(oidc.discover_provider(self.config)["token_endpoint"], self.issuer + "/token")
        self.assertEqual(len(self.calls), 1)
        capability = oidc.provider_capabilities(self.config)
        self.assertTrue(capability["device_authorization"])
        self.assertTrue(capability["pkce_s256"])
        self.assertFalse(capability["keycloak_admin"])

    def test_discovery_rejects_issuer_mismatch_untrusted_origin_and_insecure_endpoint(self):
        for field, value in (("issuer", self.issuer + "/"), ("token_endpoint", "https://evil.invalid/token"), ("jwks_uri", "http://localhost/keys")):
            with self.subTest(field=field):
                original = self.metadata[field]
                self.metadata[field] = value
                with self.assertRaises(IdentityError):
                    oidc.discover_provider(self.config, force=True)
                self.metadata[field] = original
        self.assertTrue(all(call[1] == "/tenant/.well-known/openid-configuration" for call in self.calls))

    def test_cross_origin_endpoints_require_explicit_trust(self):
        self.metadata["jwks_uri"] = "https://keys.example/keys"
        with self.assertRaises(IdentityError):
            oidc.discover_provider(self.config)
        metadata = oidc.discover_provider(dict(self.config, trusted_endpoint_origins=["https://keys.example"]))
        self.assertEqual(metadata["jwks_uri"], "https://keys.example/keys")

    def test_untrusted_certificate_and_tls_bypass_are_rejected(self):
        with self.assertRaises(IdentityError):
            oidc.discover_provider(dict(self.config, ca_file=None))
        with self.assertRaises(IdentityError):
            oidc.discover_provider(dict(self.config, tls_verify=False))
        oidc.discover_provider(self.config)
        with self.assertRaises(IdentityError):
            oidc.discover_provider(dict(self.config, tls_verify=False))

    def test_redirects_never_follow_metadata_or_credential_requests(self):
        type(self).redirect = True
        with self.assertRaises(IdentityError):
            oidc.discover_provider(self.config)
        client = oidc.OIDCDeviceClient(dict(self.config, token_endpoint=self.issuer + "/token", client_secret="never-return-this"))
        with self.assertRaises(IdentityError) as captured:
            client._post(client.token_endpoint, {"client_id": "test-client"})
        self.assertNotIn("never-return-this", str(captured.exception))
        self.assertFalse(any(call[1] == "/tenant/must-not-follow" for call in self.calls))
        self.assertEqual(len(self.calls), 2)

    def test_oversized_metadata_is_rejected(self):
        self.metadata["padding"] = "x" * 1048576
        with self.assertRaisesRegex(IdentityError, "size"):
            oidc.discover_provider(self.config)

    def test_device_flow_uses_discovered_endpoints_and_form_client_auth(self):
        type(self).responses = [{"device_code": "private-device-code", "user_code": "ABCD-1234", "verification_uri": "https://login.example/device", "expires_in": 60}, {"access_token": "opaque-token", "id_token": "signed-token"}]
        client = oidc.OIDCDeviceClient(dict(self.config, client_secret="client-secret"))
        started = client.start()
        result = client.poll(started["device_code"])
        self.assertEqual(result["id_token"], "signed-token")
        posts = [call for call in self.calls if call[0] == "POST"]
        self.assertEqual([call[1] for call in posts], ["/tenant/device", "/tenant/token"])
        self.assertNotIn("client_secret", posts[0][2])
        self.assertTrue(posts[0][3]["Authorization"].startswith("Basic "))
        self.assertEqual(posts[1][2]["grant_type"], ["urn:ietf:params:oauth:grant-type:device_code"])

    def test_missing_device_flow_does_not_prevent_introspection(self):
        del self.metadata["device_authorization_endpoint"]
        type(self).responses = [{"active": True, "sub": "raw-sub"}]
        client = oidc.OIDCDeviceClient(self.config)
        self.assertEqual(client.introspect("verified-bearer")["sub"], "raw-sub")
        with self.assertRaisesRegex(IdentityError, "device_authorization_endpoint"):
            client.start()

    def test_secret_file_is_lazy_private_and_not_reflected_in_errors(self):
        missing = str(Path(self.directory.name) / "missing-secret")
        client = oidc.OIDCDeviceClient(dict(self.config, client_secret_file=missing))
        self.assertIsInstance(client, oidc.OIDCDeviceClient)
        with self.assertRaises(IdentityError):
            client._post(self.issuer + "/token", {})
        path = Path(self.directory.name) / "client-secret"
        path.write_text("unlogged-private-client-secret\n")
        path.chmod(0o600)
        self.assertEqual(oidc.read_client_secret({"client_secret_file": str(path)}), "unlogged-private-client-secret")
        if os.name == "posix":
            path.chmod(0o644)
            with self.assertRaises(IdentityError):
                oidc.read_client_secret({"client_secret_file": str(path)})

    def test_arbitrary_oauth_error_objects_do_not_escape_safe_boundary(self):
        type(self).responses = [{"error": {"description": "private-token"}}]
        client = oidc.OIDCDeviceClient(self.config)
        with self.assertRaises(IdentityError) as captured:
            client._post(self.issuer + "/token", {}, allow_error=True)
        self.assertNotIn("private-token", str(captured.exception))


class DevicePollingTest(unittest.TestCase):
    def setUp(self):
        self.client = oidc.OIDCDeviceClient({"provider": "oidc", "issuer": "https://issuer.example", "client_id": "isolate",
            "token_endpoint": "https://issuer.example/oauth/token", "poll_timeout": 60})

    def test_pending_slow_down_and_grant_deadline(self):
        clock = {"now": 100.0, "sleeps": []}
        def sleep(value):
            clock["sleeps"].append(value)
            clock["now"] += value
        fake_time = SimpleNamespace(monotonic=lambda: clock["now"], sleep=sleep)
        with mock.patch.object(oidc, "time", fake_time), mock.patch.object(self.client, "_post", side_effect=[
                {"error": "authorization_pending"}, {"error": "slow_down"}, {"id_token": "signed"}]):
            self.assertEqual(self.client.poll("device", interval=2)["id_token"], "signed")
        self.assertEqual(clock["sleeps"], [2, 7])
        self.client._device_expiry["device"] = clock["now"] + 1
        with mock.patch.object(oidc, "time", fake_time), mock.patch.object(self.client, "_post", return_value={"error": "authorization_pending"}):
            with self.assertRaisesRegex(IdentityError, "timed out"):
                self.client.poll("device", interval=5)
        self.assertEqual(clock["sleeps"][-1], 1)

    def test_denied_error_does_not_reflect_provider_descriptions(self):
        with mock.patch.object(self.client, "_post", return_value={"error": "access_denied", "error_description": "token=do-not-print"}):
            with self.assertRaises(IdentityError) as captured:
                self.client.poll("device")
        self.assertNotIn("do-not-print", str(captured.exception))


class GenericIdentityIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSAKey.generate_key(2048, parameters={"kid": "generic-identity-test"})

    def setUp(self):
        import fakeredis
        from isolate_identity_binding import bind_provider
        self.store = fakeredis.FakeRedis(decode_responses=True)
        self.config = {"oidc": {"enabled": True, "issuer": "https://id.example/tenant/", "client_id": "isolate",
            "token_kind": "access_token"}, "keycloak": {"issuer": "https://retired.example/realms/old", "client_id": "old"},
            "identity_security": {"backchannel_logout": {"enabled": True}}}
        self.claims = {"iss": self.config["oidc"]["issuer"], "aud": "isolate", "sub": "raw-stable-sub",
            "preferred_username": "alice", "roles": ["reader"], "groups": ["Support"],
            "iat": int(time.time()) - 5, "auth_time": int(time.time()) - 5, "exp": int(time.time()) + 300}
        bind_provider(self.config, self.store, actor="fixture", reason="new provider", reconciled=True, drained=True)
        patch = mock.patch("isolate_identity.load_jwks", return_value={"keys": [self.key.as_dict(private=False)]})
        patch.start()
        self.addCleanup(patch.stop)
        security_patch = mock.patch("isolate_identity_security.load_jwks", return_value={"keys": [self.key.as_dict(private=False)]})
        security_patch.start()
        self.addCleanup(security_patch.stop)

    def token(self, changes=None):
        return jwt.encode({"alg": "RS256", "kid": "generic-identity-test"}, dict(self.claims, **(changes or {})), self.key)

    def test_generic_runtime_subject_logout_uses_raw_subject_and_single_issuer(self):
        from isolate_runtime import Runtime
        import isolate_identity_security as security
        runtime = Runtime(self.config, self.store)
        person = runtime.authenticate(self.token())
        self.assertEqual(person["oidc_sub"], "raw-stable-sub")
        self.assertEqual(person["roles"], ["reader"])
        with self.assertRaises(IdentityError):
            runtime.authenticate(self.token({"iss": self.config["keycloak"]["issuer"]}))
        logout_claims = {"iss": self.claims["iss"], "aud": "isolate", "sub": self.claims["sub"],
            "iat": int(time.time()), "jti": "logout-generic", "events": {security.LOGOUT_EVENT: {}}}
        token = jwt.encode({"alg": "RS256", "kid": "generic-identity-test"}, logout_claims, self.key)
        security.process_backchannel_logout(self.store, self.config, token)
        with self.assertRaisesRegex(IdentityError, "subject sessions"):
            runtime.authenticate(self.token())

    def test_generic_introspection_matches_raw_subject_and_admin_membership_is_explicitly_unsupported(self):
        from isolate_runtime import Runtime
        self.config["identity_security"]["introspection"] = {"enabled": True}
        with mock.patch.object(oidc.OIDCDeviceClient, "introspect", return_value={"active": True, "sub": self.claims["sub"], "aud": "isolate"}) as check:
            person = Runtime(self.config, self.store).authenticate(self.token())
            check.assert_called_once()
        self.assertNotEqual(person["keycloak_sub"], self.claims["sub"])
        self.config["identity_security"]["introspection"]["enabled"] = False
        self.config["identity_security"]["membership"] = {"enabled": True}
        with self.assertRaisesRegex(IdentityError, "does not support Keycloak Admin"):
            Runtime(self.config, self.store).authenticate(self.token())

    def test_mcp_and_job_audience_overrides_cannot_change_selected_issuer(self):
        from isolate_delegation import DelegationDenied, verified_token
        from isolate_mcp import mcp_keycloak_config
        self.config["mcp"] = {"enabled": True, "expected_audience": "isolate-mcp"}
        person, effective, audience = verified_token(self.config, self.token({"aud": "isolate-mcp"}))
        self.assertEqual(audience, "isolate-mcp")
        self.assertEqual(oidc.identity_provider_config(effective)["issuer"], self.claims["iss"])
        self.assertTrue(person["keycloak_sub"].startswith("oidc:"))
        self.config["mcp"]["issuer"] = "https://another.example"
        with self.assertRaises(DelegationDenied):
            verified_token(self.config, self.token())
        with self.assertRaises(IdentityError):
            mcp_keycloak_config(self.config)

    def test_jwks_cache_is_bound_to_deployment_issuer_and_origins(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = oidc.identity_provider_config(self.config)
            provider["jwks_cache_path"] = str(Path(directory) / "keys.json")
            keys = {"keys": [self.key.as_dict(private=False)]}
            identity_module._write_jwks_cache(provider["jwks_cache_path"], keys, provider)
            self.assertEqual(identity_module._read_jwks_cache(provider["jwks_cache_path"], 3600, provider), keys)
            for changed in (dict(provider, issuer="https://another.example"),
                    dict(provider, trusted_endpoint_origins=["https://keys.example"])):
                self.assertIsNone(identity_module._read_jwks_cache(provider["jwks_cache_path"], 3600, changed))
            identity_module._write_jwks_cache(provider["jwks_cache_path"], keys)
            self.assertIsNone(identity_module._read_jwks_cache(provider["jwks_cache_path"], 3600, provider))


if __name__ == "__main__":
    unittest.main()
