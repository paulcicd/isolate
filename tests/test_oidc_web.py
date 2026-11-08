"""Real Authlib code/PKCE login against a TLS-only provider-neutral fixture."""

import base64
import copy
import datetime
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib import parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import fakeredis
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from joserfc import jwt
from joserfc.jwk import RSAKey
from isolate_config import DEFAULT_CONFIG
from isolate_identity_binding import bind_provider
import isolate_web as web


class GenericBrowserOIDCTest(unittest.TestCase):
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
        cls.ca_file = root / "ca.pem"
        cls.ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        private = root / "tls.key"
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.signing_key = RSAKey.generate_key(2048, parameters={"kid": "synthetic-idp-rsa"})
        owner = cls

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, value, status=200):
                data = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = parse.urlsplit(self.path)
                owner.calls.append(("GET", url.path))
                if url.path == "/organization/.well-known/openid-configuration":
                    self.respond(owner.metadata)
                elif url.path == "/rsa-9xz/signing-material":
                    self.respond({"keys": [owner.signing_key.as_dict(private=False)]})
                elif url.path == "/choose-6mq/account":
                    values = {name: entries[0] for name, entries in parse.parse_qs(url.query).items()}
                    if (values.get("client_id") != "isolate-browser" or values.get("response_type") != "code"
                            or values.get("code_challenge_method") != "S256" or not values.get("code_challenge")
                            or not values.get("nonce") or not values.get("state")
                            or values.get("redirect_uri") != "https://bastion.example/auth/callback"):
                        self.respond({"error": "invalid_request"}, 400)
                        return
                    code = secrets.token_urlsafe(24)
                    owner.codes[code] = values
                    self.send_response(302)
                    self.send_header("Location", values["redirect_uri"] + "?" + parse.urlencode({"code": code, "state": values["state"]}))
                    self.end_headers()
                else:
                    self.respond({"error": "invalid_request"}, 404)

            def do_POST(self):
                owner.calls.append(("POST", self.path))
                if self.path != "/exchange-2dt/code":
                    self.respond({"error": "invalid_request"}, 404)
                    return
                values = {name: entries[0] for name, entries in parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
                granted = owner.codes.pop(values.get("code"), None)
                verifier = values.get("code_verifier", "")
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                if (not granted or not verifier or challenge != granted["code_challenge"]
                        or values.get("redirect_uri") != granted["redirect_uri"]
                        or values.get("grant_type") != "authorization_code" or values.get("client_id") != "isolate-browser"):
                    self.respond({"error": "invalid_grant"}, 400)
                    return
                owner.pkce_verified = True
                claims = {"iss": owner.issuer, "sub": "raw-browser-subject", "aud": "isolate-browser",
                    "iat": int(time.time()), "exp": int(time.time()) + 300,
                    "nonce": "incorrect-nonce" if owner.corrupt_nonce else granted["nonce"],
                    "profile": {"login": "alice"}, "teams": ["Support"], "permissions": ["reviewer"]}
                access_claims = dict(claims, sub=owner.access_subject, aud="isolate-api", teams=["API-Team"], permissions=["api-role"])
                access_token = jwt.encode({"alg": "RS256", "kid": "synthetic-idp-rsa"}, access_claims, owner.signing_key)
                self.respond({"token_type": "Bearer", "access_token": access_token,
                    "expires_in": 300, "id_token": jwt.encode({"alg": "RS256", "kid": "synthetic-idp-rsa"}, claims, owner.signing_key)})

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.ca_file), str(private))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        base = "https://localhost:" + str(cls.server.server_port)
        cls.issuer = base + "/organization"
        cls.metadata = {"issuer": cls.issuer, "authorization_endpoint": base + "/choose-6mq/account",
            "token_endpoint": base + "/exchange-2dt/code", "jwks_uri": base + "/rsa-9xz/signing-material",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["none"], "code_challenge_methods_supported": ["S256"]}
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.directory.cleanup()

    def setUp(self):
        type(self).codes, type(self).calls = {}, []
        type(self).pkce_verified, type(self).corrupt_nonce = False, False
        type(self).access_subject = "raw-browser-subject"
        self.store = fakeredis.FakeRedis(decode_responses=True)
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self.config["oidc"] = {"enabled": True, "issuer": self.issuer, "client_id": "isolate-browser",
            "ca_file": str(self.ca_file), "token_endpoint_auth_method": "none", "http_read_timeout": 2,
            "claim_mapping": {"username": "profile.login", "groups": "teams", "roles": "permissions"}}
        self.config["dashboard"].update(public_url="https://bastion.example", self_service_groups=["Support"], secret_key_file=None)
        self.config["logging"]["base_path"] = self.directory.name
        self.redis_patch = mock.patch.object(web, "redis_client", return_value=self.store)
        self.redis_patch.start()
        self.addCleanup(self.redis_patch.stop)
        bind_provider(self.config, self.store, actor="test-operator", reason="new isolated fixture", reconciled=True, drained=True)
        self.app = web.create_app(self.config)
        self.client = self.app.test_client()

    def authorize(self):
        started = self.client.get("/login", base_url="https://bastion.example")
        self.assertEqual(started.status_code, 302)
        self.assertTrue(started.location.startswith(self.metadata["authorization_endpoint"] + "?"))
        approved = requests.get(started.location, verify=str(self.ca_file), allow_redirects=False, timeout=3)
        self.assertEqual(approved.status_code, 302)
        return approved.headers["Location"]

    def test_real_authlib_pkce_signature_nonce_custom_claims_and_cookie_issuer_fence(self):
        callback = self.authorize()
        response = self.client.get(callback)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.pkce_verified)
        with self.client.session_transaction(base_url="https://bastion.example") as session:
            identity = session["identity"]
            self.assertEqual(identity["username"], "alice")
            self.assertEqual(identity["groups"], ["Support"])
            self.assertEqual(identity["roles"], ["reviewer"])
            self.assertEqual(identity["oidc_sub"], "raw-browser-subject")
            self.assertTrue(identity["keycloak_sub"].startswith("oidc:"))
            self.assertTrue(session["runtime_session"])
            self.assertNotIn("id_token", session)
        self.assertEqual(self.client.get("/me", base_url="https://bastion.example").status_code, 200)
        self.assertTrue(any(path == "/exchange-2dt/code" for _, path in self.calls))
        self.assertFalse(any("/protocol/openid-connect/" in path for _, path in self.calls))
        changed = copy.deepcopy(self.config)
        changed["oidc"]["issuer"] += "/different-tenant"
        other = web.create_app(changed).test_client()
        cookie = self.client.get_cookie("session", domain="bastion.example")
        other.set_cookie("session", cookie.value, domain="bastion.example")
        self.assertEqual(other.get("/me", base_url="https://bastion.example").status_code, 302)
        with other.session_transaction(base_url="https://bastion.example") as session:
            self.assertNotIn("identity", session)
        bind_provider(changed, self.store, actor="fixture", reason="explicit IdP change", reconciled=True, drained=True)
        self.assertEqual(self.client.get("/me", base_url="https://bastion.example").status_code, 302)

    def test_nonce_mismatch_fails_closed_after_real_token_exchange(self):
        type(self).corrupt_nonce = True
        response = self.client.get(self.authorize())
        self.assertEqual(response.status_code, 401)
        self.assertTrue(self.pkce_verified)
        with self.client.session_transaction(base_url="https://bastion.example") as session:
            self.assertNotIn("identity", session)

    def access_client(self):
        self.config["oidc"].update(token_kind="access_token", expected_audience="isolate-api")
        self.config["dashboard"]["self_service_groups"] = ["API-Team"]
        self.app = web.create_app(self.config)
        self.client = self.app.test_client()

    def test_browser_uses_verified_access_token_claims_and_separate_resource_audience(self):
        self.access_client()
        response = self.client.get(self.authorize())
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction(base_url="https://bastion.example") as session:
            self.assertEqual(session["identity"]["groups"], ["API-Team"])
            self.assertEqual(session["identity"]["roles"], ["api-role"])
        self.assertEqual(self.client.get("/me", base_url="https://bastion.example").status_code, 200)

    def test_access_token_subject_must_match_the_id_token(self):
        self.access_client()
        type(self).access_subject = "different-user"
        response = self.client.get(self.authorize())
        self.assertEqual(response.status_code, 401)
        with self.client.session_transaction(base_url="https://bastion.example") as session:
            self.assertNotIn("identity", session)

    def test_state_mismatch_never_reaches_token_endpoint(self):
        callback = parse.urlsplit(self.authorize())
        values = parse.parse_qs(callback.query)
        values["state"] = ["attacker-state"]
        url = parse.urlunsplit(callback._replace(query=parse.urlencode(values, doseq=True)))
        self.assertEqual(self.client.get(url).status_code, 401)
        self.assertFalse(any(method == "POST" for method, _ in self.calls))


if __name__ == "__main__":
    unittest.main()
