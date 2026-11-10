"""Control-plane launch, client credential and deployment boundaries."""
import asyncio
import contextlib
from io import StringIO
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
import test_runtime_api_index as fixtures
from isolate_protocols import resolve_target, ProtocolError
from isolate_runtime_config import validate_runtime_config


class ApplicationControlTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config, self.store = self.fixture.config, self.fixture.redis
        self.config["web_apps"] = {"enabled": True, "launch_ttl": 30}
        self.config["dashboard"]["public_url"] = "https://access.control.test"
        self.config["gateway"]["public_web_url"] = "https://gateway.control.test"
        self.config["protocols"] = {"enabled": True, "targets": {"1": {"protocol": "http", "project": "prod",
            "upstream": "https://upstream.internal", "mode": "web-application", "public_origin": "https://wiki.applications.test"}}}
        grant = json.loads(self.store.get("grant_1"))
        grant["allowed_actions"] = ["ssh", "http"]
        self.store.set("grant_1", json.dumps(grant))
        self.app = self.fixture.app()
        self.client = self.app.test_client()
        self.headers = {"Authorization": "Bearer " + self.fixture.token}

    def login(self):
        identity = self.fixture.runtime.authenticate(self.fixture.token)
        with self.client.session_transaction() as session:
            session["identity"] = identity
            session["runtime_session"] = "test-browser-session-0123456789"
            session["csrf_token"] = "test-csrf"
        self.store.set("isolate_browser_test-browser-session-0123456789", json.dumps({"sub": identity["keycloak_sub"], "token": self.fixture.token}))

    def test_launch_code_is_post_only_short_lived_and_requires_current_protocol_grant(self):
        path = "/api/v1/web-apps/1/launch"
        response = self.client.post(path, headers=self.headers, json={"confirm": True})
        self.assertEqual(response.status_code, 201, response.data)
        launch = response.get_json()
        self.assertEqual(launch["launch_url"], "https://wiki.applications.test/_isolate/launch")
        self.assertNotIn(launch["code"], launch["launch_url"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(len(self.store.keys("web_app_launch_*")), 1)
        for body in ({"confirm": 1}, {"confirm": False}, {"confirm": True, "upstream": "https://evil.test"}):
            self.assertEqual(self.client.post(path, headers=self.headers, json=body).status_code, 400)
        self.store.delete("grant_1")
        self.assertEqual(self.client.post(path, headers=self.headers, json={"confirm": True}).status_code, 403)

    def test_browser_launch_needs_csrf_and_posts_without_url_or_referrer_credentials(self):
        self.login()
        path = "/workspace/application/1/launch"
        self.assertEqual(self.client.post(path, data={"confirm": "true"}).status_code, 403)
        response = self.client.post(path, data={"csrf_token": "test-csrf", "confirm": "true"})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn(b'action="https://wiki.applications.test/_isolate/launch"', response.data)
        self.assertIn(b'name="code"', response.data)
        self.assertNotIn(b"Bearer", response.data)
        self.assertNotIn(self.fixture.token.encode(), response.data)
        self.assertNotIn("Location", response.headers)
        self.assertEqual(response.headers["Referrer-Policy"], "strict-origin")
        self.assertIn("form-action https://wiki.applications.test", response.headers["Content-Security-Policy"])
        self.assertEqual(self.client.post(path, data={"csrf_token": "test-csrf", "confirm": "true"}, headers={"Origin": "https://evil.test"}).status_code, 403)

    def test_detail_launch_button_and_legacy_api_route_are_distinct(self):
        self.login()
        response = self.client.get("/workspace/resource/1/http")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn(b"Open application", response.data)
        self.assertIn(b"/workspace/application/1/launch", response.data)
        self.assertNotIn(b"/protocols/http/", response.data)

    def test_optional_modes_validate_and_cannot_downgrade_to_an_unchecked_target(self):
        host = self.fixture.runtime.redis.get("server_1")
        host = json.loads(host)
        target = self.config["protocols"]["targets"]["1"]
        self.assertEqual(resolve_target(self.config, host, "http")["public_origin"], target["public_origin"])
        target["public_origin"] = "https://wiki.control.test"
        with self.assertRaises(ProtocolError):
            resolve_target(self.config, host, "http")
        self.assertTrue(validate_runtime_config(self.config)["errors"])
        target["mode"] = "api"
        target["kubernetes"] = ["not-an-object"]
        with self.assertRaises(ProtocolError):
            resolve_target(self.config, host, "http")


class ProtocolClientBoundaryTest(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location("protocol_client_test", ROOT / "scripts/isolate-protocol-proxy.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_kubectl_helper_selects_configured_access_token_without_contacting_redis(self):
        from types import SimpleNamespace
        module = self.module()
        config = {"oidc": {"enabled": True, "issuer": "https://idp.example", "client_id": "isolate", "token_kind": "access_token"}}
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "identity.json"
            cache.write_text(json.dumps({"schema_version": 3, "id_token": "wrong-identity-token", "access_token": "correct-access-token", "expires_at": 2000000000}))
            output = StringIO()
            with mock.patch("isolate_config.load_config", return_value=config), \
                    mock.patch("isolate_redis.create_redis_client", side_effect=AssertionError("private store")), contextlib.redirect_stdout(output):
                module.credential(SimpleNamespace(identity_file=str(cache), config=None))
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"]["token"], "correct-access-token")
            self.assertNotIn("wrong-identity-token", output.getvalue())

    def test_brokered_helper_refuses_missing_or_short_private_local_capabilities(self):
        from types import SimpleNamespace
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            password = Path(directory) / "local-capability"
            password.write_text("short")
            password.chmod(0o600)
            args = SimpleNamespace(api_url="https://api.example", gateway_url="wss://gateway.example", ca_file=None,
                allow_loopback_http=False, database_proxy=True, frontend_password_file=str(password), create_frontend_password=False,
                config=None)
            with self.assertRaises(ValueError):
                asyncio.run(module.database_tunnel(args))
