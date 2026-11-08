"""Operator setup preserves private state and explicit identity-provider selection."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import fakeredis
from isolate_config import DEFAULT_CONFIG, load_config, canonical_identity_config, with_identity_provider
from isolate_identity import IdentityError
from isolate_identity_binding import bind_provider, ensure_provider_binding, BINDING_KEY
from isolate_oidc import identity_provider_config
from isolate_redis import redis_options
from isolate_setup import installation_config, write_installation, diagnose


class SetupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = installation_config(provider="oidc", issuer="https://login.example/tenant/", client_id="isolate",
            public_url="https://access.example", data_root=str(self.root / "runtime"), dsn_file=str(self.root / "dsn"),
            redis_host="redis.example", redis_ca=str(self.root / "ca.pem"), admin_group="access-admins")

    def test_create_is_exclusive_private_and_keeps_credentials_external(self):
        target = self.root / "isolate.json"
        write_installation(target, self.config, provision_keys=True)
        loaded = load_config(str(target), use_env=False)
        self.assertEqual(loaded["keycloak"]["provider"], "oidc")
        self.assertEqual(loaded["keycloak"]["issuer"], "https://login.example/tenant/")
        self.assertTrue((Path(self.config["data_root"]) / "keys/gateway_ed25519").read_bytes().startswith(b"-----BEGIN OPENSSH PRIVATE KEY"))
        original = target.read_bytes()
        with self.assertRaises(ValueError):
            write_installation(target, self.config, provision_keys=True)
        self.assertEqual(target.read_bytes(), original)
        if os.name == "posix":
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual((Path(self.config["data_root"]) / "keys/dashboard_secret").stat().st_mode & 0o777, 0o600)

    def test_setup_rejects_untrusted_origins_and_relative_secret_paths(self):
        source = dict(provider="oidc", issuer="https://login.example", client_id="isolate", public_url="https://access.example",
                      data_root=str(self.root), dsn_file=str(self.root / "dsn"), redis_host="redis.example", redis_ca=str(self.root / "ca"))
        for changes in ({"issuer": "http://login.example"}, {"public_url": "https://user:secret@access.example"},
                        {"dsn_file": "relative"}, {"client_secret_file": "relative"}):
            with self.subTest(changes=changes), self.assertRaises((IdentityError, ValueError)):
                installation_config(**dict(source, **changes))

    def test_redis_password_file_is_private_and_lazily_read(self):
        secret = self.root / "redis-password"
        secret.write_text("first-password\n")
        secret.chmod(0o600)
        config = {"redis": {"password_file": str(secret)}}
        self.assertEqual(redis_options(config)["password"], "first-password")
        secret.write_text("rotated-password\n")
        self.assertEqual(redis_options(config)["password"], "rotated-password")
        if os.name == "posix":
            secret.chmod(0o640)
            with self.assertRaises(IdentityError):
                redis_options(config)

    def test_disabled_oidc_preserves_legacy_and_audience_override_is_explicit(self):
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["keycloak"]["issuer"] = "https://legacy.example/realms/isolate"
        config["oidc"] = {"enabled": False, "issuer": "https://other.example"}
        self.assertEqual(canonical_identity_config(config)["keycloak"]["provider"], "keycloak")
        provider = identity_provider_config(self.config)
        effective = with_identity_provider(self.config, dict(provider, expected_audience="isolate-mcp"))
        self.assertEqual(identity_provider_config(effective)["expected_audience"], "isolate-mcp")
        self.assertNotIn("client_secret", provider)

    def test_doctor_offline_does_not_contact_provider_or_store(self):
        with mock.patch("isolate_oidc.discover_provider", side_effect=AssertionError("network")), mock.patch("isolate_redis.create_redis_client", side_effect=AssertionError("store")):
            report = diagnose(self.config, offline=True)
        self.assertTrue(report["offline"])
        self.assertFalse(report["ok"])
        self.assertEqual(report["callback_url"], "https://access.example/auth/callback")
        self.assertNotIn(self.config["state"]["dsn_file"], json.dumps(report))

    def test_api_client_identity_uses_the_api_without_a_redis_dependency(self):
        from isolate_identity import load_verified_identity
        from isolate_client import APIClient
        provider = {"oidc": {"enabled": True, "issuer": "https://idp.example", "client_id": "isolate", "token_kind": "access_token"},
                    "api": {"client_url": "https://access.example"}}
        claims = {"iss": "https://idp.example", "sub": "raw-sub", "aud": "isolate", "preferred_username": "alice", "groups": ["old-group"], "exp": 9999999999}
        from isolate_oidc import normalize_identity_claims
        expected = normalize_identity_claims(claims, identity_provider_config(provider))
        with mock.patch("isolate_identity._load_token_cache", return_value={"access_token": "verified-token"}), \
                mock.patch("isolate_identity.verify_jwt_claims", return_value=claims), \
                mock.patch("isolate_redis.create_redis_client", side_effect=AssertionError("private Redis must not be needed")), \
                mock.patch.object(APIClient, "call", return_value=dict(expected, groups=["current-group"])) as api:
            identity = load_verified_identity(provider)
        self.assertEqual(identity["groups"], ["current-group"])
        api.assert_called_once_with("/api/v1/me", token="verified-token")

    def test_setup_plan_does_not_create_files(self):
        output = self.root / "new.json"
        command = [sys.executable, "scripts/isolate-setup.py", "init", "--plan", "--output", str(output),
            "--issuer", "https://login.example", "--client-id", "isolate", "--public-url", "https://access.example",
            "--data-root", str(self.root / "runtime"), "--dsn-file", str(self.root / "dsn"),
            "--redis-host", "redis.example", "--redis-ca", str(self.root / "ca")]
        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse((self.root / "runtime").exists())
        self.assertEqual(json.loads(result.stdout)["oidc"]["issuer"], "https://login.example")


class IdentityBindingTest(unittest.TestCase):
    def setUp(self):
        self.store = fakeredis.FakeRedis()
        self.config = {"oidc": {"enabled": True, "issuer": "https://idp.example", "client_id": "isolate"}}

    def test_new_oidc_requires_explicit_reconciliation_then_remains_bound(self):
        self.store.set("grant_1", json.dumps({"subject": "group", "name": "admins", "project": "prod"}))
        with self.assertRaises(IdentityError):
            ensure_provider_binding(self.config, self.store)
        with self.assertRaises(IdentityError):
            bind_provider(self.config, self.store, actor="ops", reason="new install")
        record = bind_provider(self.config, self.store, actor="ops", reason="reviewed group grants", drained=True, reconciled=True)
        self.assertEqual(ensure_provider_binding(self.config, self.store), record)
        epoch = self.store.get("isolate_authority_epoch")
        self.assertEqual(bind_provider(self.config, self.store, actor="ops", reason="repeat"), record)
        self.assertEqual(self.store.get("isolate_authority_epoch"), epoch)
        self.assertEqual(len(self.store.keys("identity_binding_event_*")), 1)

    def test_switching_issuer_or_adapter_denies_old_binding_and_rotates_epoch(self):
        legacy = {"keycloak": {"issuer": "https://idp.example"}}
        ensure_provider_binding(legacy, self.store)
        self.assertEqual(json.loads(self.store.get(BINDING_KEY))["provider"], "keycloak")
        with self.assertRaises(IdentityError):
            ensure_provider_binding(self.config, self.store)
        before = self.store.get("isolate_authority_epoch")
        bind_provider(self.config, self.store, actor="ops", reason="reconciled all principals", drained=True, reconciled=True)
        self.assertNotEqual(self.store.get("isolate_authority_epoch"), before)
        changed = copy.deepcopy(self.config)
        changed["oidc"]["issuer"] = "https://other.example"
        with self.assertRaises(IdentityError):
            ensure_provider_binding(changed, self.store)
        self.assertTrue(self.store.get("grant_1") is None)

    def test_corrupt_binding_fails_closed(self):
        self.store.set(BINDING_KEY, "not-json")
        with self.assertRaises(IdentityError):
            ensure_provider_binding(self.config, self.store)


if __name__ == "__main__":
    unittest.main()
