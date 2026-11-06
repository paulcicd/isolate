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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "shared"))
import isolate
import isolate_connection_auth as auth
import isolate_identity
from isolate_logging import SessionLogger
from isolate_policy import PolicyDenied
from isolate_ssh import SSHArgumentError, build_ssh_argv


class Redis:
    def __init__(self):
        self.values = {}
    def set(self, key, value):
        self.values[key] = value
    def get(self, key):
        return self.values.get(key)
    def keys(self, pattern):
        return [key for key in self.values if fnmatch.fnmatchcase(key, pattern)]


class ConnectionAuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.config = {"keycloak": {"issuer": "https://id.example/realms/apex", "client_id": "isolate", "expected_audience": "isolate"},
                       "connection_authorization": {"allowed_target_ports": [22]}, "ssh": {"default_sudo_mode": "none"}}
        self.claims = {"sub": "alice-sub", "preferred_username": "alice", "groups": ["apex"],
                       "aud": "isolate", "iss": self.config["keycloak"]["issuer"], "exp": self.now + 600}
        self.redis = Redis()
        self.host = {"server_id": "10001", "server_name": "pilot", "server_ip": "192.0.2.1", "server_port": 22, "project_name": "pilot"}
        self.grant = {"subject": "group", "name": "apex", "project": "pilot", "host": "10001", "remote_user": "observer", "sudo_mode": "none", "allowed_actions": ["ssh"], "expires_at": self.now + 300}
        self.redis.set("server_10001", json.dumps(self.host))
        self.redis.set("grant_1", json.dumps(self.grant))
        self.args = SimpleNamespace(host_id="10001", hostname=["192.0.2.1"], port=22, user=["observer"], nosudo=True,
                                    project="pilot", human_user="alice", keycloak_sub="alice-sub",
                                    proxy_host=None, proxy_port=None, proxy_user=None)
        self.verifier = mock.patch.object(auth, "verify_jwt_claims", return_value=self.claims)
        self.verifier.start()
        self.addCleanup(self.verifier.stop)

    def authorize(self):
        return auth.authorize_connection(self.args, "signed-token", self.config, self.redis, "alice")

    def test_valid_connection_is_pinned_to_current_policy(self):
        result = self.authorize()
        self.assertEqual(result["decision"]["remote_user"], "observer")
        self.assertEqual(result["deadline"], self.grant["expires_at"])

    def test_target_user_port_identity_and_proxy_overrides_fail(self):
        changes = {"hostname": ["192.0.2.2"], "port": 443, "user": ["root"], "nosudo": False,
                   "human_user": "admin", "keycloak_sub": "admin-sub", "project": "other", "proxy_host": ["192.0.2.3"], "host_id": "999"}
        for field, value in changes.items():
            with self.subTest(field=field):
                old = getattr(self.args, field)
                setattr(self.args, field, value)
                with self.assertRaises((auth.ConnectionDenied, PolicyDenied)):
                    self.authorize()
                setattr(self.args, field, old)

    def test_no_grant_cannot_be_bypassed_by_direct_wrapper_request(self):
        self.redis.values.pop("grant_1")
        with self.assertRaises(PolicyDenied):
            self.authorize()

    def test_connections_closed_and_inventory_port_enforced(self):
        self.config["connection_authorization"]["connections_enabled"] = False
        with self.assertRaises(auth.ConnectionDenied):
            self.authorize()
        self.config["connection_authorization"]["connections_enabled"] = True
        self.host["server_port"] = self.args.port = 443
        self.redis.set("server_10001", json.dumps(self.host))
        with self.assertRaises(auth.ConnectionDenied):
            self.authorize()

    def test_explicit_unix_mapping_cannot_be_selected_by_caller(self):
        self.config["connection_authorization"].update(require_explicit_mapping=True, unix_users={"alice": {"sub": "different"}})
        with self.assertRaises(auth.ConnectionDenied):
            self.authorize()
        self.config["connection_authorization"]["unix_users"]["alice"]["sub"] = "alice-sub"
        self.authorize()
        self.claims["preferred_username"] = "other"
        self.config["connection_authorization"]["unix_users"] = {}
        with self.assertRaises(auth.ConnectionDenied):
            self.authorize()

    def test_disabled_verification_wrong_audience_and_unsafe_username_fail(self):
        for key, value in (("verify_tokens", False), ("tls_verify", False), ("issuer", "")):
            with self.subTest(key=key):
                config = copy.deepcopy(self.config)
                config["keycloak"][key] = value
                with self.assertRaises(auth.ConnectionDenied):
                    auth.bind_identity("token", config, "alice")
        self.claims.update(aud="other", azp="isolate")
        with self.assertRaises(auth.ConnectionDenied):
            self.authorize()
        self.claims.update(aud="isolate", preferred_username="../admin")
        with self.assertRaises(auth.ConnectionDenied):
            self.authorize()

    def test_active_session_rechecks_revocation_inventory_and_deadline(self):
        context = self.authorize()
        auth.recheck_connection(context, self.config, self.redis)
        self.redis.values.pop("grant_1")
        with self.assertRaises(PolicyDenied):
            auth.recheck_connection(context, self.config, self.redis)
        self.redis.set("grant_1", json.dumps(self.grant))
        self.host["server_ip"] = "192.0.2.2"
        self.redis.set("server_10001", json.dumps(self.host))
        with self.assertRaises(auth.ConnectionDenied):
            auth.recheck_connection(context, self.config, self.redis)
        with mock.patch.object(auth.time, "time", return_value=context["deadline"]):
            with self.assertRaises(auth.ConnectionDenied):
                auth.recheck_connection(context, self.config, self.redis)

    def test_audit_path_traversal_is_rejected_before_creating_files(self):
        with tempfile.TemporaryDirectory() as directory:
            for identity, session_id in (({"username": "../admin"}, "session"), ({"username": "alice"}, "../../escape")):
                with self.assertRaises(ValueError):
                    SessionLogger(directory, identity, session_id=session_id)
            self.assertEqual(os.listdir(directory), [])

    def test_forwarding_and_agent_options_cannot_override_config(self):
        config = {"allowed_extra_args": ["-A", "-v"]}
        with self.assertRaises(SSHArgumentError):
            build_ssh_argv(config, {"hostname": "192.0.2.1"}, extra_args=["-A"])
        args = build_ssh_argv(config, {"hostname": "192.0.2.1"})
        for option in ("ForwardAgent=no", "ClearAllForwardings=yes", "StrictHostKeyChecking=yes", "BatchMode=yes"):
            self.assertIn(option, args)

    def test_cli_administration_denies_non_admin_before_dispatch(self):
        args = isolate.build_parser().parse_args(["grant", "add", "--user", "alice", "--project", "pilot", "--remote-user", "root"])
        with mock.patch.object(isolate, "_require_platform_admin", side_effect=isolate.AccessDenied("no admin")):
            with self.assertRaises(isolate.AccessDenied):
                isolate.authorize_cli_command(args, self.config)
        with mock.patch.object(isolate, "_require_platform_admin", side_effect=isolate.AccessDenied("no admin")), \
                mock.patch.object(isolate, "redis_client") as redis:
            self.assertEqual(isolate.cmd_grant_add(args, self.config), 2)
            redis.assert_not_called()

    def test_token_audience_cannot_be_replaced_by_azp(self):
        with self.assertRaises(isolate_identity.IdentityError):
            isolate_identity._validate_claims(dict(self.claims, aud="other", azp="isolate"), self.config["keycloak"])

    def test_real_signed_token_is_verified_and_tampering_is_denied(self):
        from joserfc import jwt
        from joserfc.jwk import RSAKey
        import base64
        self.verifier.stop()
        key = RSAKey.generate_key(2048)
        token = jwt.encode({"alg": "RS256"}, self.claims, key)
        with mock.patch.object(isolate_identity, "load_jwks", return_value={"keys": [key.as_dict(private=False)]}):
            auth.authorize_connection(self.args, token, self.config, self.redis, "alice")
            head, payload, signature = token.split(".")
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            claims["preferred_username"] = "admin"
            altered = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
            with self.assertRaises(isolate_identity.IdentityError):
                auth.authorize_connection(self.args, head + "." + altered + "." + signature, self.config, self.redis, "alice")

    def test_helper_rejects_wrapper_option_injection_before_token_handoff(self):
        import helper
        connection = helper.ServerConnection(helper=SimpleNamespace(config={"ssh": {"allowed_extra_args": ["-v"]}}), unknown_args=["--user", "root"])
        with mock.patch.object(helper, "prepare_authorization_file") as prepare:
            with self.assertRaises(SSHArgumentError):
                connection.build_cmd()
            prepare.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Linux service UID ACL")
    def test_authorization_file_handoff_does_not_expose_tokens_in_argv(self):
        with mock.patch.object(auth, "_load_token_cache", return_value={"id_token": "signed-token"}):
            path = auth.prepare_authorization_file()
        try:
            self.assertEqual(auth.read_authorization_file(path, os.getuid()), "signed-token")
            self.assertNotIn("signed-token", path)
        finally:
            os.unlink(path)

    @unittest.skipUnless(os.name == "posix", "Linux file ownership and O_NOFOLLOW")
    def test_token_file_rejects_symlink_and_unsafe_permissions(self):
        uid = os.getuid()
        with tempfile.NamedTemporaryFile(prefix="isolate-authorization-{}-".format(uid), dir="/tmp", delete=False) as output:
            path = output.name
            output.write(b'{"id_token":"signed"}')
        link = path + "-link"
        try:
            os.chmod(path, 0o640)
            self.assertEqual(auth.read_authorization_file(path, uid), "signed")
            os.chmod(path, 0o666)
            with self.assertRaises(auth.ConnectionDenied):
                auth.read_authorization_file(path, uid)
            os.symlink(path, link)
            with self.assertRaises(OSError):
                auth.read_authorization_file(link, uid)
        finally:
            os.unlink(path)
            if os.path.lexists(link):
                os.unlink(link)


if __name__ == "__main__":
    unittest.main()
