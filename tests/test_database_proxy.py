"""Database framing, credential boundaries and content-free SQL audit."""
import asyncio
import contextlib
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import isolate_database_proxy as db
from isolate_protocols import ProtocolError


class DatabaseConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.secret = self.root / "password"
        self.secret.write_text("never-expose-upstream-password\n")
        self.secret.chmod(0o600)
        self.target = {"protocol": "postgresql", "database_proxy": {"enabled": True,
            "frontend_cert_file": str(self.root / "tls.pem"), "frontend_key_file": str(self.root / "tls.key"),
            "databases": ["app"], "credentials": {"type": "file", "username": "db_reader", "password_file": str(self.secret)}}}
        self.context = {"decision": {"remote_user": "db_reader", "sudo_mode": "none"}}

    def test_private_credentials_match_policy_and_are_cleared_after_use(self):
        with db.database_credentials(self.target, self.context) as secret:
            self.assertEqual(secret["username"], "db_reader")
            self.assertEqual(secret["password"], "never-expose-upstream-password")
        self.assertEqual(secret, {})
        for decision in ({"remote_user": "db_admin", "sudo_mode": "none"}, {"remote_user": "db_reader", "sudo_mode": "sudo-i"}):
            with self.subTest(decision=decision), self.assertRaises(ProtocolError):
                with db.database_credentials(self.target, {"decision": decision}):
                    pass

    def test_identity_profiles_are_selected_by_policy_without_caller_paths(self):
        options = self.target["database_proxy"]
        options["identities"] = {"db_reader": options.pop("credentials")}
        with db.database_credentials(self.target, self.context) as credential:
            self.assertEqual(credential["username"], "db_reader")
        with self.assertRaises(ProtocolError):
            with db.database_credentials(self.target, {"decision": {"remote_user": "arbitrary", "sudo_mode": "none"}}):
                pass

    def test_database_and_frontend_tls_configuration_must_be_explicit(self):
        for change in ({"databases": []}, {"frontend_key_file": "relative"}, {"max_packet_bytes": True}, {"audit_statement_text": "true"}):
            target = copy.deepcopy(self.target)
            target["database_proxy"].update(change)
            with self.subTest(change=change), self.assertRaises(ProtocolError):
                db.validate_database_target(target)

    def test_dynamic_vault_lease_is_bound_and_revoked_even_on_identity_mismatch(self):
        profile = {"type": "vault-database", "path": "database/creds/reader"}
        self.target["database_proxy"]["credentials"] = profile
        response = {"lease_id": "private-lease", "lease_duration": 30,
                    "data": {"username": "db_reader", "password": "private-dynamic-password"}}
        with mock.patch.object(db, "_vault_response", side_effect=[response, {}]) as vault:
            with db.database_credentials(self.target, self.context) as credential:
                self.assertLessEqual(credential["expires_at"], time.time() + 30)
            self.assertEqual(vault.call_args.args[1:], ("sys/leases/revoke", {"lease_id": "private-lease"}))
        response["data"]["username"] = "unexpected-superuser"
        with mock.patch.object(db, "_vault_response", side_effect=[response, {}]) as vault:
            with self.assertRaises(ProtocolError):
                with db.database_credentials(self.target, self.context):
                    pass
            self.assertEqual(vault.call_count, 2)

    def test_statement_audit_defaults_to_hash_and_never_parameters_or_rows(self):
        sql = b"select 'never-write-this-literal'"
        result = db._statement(sql, {})
        self.assertEqual(result["statement_sha256"], hashlib.sha256(sql).hexdigest())
        self.assertEqual(result["statement_kind"], "SELECT")
        self.assertNotIn("never-write", json.dumps(result))
        self.assertEqual(db._statement(sql, {"audit_statement_text": True})["statement_text"], sql.decode())


class MySQLAuditTest(unittest.TestCase):
    def setUp(self):
        self.state = db.MySQLAuditState({"databases": ["app"]})

    def test_prepared_parameters_rows_and_long_data_do_not_enter_audit(self):
        event, prepared = self.state.command(b"\x16SELECT ? AS secret")
        self.assertEqual(event, "database_prepare")
        ok = b"\0" + struct.pack("<IHHBH", 17, 1, 1, 0, 0)
        self.assertIsNone(self.state.response(ok))
        for packet in (b"parameter-definition", b"\xfe\0\0\x02\0", b"column-definition"):
            self.assertIsNone(self.state.response(packet))
        self.assertEqual(self.state.response(b"\xfe\0\0\x02\0")["result"], "completed")
        _, execute = self.state.command(b"\x17" + struct.pack("<I", 17) + b"secret-parameter-bytes")
        for packet in (b"\x01", b"column-definition", b"\xfe\0\0\x02\0", b"\0private-row-value"):
            self.assertIsNone(self.state.response(packet))
        result = self.state.response(b"\xfe\0\0\x02\0")
        self.assertEqual(result["row_count"], 1)
        self.assertNotIn("secret-parameter", json.dumps(execute))
        self.assertNotIn("private-row", json.dumps(result))
        _, long_data = self.state.command(b"\x18" + struct.pack("<I", 17) + b"\0\0private-chunk")
        self.assertNotIn("private-chunk", json.dumps(long_data))
        self.assertIsNone(self.state.active)

    def test_multi_results_error_state_and_user_switch_are_not_silently_ignored(self):
        self.state.command(b"\x03SELECT 1; SELECT 2")
        self.assertIsNone(self.state.response(b"\0\0\0\x0a\0\0\0"))
        self.assertEqual(self.state.response(b"\xff\x01\0#42000private-error-details")["sqlstate"], "42000")
        with self.assertRaises(ProtocolError):
            self.state.command(b"\x11different-user\0")

    def test_unknown_prepared_statements_and_local_infile_are_denied(self):
        with self.assertRaises(ProtocolError):
            self.state.command(b"\x17" + struct.pack("<I", 999))
        self.state.command(b"\x03LOAD DATA")
        with self.assertRaises(ProtocolError):
            self.state.response(b"\xfb/etc/private-file")

    def test_mysql_authentication_scrambles_have_known_lengths_and_are_not_passwords(self):
        # Auth-plugin-data has a fixed 20-byte salt plus a separate terminator.
        # A trailing zero in upstream data must not shorten that salt.
        salt = b'a' * 19 + b'\0'
        greeting = (b'\x0a8.0.0\0' + struct.pack('<I', 123) + salt[:8] + b'\0'
            + struct.pack('<H', 0xffff) + b'\x21' + struct.pack('<H', 2)
            + struct.pack('<H', 8) + b'\x15' + b'\0' * 10 + salt[8:] + b'\0mysql_native_password\0')
        self.assertEqual(db._mysql_greeting(greeting)['salt'], salt)
        for plugin, length in (("mysql_native_password", 20), ("caching_sha2_password", 32)):
            with self.subTest(plugin=plugin):
                result = db._mysql_scramble(plugin, "secret-password", b"0123456789abcdefghij")
                self.assertEqual(len(result), length)
                self.assertNotIn(b"secret-password", result)


class DatabaseFramingTest(unittest.IsolatedAsyncioTestCase):
    async def test_oversized_packets_fail_before_payload_allocation(self):
        for packet, function in ((b"Q" + struct.pack("!I", 99999999), db._pg_packet),
                                 (b"\xff\xff\xff\0", db._mysql_packet)):
            reader = asyncio.StreamReader()
            reader.feed_data(packet)
            reader.feed_eof()
            with self.subTest(function=function.__name__), self.assertRaises(ProtocolError):
                await function(reader, 1024)

    async def test_frontend_capability_must_be_private_random_material(self):
        target = {"protocol": "postgresql", "database_proxy": {"enabled": True,
            "frontend_cert_file": os.path.abspath("cert"), "frontend_key_file": os.path.abspath("key"),
            "databases": ["app"], "credentials": {"username": "db_reader", "password_file": "/private"}}}
        for password in ("short", "x" * 32 + "\n", None):
            with self.subTest(password=password), self.assertRaises(ProtocolError):
                await db.proxy_database_session(None, {}, target, None, None, frontend_password=password)


class CancellationOwnershipTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import test_runtime_api_index as fixtures
        from isolate_runtime import Runtime
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        root = Path(self.fixture.directory.name)
        self.fixture.config['protocols'] = {'enabled': True, 'targets': {'1': {
            'protocol': 'postgresql', 'project': 'prod', 'upstream': 'postgresql://postgres.internal:5432',
            'database_proxy': {'enabled': True, 'databases': ['app'],
                'frontend_cert_file': str(root / 'cert.pem'), 'frontend_key_file': str(root / 'cert.key'),
                'credentials': {'type': 'file', 'username': 'db_reader', 'password_file': str(root / 'password')}}}}}
        grant = json.loads(self.fixture.redis.get('grant_1'))
        grant.update(remote_user='db_reader', allowed_actions=['postgresql'])
        self.fixture.redis.set('grant_1', json.dumps(grant))
        self.runtime = Runtime(self.fixture.config, self.fixture.redis)
        self.owner = self.runtime.authorize(self.fixture.token, '1', protocol='postgresql')
        self.runtime.prepare(self.owner)
        self.runtime.start(self.owner)
        self.addCleanup(self.runtime.finish, self.owner)
        _, synthetic = await db._register_cancel(self.runtime, self.owner, struct.pack('!II', 1234, 5678))
        pid, key = struct.unpack('!II', synthetic)
        self.cancellation = {'process_id': pid, 'secret_key': key}
        self.request = self.runtime.authorize(self.fixture.token, '1', protocol='postgresql')
        self.target = {'protocol': 'postgresql', 'address': '127.0.0.1', 'port': 5432, 'hostname': 'postgres.internal'}

    async def test_other_node_uses_separate_durable_evidence_and_preserves_owner_recording(self):
        owner_log = Path(self.owner['_logger'].jsonl_path)
        before = owner_log.read_bytes()
        with mock.patch.object(db.asyncio, 'open_connection', side_effect=OSError('synthetic unavailable')):
            with self.assertRaises(OSError):
                await db.cancel_database_query(self.runtime, self.request, self.target, self.cancellation)
        self.assertEqual(owner_log.read_bytes(), before)
        logs = list(Path(self.fixture.directory.name).rglob('session.jsonl'))
        other = next(path for path in logs if path != owner_log)
        record = json.loads(other.read_text().strip())
        self.assertEqual(record['session_id'], self.request['connection_id'])
        self.assertEqual(record['parent_connection_id'], self.owner['connection_id'])
        self.assertNotEqual(record['session_id'], self.owner['connection_id'])

    async def test_foreign_subject_and_lost_owner_never_reach_upstream(self):
        foreign = copy.deepcopy(self.request['identity'])
        foreign['keycloak_sub'] = 'another-user'
        with mock.patch.object(db.asyncio, 'open_connection') as upstream:
            self.assertFalse(await db.cancel_database_query(self.runtime, dict(self.request, identity=foreign), self.target, self.cancellation))
            self.owner['_lease'].release()
            self.assertFalse(await db.cancel_database_query(self.runtime, self.request, self.target, self.cancellation))
            upstream.assert_not_called()


if __name__ == "__main__":
    unittest.main()
