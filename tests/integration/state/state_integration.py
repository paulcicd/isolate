"""Real PostgreSQL/Redis contract and domain-state migration integration tests.

The Compose project exposes no ports, uses synthetic fixtures, and does not
contact the running demo or any production Keycloak/database.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "shared"))
sys.path.insert(0, str(ROOT / "tests"))

import psycopg
from psycopg.conninfo import make_conninfo
from psycopg import sql
import redis
from redis.exceptions import WatchError
from test_state import StateTest, MigrationTest
from isolate_redis import create_redis_client
from isolate_state import SQLState, StateClient
from isolate_state_migration import freeze_source, import_source, cutover


DSN = "host=postgres dbname=isolate_state_test user=isolate_state_test password=isolated-state-integration-password connect_timeout=3"


def postgres_fixture(test, active=True):
    test.directory = tempfile.TemporaryDirectory(prefix="isolate-state-integration-")
    test.addCleanup(test.directory.cleanup)
    schema = "state_fixture_" + uuid.uuid4().hex
    with psycopg.connect(DSN) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    def cleanup():
        with psycopg.connect(DSN) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
    test.addCleanup(cleanup)
    test.path = os.path.join(test.directory.name, "state.dsn")
    Path(test.path).write_text(make_conninfo(DSN, options="-c search_path=" + schema), encoding="utf-8")
    os.chmod(test.path, 0o600)
    test.options = {"backend": "postgresql", "dsn_file": test.path, "require_tls": False}  # isolated Compose network only
    test.redis = redis.Redis(host="redis", socket_timeout=5)
    test.redis.flushdb()  # Only this dedicated Compose project's private Redis.
    test.state = SQLState(test.options)
    test.state.initialize(active=active)
    test.client = StateClient(test.redis, test.options)


class PostgreSQLStateTest(StateTest):
    def setUp(self):
        postgres_fixture(self)

    def test_expiry_is_part_of_cas_and_does_not_extend_on_increment(self):
        self.client.set("identity_revocation_ttl", "1", px=1000)
        before = self.client.pttl("identity_revocation_ttl")
        self.client.incr("identity_revocation_ttl")
        self.assertLessEqual(self.client.pttl("identity_revocation_ttl"), before)
        with self.client.pipeline() as pipe:
            pipe.watch("identity_revocation_ttl")
            time.sleep(1.1)
            pipe.multi()
            pipe.set("grant_after_expiry", "unsafe")
            with self.assertRaises(WatchError):
                pipe.execute()
        self.assertEqual(self.client.pttl("identity_revocation_ttl"), -2)

    def test_factory_cli_and_ephemeral_redis_loss_share_sql_authority(self):
        config = {"state": self.options, "redis": {"host": "redis"}}
        store = create_redis_client(config)
        self.assertIsInstance(store, StateClient)
        store.set("server_10001", json.dumps({"server_id": "10001", "server_name": "fixture", "server_ip": "192.0.2.1", "project_name": "fixture"}))
        store.set("grant_1", json.dumps({"subject": "group", "name": "Support", "project": "fixture", "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh"]}))
        store.set("identity_revocation_fixture", "revoked")
        store.set("job_execution_claim_1", "already consumed")
        store.set("isolate_ticket_consumed", "ticket")
        self.assertEqual(store.getdel("isolate_ticket_consumed"), b"ticket")
        self.redis.flushdb()
        self.assertIsNotNone(store.get("grant_1"))
        self.assertEqual(store.get("identity_revocation_fixture"), b"revoked")
        self.assertEqual(store.get("job_execution_claim_1"), b"already consumed")
        self.assertIsNone(store.getdel("isolate_ticket_consumed"))
        from isolate import load_grants
        self.assertEqual(load_grants(store)[0]["remote_user"], "support")
        config_file = Path(self.directory.name) / "config.json"
        config_file.write_text(json.dumps(config))
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "isolate-state.py"), "--config", str(config_file), "status"],
                                check=True, capture_output=True, text=True)
        status = json.loads(result.stdout)
        self.assertEqual(status["status"], "active")
        self.assertNotIn("password", result.stdout)
        with self.state.connection(write=True) as conn:
            self.assertEqual(conn.execute("SHOW synchronous_commit").fetchone()["synchronous_commit"], "on")


class PostgreSQLMigrationTest(MigrationTest):
    def setUp(self):
        postgres_fixture(self, active=False)
        self.source = self.redis
        self.source.set("server_10001", '{"server_id":10001}')
        self.source.set("offset_server_id", "10001")
        self.source.set("grant_1", '{"remote_user":"support"}')
        self.source.set("offset_grant_id", "1")
        self.source.set("identity_revocation_dead", "123", ex=300)
        self.source.set("isolate_ticket_old", "must not migrate", ex=60)
        self.source.set("active_session_old", "ephemeral")
        self.target = self.state


if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PostgreSQLStateTest))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PostgreSQLMigrationTest))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
