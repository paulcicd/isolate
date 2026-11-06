"""Authorization and scheduling regressions for temporary access requests."""

import fnmatch
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from isolate_access import (
    AccessDenied, approve_access_request, cancel_access_request,
    can_access_request, comment_access_request, create_access_request,
    deny_access_request, get_access_request, owns_access_request, parse_access_time,
    renew_access_request, revoke_access_request,
)
from isolate_policy import PolicyDenied, resolve_grant


class MemoryRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value):
        self.store[key] = value

    def incr(self, key):
        value = int(self.store.get(key, 0)) + 1
        self.store[key] = str(value)
        return value

    def delete(self, key):
        return self.store.pop(key, None) is not None

    def keys(self, pattern):
        return [key for key in self.store if fnmatch.fnmatchcase(key, pattern)]


class TransactionRedis(MemoryRedis):
    """Optimistic Redis stand-in that rejects writes after a watched key changes."""
    def __init__(self):
        super().__init__()
        self.before_execute = None
        self.executions = 0

    def pipeline(self, transaction=True):
        return MemoryPipeline(self)


class MemoryPipeline:
    def __init__(self, redis):
        self.redis = redis
        self.watched = {}
        self.commands = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def watch(self, *keys):
        for key in keys:
            self.watched[key] = self.redis.get(key)

    def get(self, key):
        return self.redis.get(key)

    def multi(self):
        pass

    def set(self, key, value):
        self.commands.append(("set", key, value))

    def delete(self, key):
        self.commands.append(("delete", key, None))

    def execute(self):
        from redis.exceptions import WatchError
        if self.redis.before_execute:
            callback = self.redis.before_execute
            self.redis.before_execute = None
            callback()
        if any(self.redis.get(key) != value for key, value in self.watched.items()):
            raise WatchError()
        self.redis.executions += 1
        for operation, key, value in self.commands:
            if operation == "set":
                self.redis.set(key, value)
            else:
                self.redis.delete(key)


class AccessLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.redis = MemoryRedis()
        self.owner = {"username": "alice", "keycloak_sub": "alice-id", "groups": ["DBA"]}
        self.other = {"username": "bob", "keycloak_sub": "bob-id", "groups": []}
        self.admin = {"username": "admin", "keycloak_sub": "admin-id", "groups": ["Access-admin"]}
        self.clock = mock.patch("isolate_access.now_ts", return_value=1000)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def request(self, **kwargs):
        return create_access_request(
            self.redis, self.owner, project="prod", host="42", remote_user="dba",
            sudo_mode="none", reason="Diagnose incident", **kwargs,
        )

    def approve(self, request, **kwargs):
        return approve_access_request(self.redis, request["id"], self.admin, 120, **kwargs)

    def test_explicit_timezone_and_unix_dates(self):
        self.assertEqual(parse_access_time("2026-11-07T22:00:00+07:00"), parse_access_time("2026-11-07T15:00:00Z"))
        self.assertEqual(parse_access_time("1200"), 1200)
        with self.assertRaises(ValueError):
            parse_access_time("2026-11-07T22:00")
        with self.assertRaises(ValueError):
            parse_access_time(True)

    def test_invalid_windows_do_not_create_requests(self):
        for start, end in ((1200, 1100), (1000, 1000), (None, 900)):
            with self.assertRaises(AccessDenied):
                self.request(starts_at=start, ends_at=end)
        self.assertEqual(self.redis.keys("access_request_*"), [])

    def test_scheduled_grant_is_denied_before_start_and_after_end(self):
        request = self.request(starts_at=2000, ends_at=2120)
        record, grant = self.approve(request, max_ttl=120)
        self.assertEqual((grant["starts_at"], grant["expires_at"]), (2000, 2120))
        host = {"server_id": "42", "project_name": "prod"}
        for when in (1000, 1999, 2120):
            with mock.patch("isolate_policy.time.time", return_value=when), self.assertRaises(PolicyDenied):
                resolve_grant(self.owner, project="prod", host=host, grants=[grant])
        with mock.patch("isolate_policy.time.time", return_value=2000):
            self.assertEqual(resolve_grant(self.owner, project="prod", host=host, grants=[grant])["remote_user"], "dba")

    def test_approval_limits_duration_from_future_start_and_requested_end(self):
        request = self.request(starts_at=2000, ends_at=2060)
        record, grant = self.approve(request, max_ttl=60)
        self.assertEqual(grant["expires_at"], 2060)
        too_long = self.request(starts_at=2000)
        with self.assertRaises(AccessDenied):
            self.approve(too_long, max_ttl=60)
        with self.assertRaises(AccessDenied):
            approve_access_request(self.redis, too_long["id"], self.admin, 0)

    def test_late_approval_never_grants_an_expired_window(self):
        request = self.request(starts_at=1100, ends_at=1200)
        with mock.patch("isolate_access.now_ts", return_value=1300), self.assertRaises(AccessDenied):
            self.approve(request)
        self.assertEqual(get_access_request(self.redis, request["id"])["status"], "pending")
        self.assertEqual(self.redis.keys("grant_*"), [])

    def test_owner_identity_uses_stable_subject(self):
        request = self.request()
        same_name_other_sub = dict(self.other, username="alice")
        renamed_owner = dict(self.owner, username="alice.renamed")
        self.assertFalse(owns_access_request(request, same_name_other_sub))
        self.assertFalse(owns_access_request(request, {"username": "alice"}))
        self.assertTrue(owns_access_request(request, renamed_owner))
        self.assertFalse(can_access_request(request, self.other))
        self.assertTrue(can_access_request(request, self.admin, ["Access-admin"]))

    def test_temporary_grant_uses_stable_subject_after_username_changes(self):
        _, grant = self.approve(self.request())
        self.assertEqual(grant["keycloak_sub"], self.owner["keycloak_sub"])
        host = {"server_id": "42", "project_name": "prod"}
        with mock.patch("isolate_policy.time.time", return_value=1000):
            reused_name = dict(self.other, username=self.owner["username"])
            with self.assertRaises(PolicyDenied):
                resolve_grant(reused_name, project="prod", host=host, grants=[grant])
            with self.assertRaises(PolicyDenied):
                resolve_grant({"username": "alice"}, project="prod", host=host, grants=[grant])
            renamed_owner = dict(self.owner, username="alice.renamed")
            self.assertEqual(resolve_grant(renamed_owner, project="prod", host=host, grants=[grant])["remote_user"], "dba")

    def test_legacy_username_grants_continue_matching_without_subject(self):
        legacy = {"subject": "user", "name": "alice", "project": "prod", "remote_user": "dba"}
        self.assertEqual(resolve_grant(self.owner, project="prod", grants=[legacy])["remote_user"], "dba")
        with self.assertRaises(PolicyDenied):
            resolve_grant(self.other, project="prod", grants=[legacy])

    def test_only_owner_can_cancel_pending_and_it_cannot_be_approved(self):
        request = self.request()
        with self.assertRaises(AccessDenied):
            cancel_access_request(self.redis, request["id"], self.other)
        self.assertEqual(cancel_access_request(self.redis, request["id"], self.owner)["status"], "cancelled")
        with self.assertRaises(AccessDenied):
            self.approve(request)
        self.assertEqual(self.redis.keys("grant_*"), [])

    def test_revoke_requires_admin_and_removes_only_its_linked_grant(self):
        request = self.request()
        approved, _ = self.approve(request)
        with self.assertRaises(AccessDenied):
            revoke_access_request(self.redis, request["id"], self.owner, admin_groups=["Access-admin"])
        revoked = revoke_access_request(self.redis, request["id"], self.admin, admin_groups=["Access-admin"], reason="Incident resolved")
        self.assertEqual(revoked["status"], "revoked")
        self.assertIsNone(self.redis.get("grant_" + approved["grant_id"]))
        self.assertEqual(revoked["comments"][-1]["action"], "revoke")

    def test_revoke_refuses_a_replaced_linked_grant(self):
        approved, _ = self.approve(self.request())
        grant_key = "grant_" + approved["grant_id"]
        replacement = {"request_id": "other", "subject": "user", "name": "bob"}
        self.redis.set(grant_key, json.dumps(replacement))
        with self.assertRaises(AccessDenied):
            revoke_access_request(self.redis, approved["id"], self.admin, ["Access-admin"])
        self.assertEqual(json.loads(self.redis.get(grant_key)), replacement)
        self.assertEqual(get_access_request(self.redis, approved["id"])["status"], "approved")

    def test_renewal_requires_owner_and_reapproval_without_extending_old_grant(self):
        approved, _ = self.approve(self.request())
        original_grant = self.redis.get("grant_" + approved["grant_id"])
        with self.assertRaises(AccessDenied):
            renew_access_request(self.redis, approved["id"], self.other)
        renewed = renew_access_request(self.redis, approved["id"], self.owner, starts_at=1200, ends_at=1400)
        self.assertEqual(renewed["renewal_of"], approved["id"])
        self.assertEqual(renewed["status"], "pending")
        self.assertIsNone(renewed["grant_id"])
        self.assertEqual(len(self.redis.keys("grant_*")), 1)
        self.assertEqual(self.redis.get("grant_" + approved["grant_id"]), original_grant)

    def test_comment_owner_and_admin_acl(self):
        request = self.request()
        with self.assertRaises(AccessDenied):
            comment_access_request(self.redis, request["id"], self.other, "not mine")
        result = comment_access_request(self.redis, request["id"], self.admin, "review", ["Access-admin"])
        self.assertEqual(result["comments"][-1]["text"], "review")

    def test_atomic_approval_rechecks_a_concurrent_cancellation(self):
        self.redis = TransactionRedis()
        request = self.request()

        def concurrent_cancel():
            current = get_access_request(self.redis, request["id"])
            current["status"] = "cancelled"
            self.redis.set("access_request_" + request["id"], json.dumps(current))

        self.redis.before_execute = concurrent_cancel
        with self.assertRaises(AccessDenied):
            self.approve(request)
        self.assertEqual(self.redis.keys("grant_*"), [])
        self.assertEqual(get_access_request(self.redis, request["id"])["status"], "cancelled")

    def test_atomic_approve_and_revoke_share_one_transaction_each(self):
        self.redis = TransactionRedis()
        approved, _ = self.approve(self.request())
        self.assertEqual(self.redis.executions, 1)
        revoke_access_request(self.redis, approved["id"], self.admin, ["Access-admin"])
        self.assertEqual(self.redis.executions, 2)
        self.assertEqual(self.redis.keys("grant_*"), [])

    def test_atomic_revoke_cannot_delete_a_concurrently_replaced_grant(self):
        self.redis = TransactionRedis()
        approved, _ = self.approve(self.request())
        grant_key = "grant_" + approved["grant_id"]
        replacement = {"request_id": "someone-else", "subject": "user", "name": "bob"}
        self.redis.before_execute = lambda: self.redis.set(grant_key, json.dumps(replacement))
        with self.assertRaises(AccessDenied):
            revoke_access_request(self.redis, approved["id"], self.admin, ["Access-admin"])
        self.assertEqual(json.loads(self.redis.get(grant_key)), replacement)
        self.assertEqual(get_access_request(self.redis, approved["id"])["status"], "approved")


if __name__ == "__main__":
    unittest.main()
