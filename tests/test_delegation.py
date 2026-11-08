"""Real signed identities, sealed job credentials and live worker revocation."""

import concurrent.futures
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import fakeredis
from joserfc import jwt
from joserfc.jwk import RSAKey

from isolate_config import DEFAULT_CONFIG
import isolate_delegation as delegation
from isolate_identity import IdentityError, normalize_claims
import isolate_identity_security as security
import isolate_jobs as jobs
from isolate_policy import PolicyDenied, resolve_grant


class DelegationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSAKey.generate_key(2048, parameters={"kid": "delegation-test"})

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.redis = fakeredis.FakeRedis(decode_responses=True)
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self.config["keycloak"].update(issuer="https://id.example/realms/company", client_id="isolate",
            expected_audience="isolate", jwks_cache_path=None)
        self.config["identity_security"]["delegation"] = {"enabled": True, "max_seconds": 120, "recheck_interval": 0.25}
        self.config["identity_security"]["backchannel_logout"]["enabled"] = True
        key_path = Path(self.directory.name) / "jobs.key"
        key_path.write_bytes(b"secret-job-signing-key-at-least-32-bytes")
        key_path.chmod(0o600)
        self.config["command_execution"].update(enabled=True, allowed_groups=["Support"],
            allow_arbitrary_commands=True, signing_key_file=str(key_path), jobs_path=self.directory.name,
            max_timeout=60, default_timeout=30)
        self.claims = {"iss": self.config["keycloak"]["issuer"], "aud": "isolate", "sub": "human-stable-sub",
            "preferred_username": "alice", "groups": ["Support"], "iat": int(time.time()) - 10,
            "auth_time": int(time.time()) - 10, "exp": int(time.time()) + 600, "sid": "human-session"}
        self.token = self.sign(self.claims)
        self.identity = normalize_claims(self.claims)
        self.host = {"server_id": "1", "server_name": "server", "project_name": "prod", "server_ip": "127.0.0.1", "server_port": 22}
        self.grant = {"id": "1", "subject": "group", "name": "Support", "project": "prod", "remote_user": "observer",
            "sudo_mode": "none", "allowed_actions": ["command", "runbook"]}
        self.redis.set("server_1", json.dumps(self.host))
        self.redis.set("grant_1", json.dumps(self.grant))
        self.decision = resolve_grant(self.identity, project="prod", host=self.host, grants=[self.grant], action="command")
        patcher = mock.patch("isolate_identity.load_jwks", return_value={"keys": [self.key.as_dict(private=False)]})
        patcher.start()
        self.addCleanup(patcher.stop)

    def sign(self, claims):
        return jwt.encode({"alg": "RS256", "kid": "delegation-test"}, claims, self.key)

    def job(self, **changes):
        return jobs.create_command_job(self.redis, self.config, self.identity, self.host, self.decision,
            "whoami", token=changes.pop("token", self.token), **changes)

    def test_job_stores_only_sealed_short_lived_credentials(self):
        record = self.job()
        self.assertEqual(record["schema_version"], 3)
        self.assertTrue(jobs.verify_job_signature(record, self.config))
        self.assertLessEqual(record["delegation_expires_at"], time.time() + 120)
        self.assertNotIn(self.token, json.dumps(record))
        self.assertNotIn(self.token, json.dumps(jobs.list_jobs(self.redis)))
        private = self.redis.get("delegated_identity_" + record["delegation_id"])
        self.assertNotIn(self.token, private)
        self.assertGreater(self.redis.ttl("delegated_identity_" + record["delegation_id"]), 0)
        identity, decision = delegation.recheck_delegation(self.redis, self.config, record, self.host)
        self.assertEqual(identity["keycloak_sub"], self.identity["keycloak_sub"])
        self.assertEqual(decision["remote_user"], "observer")

    def test_tampering_command_reference_ciphertext_and_binding_is_denied(self):
        record = self.job()
        altered = dict(record, command="sudo dangerous-command")
        self.assertFalse(jobs.verify_job_signature(altered, self.config))
        with self.assertRaises(IdentityError):
            delegation.recheck_delegation(self.redis, self.config, altered, self.host)
        private_key = "delegated_identity_" + record["delegation_id"]
        private = json.loads(self.redis.get(private_key))
        private["ciphertext"] = private["ciphertext"][:-5] + "AAAA="
        self.redis.set(private_key, json.dumps(private))
        with self.assertRaises(IdentityError):
            delegation.recheck_delegation(self.redis, self.config, record, self.host)

    def test_missing_expired_wrong_subject_and_wrong_signature_cannot_queue(self):
        for token in (None, self.sign(dict(self.claims, sub="other")), self.sign(dict(self.claims, exp=int(time.time()) - 1))):
            with self.subTest(token="missing" if token is None else "invalid"):
                with self.assertRaises(jobs.JobError):
                    self.job(token=token)
        wrong_key = RSAKey.generate_key(2048)
        bad = jwt.encode({"alg": "RS256"}, self.claims, wrong_key)
        with self.assertRaises(jobs.JobError):
            self.job(token=bad)
        self.assertEqual(jobs.list_jobs(self.redis), [])

    def test_idp_logout_and_private_delegation_revoke_deny_queued_job(self):
        record = self.job()
        self.redis.set(security._key(self.claims["iss"], "sid", "human-session"), "1")
        with mock.patch.object(jobs.subprocess, "Popen") as popen:
            finished = jobs.execute_job(self.redis, self.config, record)
        self.assertEqual(finished["status"], "failed")
        popen.assert_not_called()
        self.redis.delete(security._key(self.claims["iss"], "sid", "human-session"))
        second = self.job()
        delegation.revoke_delegation(self.redis, second["delegation_id"])
        with self.assertRaises(IdentityError):
            delegation.recheck_delegation(self.redis, self.config, second, self.host)

    def test_live_membership_removal_rechecks_current_grants(self):
        self.config["identity_security"]["membership"] = {"enabled": True}
        groups = ["Support"]
        with mock.patch.object(security, "_live_membership", side_effect=lambda *args: (list(groups), [])):
            record = self.job()
            delegation.recheck_delegation(self.redis, self.config, record, self.host)
            groups.clear()
            with self.assertRaises(IdentityError):
                delegation.recheck_delegation(self.redis, self.config, record, self.host)

    def test_route_or_policy_change_does_not_retarget_existing_delegation(self):
        record = self.job()
        with self.assertRaises(IdentityError):
            delegation.recheck_delegation(self.redis, self.config, record, dict(self.host, server_ip="127.0.0.2"))
        self.redis.set("grant_1", json.dumps(dict(self.grant, remote_user="root")))
        with self.assertRaises(IdentityError):
            delegation.recheck_delegation(self.redis, self.config, record, self.host)

    def test_fresh_step_up_is_bound_and_expiry_does_not_extend(self):
        self.config["identity_security"]["step_up"].update(enabled=True, required_projects=["prod"],
            acr_values=["2"], max_age_seconds=30)
        self.token = self.sign(dict(self.claims, acr="2"))
        record = self.job()
        self.assertLessEqual(record["delegation_expires_at"], self.claims["auth_time"] + 30)
        original = record["delegation_expires_at"]
        delegation.recheck_delegation(self.redis, self.config, record, self.host)
        self.assertEqual(record["delegation_expires_at"], original)
        with mock.patch.object(delegation.time, "time", return_value=original + 1):
            with self.assertRaises(IdentityError):
                delegation.recheck_delegation(self.redis, self.config, record, self.host)

    def test_human_approval_gate_is_not_bypassed_by_live_delegation(self):
        self.config["session_approval"].update(enabled=True, required_projects=["prod"])
        with self.assertRaisesRegex(jobs.JobError, "human session approval"):
            self.job()

    def test_delegated_retry_requires_fresh_authorization(self):
        record = self.job()
        record["status"] = "failed"
        jobs._save(self.redis, record)
        with self.assertRaisesRegex(jobs.JobError, "fresh submitter"):
            jobs.retry_job(self.redis, self.config, record["id"], self.identity)
        retry = jobs.retry_job(self.redis, self.config, record["id"], self.identity,
            current_identity=self.identity, token=self.token)
        self.assertNotEqual(retry["delegation_id"], record["delegation_id"])
        self.assertEqual(retry["retry_of"], record["id"])

    def test_mcp_audience_is_server_whitelisted_and_remains_bound(self):
        self.config["mcp"].update(enabled=True, expected_audience="isolate-mcp")
        token = self.sign(dict(self.claims, aud="isolate-mcp"))
        record = self.job(token=token)
        delegation.recheck_delegation(self.redis, self.config, record, self.host)
        self.config["mcp"]["expected_audience"] = "changed-audience"
        with self.assertRaises(IdentityError):
            delegation.recheck_delegation(self.redis, self.config, record, self.host)

    def test_worker_revocation_terminates_actual_running_subprocess(self):
        record = self.job()
        command = [sys.executable, "-u", "-c", "import time; print('started', flush=True); time.sleep(30)"]
        with mock.patch.object(jobs, "build_ssh_argv", return_value=command), mock.patch.object(jobs, "_audit"):
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = pool.submit(jobs.execute_job, self.redis, self.config, record)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    current = jobs.get_job(self.redis, record["id"])
                    if current.get("status") == "running":
                        break
                    time.sleep(0.02)
                else:
                    self.fail("worker did not start")
                self.redis.set(security._key(self.claims["iss"], "sid", "human-session"), "1")
                finished = future.result(timeout=8)
                self.assertEqual(finished["status"], "cancelled")
                self.assertIn("delegated authorization", finished["error"])
                self.assertNotIn(self.token, json.dumps(finished))
            finally:
                if not future.done():
                    jobs.request_job_cancel(self.redis, record["id"], {"username": "test-cleanup"})
                pool.shutdown(wait=True)

    def test_workload_identity_cannot_match_a_human_or_group_grant(self):
        self.config["keycloak"]["token_kind"] = "access_token"
        self.config["identity_security"]["introspection"]["enabled"] = True
        self.config["identity_security"]["workloads"] = {"enabled": True, "clients": {"automation": {
            "sub": "service-sub", "required_scopes": ["isolate.execute"], "allowed_actions": ["command"]}}}
        claims = dict(self.claims, sub="service-sub", azp="automation", isolate_principal_type="service",
            scope="isolate.execute", groups=["Support"], preferred_username="service-account-automation")
        token = self.sign(claims)
        identity = normalize_claims(claims)
        response = dict(claims, active=True)
        with mock.patch.object(security.KeycloakDeviceClient, "introspect", return_value=response):
            effective = security.refresh_identity(self.redis, self.config, identity, token)
            self.assertEqual(effective["groups"], [])
            with self.assertRaises(PolicyDenied):
                resolve_grant(effective, project="prod", host=self.host, grants=[self.grant], action="command")
            grant = dict(self.grant, subject="service", name="automation")
            self.redis.set("grant_1", json.dumps(grant))
            decision = resolve_grant(effective, project="prod", host=self.host, grants=[grant], action="command")
            record = jobs.create_command_job(self.redis, self.config, effective, self.host, decision, "whoami", token=token)
            self.assertEqual(record["principal_type"], "service")
            delegation.recheck_delegation(self.redis, self.config, record, self.host)
            self.config["identity_security"]["workloads"]["clients"]["automation"]["allowed_actions"] = []
            with self.assertRaises(IdentityError):
                delegation.recheck_delegation(self.redis, self.config, record, self.host)

    def test_workload_registration_requires_signed_marker_subject_client_and_scope(self):
        self.config["keycloak"]["token_kind"] = "access_token"
        self.config["identity_security"]["introspection"]["enabled"] = True
        self.config["identity_security"]["workloads"] = {"enabled": True, "clients": {"automation": {
            "sub": "service-sub", "required_scopes": ["isolate.runbook"], "allowed_actions": ["runbook"],
            "allowed_runbook_classes": ["read_only"]}}}
        claims = dict(self.claims, sub="service-sub", azp="automation", isolate_principal_type="service", scope="isolate.runbook")
        for update in ({"isolate_principal_type": "human"}, {"sub": "other"}, {"azp": "unregistered"},
                       {"scope": "isolate.read"}, {"aud": "untrusted"}):
            with self.subTest(update=update), self.assertRaises(IdentityError):
                security.workload_identity(self.config, self.sign(dict(claims, **update)))
        effective = security.workload_identity(self.config, self.sign(claims))
        security.assert_workload_action(self.config, effective, "runbook", "read_only")
        with self.assertRaises(IdentityError):
            security.assert_workload_action(self.config, effective, "runbook", "operational")
        with self.assertRaises(IdentityError):
            security.assert_workload_action(self.config, effective, "command")

    def test_service_runbook_can_execute_only_registered_class_and_explicit_grant(self):
        from isolate_runbooks import render_runbook
        self.config["keycloak"]["token_kind"] = "access_token"
        self.config["identity_security"]["introspection"]["enabled"] = True
        self.config["runbooks"].update(enabled=True)
        self.config["identity_security"]["workloads"] = {"enabled": True, "clients": {"automation": {
            "sub": "service-sub", "required_scopes": ["isolate.runbook"], "allowed_actions": ["runbook"],
            "allowed_runbook_classes": ["read_only"]}}}
        claims = dict(self.claims, sub="service-sub", azp="automation", isolate_principal_type="service", scope="isolate.runbook")
        token = self.sign(claims)
        effective = security.workload_identity(self.config, token)
        grant = dict(self.grant, subject="service", name="automation", allowed_actions=["runbook"])
        self.redis.set("grant_1", json.dumps(grant))
        decision = resolve_grant(effective, project="prod", host=self.host, grants=[grant], action="runbook")
        rendered = render_runbook(self.config, "uptime", {})
        with mock.patch.object(security.KeycloakDeviceClient, "introspect", return_value=dict(claims, active=True)):
            record = jobs.create_runbook_job(self.redis, self.config, effective, self.host, decision, rendered, token=token)
            self.assertEqual(record["principal_type"], "service")
            self.assertEqual(record["groups"], [])
            with mock.patch.object(jobs, "build_ssh_argv", return_value=[sys.executable, "-c", "print('ok')"]):
                finished = jobs.execute_job(self.redis, self.config, record)
            self.assertEqual(finished["status"], "completed")


class MembershipTest(unittest.TestCase):
    def setUp(self):
        self.redis = fakeredis.FakeRedis(decode_responses=True)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = Path(self.directory.name) / "membership.token"
        path.write_text("protected-management-token")
        path.chmod(0o600)
        self.config = {"keycloak": {"issuer": "https://id.example/auth/realms/company", "client_id": "isolate"},
            "identity_security": {"membership": {"enabled": True, "token_file": str(path)}}}
        self.identity = normalize_claims({"sub": "stable-sub", "preferred_username": "alice", "groups": ["old-group"]})

    def test_live_admin_groups_replace_old_claims_and_use_only_verified_subject(self):
        responses = [{"id": "stable-sub", "enabled": True}, [{"name": "new-group", "path": "/new-group"}], [{"name": "auditor"}]]
        with mock.patch.object(security, "_membership_get", side_effect=responses) as getter:
            effective = security.refresh_identity(self.redis, self.config, self.identity, "signature-verified-token")
        self.assertEqual(effective["groups"], ["new-group"])
        self.assertEqual(effective["roles"], ["auditor"])
        self.assertEqual(effective["raw_claims"]["groups"], ["old-group"])
        self.assertTrue(all(call.args[1].startswith("https://id.example/auth/admin/realms/company/users/stable-sub") for call in getter.call_args_list))

    def test_disabled_missing_claim_or_authority_outage_never_falls_back(self):
        for responses in ([{"id": "stable-sub", "enabled": False}], [{"id": "wrong", "enabled": True}],
                [{"id": "stable-sub", "enabled": True}, [{}]], [IdentityError("offline")]):
            with self.subTest(responses=responses), mock.patch.object(security, "_membership_get", side_effect=responses):
                with self.assertRaises(IdentityError):
                    security.refresh_identity(self.redis, self.config, self.identity, "verified-token")

    def test_management_credential_cache_never_caches_user_membership(self):
        secret = Path(self.directory.name) / "membership.secret"
        secret.write_text("client-secret")
        secret.chmod(0o600)
        self.config["identity_security"]["membership"] = {"enabled": True, "client_id": "read-only-membership",
            "client_secret_file": str(secret)}
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({"access_token": "short-admin-access-token",
            "token_type": "Bearer", "expires_in": 120}).encode()
        opener = mock.Mock()
        opener.open.return_value = response
        security._ADMIN_TOKENS.clear()
        with mock.patch.object(security.request, "build_opener", return_value=opener):
            token1 = security._management_token(self.config, self.config["keycloak"]["issuer"])
            token2 = security._management_token(self.config, self.config["keycloak"]["issuer"])
        self.assertEqual(token1, token2)
        opener.open.assert_called_once()
        self.assertIn(b"client_credentials", opener.open.call_args.args[0].data)
        # Each refresh below still performs live user+group+role calls.
        responses = [{"id": "stable-sub", "enabled": True}, [{"name": "first"}], [],
                     {"id": "stable-sub", "enabled": True}, [], []]
        with mock.patch.object(security, "_membership_get", side_effect=responses) as getter:
            one = security.refresh_identity(self.redis, self.config, self.identity, "verified-token")
            two = security.refresh_identity(self.redis, self.config, self.identity, "verified-token")
        self.assertEqual(one["groups"], ["first"])
        self.assertEqual(two["groups"], [])
        self.assertEqual(getter.call_count, 6)


if __name__ == "__main__":
    unittest.main()
