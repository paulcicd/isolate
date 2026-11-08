"""Real HTTP CRUD and CAS against authoritative SQLite with Redis leases."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import fakeredis
from flask import Flask
from isolate_api import register_api_routes
from isolate_config import DEFAULT_CONFIG
from isolate_identity import IdentityError
from isolate_state import SQLState, StateClient


class AdminAPITest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self.config["api"]["enabled"] = True
        self.config["dashboard"]["admin_groups"] = ["platform-admin"]
        self.config["logging"].update(sinks=[{"type": "jsonl", "path": str(self.root / "audit.jsonl")}])
        self.config["state"].update(backend="sqlite", sqlite_path=str(self.root / "control.sqlite"))
        SQLState(self.config["state"]).initialize()
        self.store = StateClient(fakeredis.FakeRedis(), self.config["state"])
        self.admin = {"keycloak_sub": "admin-subject", "username": "operator", "groups": ["platform-admin"],
            "raw_claims": {"scope": "isolate.inventory.write isolate.policy.write"}}
        self.machine = {"keycloak_sub": "robot-subject", "username": "terraform", "groups": [], "roles": [],
            "principal_type": "service", "service_client_id": "terraform",
            "raw_claims": {"scope": "isolate.inventory.write isolate.policy.write"}}
        self.config["identity_security"]["workloads"] = {"enabled": True, "clients": {"terraform": {
            "allowed_actions": ["inventory.write", "policy.write"], "admin_projects": ["stage"]}}}
        self.app = Flask(__name__)
        register_api_routes(self.app, self.config, lambda _: self.store, lambda: self.admin,
                            lambda: "browser-csrf", lambda: "admin-token")
        self.runtime = mock.patch("isolate_api.Runtime", side_effect=lambda *a, **k: SimpleNamespace(redis=self.store, authenticate=self.authenticate))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.client = self.app.test_client()
        self.host = {"project_name": "stage", "server_name": "app.example", "server_ip": "192.0.2.10", "server_user": "observer"}
        self.grant = {"subject": "group", "name": "Support", "project": "stage", "remote_user": "observer", "sudo_mode": "none", "allowed_actions": ["ssh"]}

    def authenticate(self, token):
        if token == "admin-token":
            return self.admin
        if token == "machine-token":
            return self.machine
        raise IdentityError("invalid token")

    def headers(self, token="admin-token", revision=None, key="unique-create-key-0001"):
        value = {"Authorization": "Bearer " + token, "Idempotency-Key": key}
        if revision:
            value["If-Match"] = revision
        return value

    def create(self, kind="host", values=None, **headers):
        response = self.client.post("/api/v1/admin/" + kind + "s", headers=self.headers(**headers),
                                    json={kind: values or getattr(self, kind), "confirm": True})
        self.assertEqual(response.status_code, 201, response.data)
        return response.get_json()[kind]

    def test_crud_revisions_idempotency_and_deleted_create_reconciliation(self):
        for kind in ("host", "grant"):
            with self.subTest(kind=kind):
                created = self.create(kind)
                resource_id = created.get("server_id") or created["id"]
                path = "/api/v1/admin/" + kind + "s/" + resource_id
                replay = self.client.post("/api/v1/admin/" + kind + "s", headers=self.headers(), json={kind: getattr(self, kind), "confirm": True})
                self.assertEqual(replay.status_code, 200)
                self.assertEqual(replay.get_json()[kind], created)
                self.assertEqual(self.client.get(path, headers=self.headers()).get_json()[kind], created)
                change = {"server_note": "reviewed"} if kind == "host" else {"name": "Operations"}
                self.assertEqual(self.client.put(path, headers=self.headers(), json={kind: change, "confirm": True}).status_code, 428)
                updated = self.client.put(path, headers=self.headers(revision='"' + created["_revision"] + '"'), json={kind: change, "confirm": True})
                self.assertEqual(updated.status_code, 200, updated.data)
                self.assertEqual(self.client.delete(path, headers=self.headers(revision=created["_revision"]), json={"confirm": True}).status_code, 409)
                revision = updated.get_json()[kind]["_revision"]
                self.assertEqual(self.client.delete(path, headers=self.headers(revision=revision), json={"confirm": True}).status_code, 204)
                self.assertEqual(self.client.get(path, headers=self.headers()).status_code, 404)
                deleted_replay = self.client.post("/api/v1/admin/" + kind + "s", headers=self.headers(), json={kind: getattr(self, kind), "confirm": True})
                self.assertEqual(deleted_replay.status_code, 409)
        self.assertTrue((self.root / "audit.jsonl").read_text())

    def test_machine_projects_scope_and_old_and_new_project_are_enforced(self):
        host = self.create(token="machine-token")
        production = self.create(values=dict(self.host, project_name="prod"), key="other-create-key-0001")
        listed = self.client.get("/api/v1/admin/hosts", headers=self.headers("machine-token")).get_json()["hosts"]
        self.assertEqual([row["server_id"] for row in listed], [host["server_id"]])
        path = "/api/v1/admin/hosts/" + host["server_id"]
        moved = self.client.put(path, headers=self.headers("machine-token", host["_revision"]), json={"host": {"project_name": "prod"}, "confirm": True})
        self.assertEqual(moved.status_code, 403)
        hidden = "/api/v1/admin/hosts/" + production["server_id"]
        self.assertEqual(self.client.get(hidden, headers=self.headers("machine-token")).status_code, 404)
        self.machine["raw_claims"]["scope"] = "isolate.read"
        self.assertEqual(self.client.get(path, headers=self.headers("machine-token")).status_code, 403)

    def test_signed_workload_authentication_reaches_scoped_admin_api_without_human_roles(self):
        from joserfc import jwt
        from joserfc.jwk import RSAKey
        self.runtime.stop()
        self.config["keycloak"].update(issuer="https://idp.example/realms/isolate", token_kind="access_token")
        self.config["identity_security"]["introspection"]["enabled"] = True
        client = self.config["identity_security"]["workloads"]["clients"]["terraform"]
        client.update(sub="workload-subject", required_scopes=["isolate.inventory.write"])
        claims = {"iss": self.config["keycloak"]["issuer"], "aud": "isolate-bastion", "sub": "workload-subject",
            "azp": "terraform", "preferred_username": "terraform", "isolate_principal_type": "service",
            "groups": ["platform-admin"], "scope": "isolate.inventory.write", "iat": int(time.time()), "exp": int(time.time()) + 300}
        key = RSAKey.generate_key(2048)
        token = jwt.encode({"alg": "RS256"}, claims, key)
        with mock.patch("isolate_identity.load_jwks", return_value={"keys": [key.as_dict(private=False)]}), \
                mock.patch("isolate_identity_security.KeycloakDeviceClient.introspect", return_value={"active": True, "sub": claims["sub"], "aud": claims["aud"]}):
            response = self.client.post("/api/v1/admin/hosts", headers=self.headers(token), json={"host": self.host, "confirm": True})
            self.assertEqual(response.status_code, 201, response.data)
            denied = self.client.post("/api/v1/admin/hosts", headers=self.headers(token, key="production-create-key-001"),
                json={"host": dict(self.host, project_name="prod"), "confirm": True})
            self.assertEqual(denied.status_code, 403)

    def test_broader_grants_managed_grants_and_gitops_are_protected(self):
        for selector in ({"project": "*"}, {"project_glob": "stage*"}):
            values = {k: v for k, v in self.grant.items() if k != "project"}
            response = self.client.post("/api/v1/admin/grants", headers=self.headers("machine-token"), json={"grant": dict(values, **selector), "confirm": True})
            self.assertEqual(response.status_code, 403, response.data)
        created = self.create("grant")
        key = "grant_" + created["id"]
        record = json.loads(self.store.get(key))
        record["managed_by"] = "access_package_9"
        self.store.set(key, json.dumps(record))
        path = "/api/v1/admin/grants/" + created["id"]
        current = self.client.get(path, headers=self.headers()).get_json()["grant"]
        self.assertEqual(self.client.delete(path, headers=self.headers(revision=current["_revision"]), json={"confirm": True}).status_code, 403)
        self.config["policy_as_code"]["enforce_git"] = True
        response = self.client.post("/api/v1/admin/grants", headers=self.headers(), json={"grant": self.grant, "confirm": True})
        self.assertEqual(response.status_code, 403)

    def test_browser_csrf_confirmation_human_scope_and_credential_redaction(self):
        self.assertEqual(self.client.post("/api/v1/admin/hosts", json={"host": self.host, "confirm": True}).status_code, 403)
        browser_headers = {"X-CSRF-Token": "browser-csrf", "Idempotency-Key": "browser-create-key-0001"}
        created = self.client.post("/api/v1/admin/hosts", headers=browser_headers, json={"host": self.host, "confirm": True})
        self.assertEqual(created.status_code, 201, created.data)
        self.admin["raw_claims"] = {"scope": "openid"}
        self.assertEqual(self.client.get("/api/v1/admin/hosts", headers=self.headers()).status_code, 403)
        self.admin["raw_claims"] = {"scp": ["isolate.inventory.write"]}
        self.store.set("server_17", json.dumps(dict(self.host, server_id=17, password="NEVER-EXPOSE", private_key="NEVER-EXPOSE")))
        result = self.client.get("/api/v1/admin/hosts/17", headers=self.headers())
        self.assertEqual(result.status_code, 200)
        self.assertNotIn(b"NEVER-EXPOSE", result.data)
        self.assertEqual(self.client.post("/api/v1/admin/hosts", headers=self.headers(), json={"host": dict(self.host, password="NO"), "confirm": True}).status_code, 400)

    def test_concurrent_idempotent_creates_and_compare_and_set_updates(self):
        def create(_):
            with self.app.test_client() as client:
                return client.post("/api/v1/admin/hosts", headers=self.headers(), json={"host": self.host, "confirm": True})
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(create, range(4)))
        self.assertEqual(sorted(row.status_code for row in responses), [200, 200, 200, 201])
        records = [row.get_json()["host"] for row in responses]
        self.assertEqual(len({row["server_id"] for row in records}), 1)
        record = records[0]
        def update(note):
            with self.app.test_client() as client:
                return client.put("/api/v1/admin/hosts/" + record["server_id"], headers=self.headers(revision=record["_revision"]),
                                  json={"host": {"server_note": note}, "confirm": True}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(update, ("first", "second"))), [200, 409])

    def test_unavailable_audit_prevents_mutation_and_reference_prevents_delete(self):
        with mock.patch("isolate_admin_api.prepare_and_dispatch", side_effect=__import__("isolate_audit").AuditSinkError("unavailable")):
            response = self.client.post("/api/v1/admin/hosts", headers=self.headers(), json={"host": self.host, "confirm": True})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.store.keys("server_*"), [])
        proxy = self.create()
        self.create(values=dict(self.host, server_name="other.example", proxy_id=proxy["server_id"]), key="proxy-create-key-0001")
        response = self.client.delete("/api/v1/admin/hosts/" + proxy["server_id"], headers=self.headers(revision=proxy["_revision"]), json={"confirm": True})
        self.assertEqual(response.status_code, 409)


if __name__ == "__main__":
    unittest.main()
