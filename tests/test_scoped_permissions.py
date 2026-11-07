"""Object, export and mutation boundaries for project-scoped management roles."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from isolate_permissions import PermissionDenied, authorize_inventory_change, filter_projects, has_permission, is_platform_admin, role_names
from isolate_policy import PolicyDenied, resolve_grant


class ScopedPermissionsTest(unittest.TestCase):
    def setUp(self):
        self.config = {"dashboard": {"admin_groups": ["Platform-Admins"], "role_bindings": [
            {"group": "Payments-Owners", "role": "project-owner", "projects": ["payments-prod"]},
            {"group": "Approvers", "role": "approver", "project_globs": ["analytics-*"]},
            {"group": "Auditors", "role": "auditor", "projects": ["payments-prod", "analytics-prod"]},
            {"group": "Inventory", "role": "inventory-operator", "projects": ["payments-stage"]},
        ]}}
        self.owner = {"username": "owner", "keycloak_sub": "owner-sub", "groups": ["Payments-Owners"]}
        self.approver = {"username": "approver", "groups": ["Approvers"]}
        self.auditor = {"username": "auditor", "groups": ["Auditors"]}
        self.operator = {"username": "operator", "groups": ["Inventory"]}
        self.admin = {"username": "admin", "groups": ["Platform-Admins"]}

    def test_owner_entry_is_distinct_from_object_scope(self):
        self.assertTrue(has_permission(self.owner, self.config, "inventory.write"))
        self.assertTrue(has_permission(self.owner, self.config, "inventory.write", "PAYMENTS-PROD"))
        self.assertFalse(has_permission(self.owner, self.config, "inventory.write", "payments-stage"))
        for project in ("", " ", 42, {}, []):
            with self.subTest(project=project):
                self.assertFalse(has_permission(self.owner, self.config, "inventory.write", project))

    def test_approver_globs_require_matching_project_and_never_grant_audit(self):
        self.assertTrue(has_permission(self.approver, self.config, "sessions.approve", "analytics-prod"))
        self.assertTrue(has_permission(self.approver, self.config, "access.approve", "analytics-stage"))
        self.assertFalse(has_permission(self.approver, self.config, "access.approve", "payments-prod"))
        self.assertFalse(has_permission(self.approver, self.config, "audit.read", "analytics-prod"))
        self.assertFalse(has_permission(self.approver, self.config, "inventory.write", "analytics-prod"))

    def test_auditor_is_read_only_and_operator_cannot_approve(self):
        self.assertTrue(has_permission(self.auditor, self.config, "audit.read", "payments-prod"))
        self.assertTrue(has_permission(self.auditor, self.config, "sessions.read", "analytics-prod"))
        for permission in ("inventory.write", "access.approve", "sessions.approve"):
            self.assertFalse(has_permission(self.auditor, self.config, permission, "payments-prod"))
        self.assertTrue(has_permission(self.operator, self.config, "inventory.write", "payments-stage"))
        self.assertFalse(has_permission(self.operator, self.config, "access.read", "payments-stage"))
        self.assertFalse(has_permission(self.operator, self.config, "access.approve", "payments-stage"))

    def test_table_and_export_use_identical_object_filter_with_missing_projects_denied(self):
        records = [
            {"id": "allowed", "project": "payments-prod"},
            {"id": "other", "project": "secret-prod"},
            {"id": "missing"},
            {"id": "empty", "project": ""},
            {"id": "none", "project": None},
        ]
        expected = [{"id": "allowed", "project": "payments-prod"}]
        for permission in ("audit.read", "sessions.read", "access.read"):
            self.assertEqual(filter_projects(records, self.auditor, self.config, permission), expected)
            self.assertEqual(filter_projects(iter(records), self.auditor, self.config, permission), expected)
        self.assertEqual(filter_projects(records, self.operator, self.config, "audit.read"), [])

    def test_inventory_field_and_current_project_move_are_rechecked(self):
        hosts = [{"server_id": "1", "project_name": "payments-stage"},
                 {"server_id": "2", "project_name": "payments-prod"}]
        self.assertEqual([row["server_id"] for row in filter_projects(hosts, self.operator, self.config, "inventory.read", "project_name")], ["1"])
        self.assertTrue(has_permission(self.operator, self.config, "inventory.write", hosts[0]["project_name"]))
        hosts[0]["project_name"] = "payments-prod"
        self.assertFalse(has_permission(self.operator, self.config, "inventory.write", hosts[0]["project_name"]))
        self.assertEqual(filter_projects(hosts, self.operator, self.config, "inventory.read", "project_name"), [])

    def test_roles_do_not_authorize_ssh_or_global_admin(self):
        self.assertEqual(role_names(self.owner, self.config), ["project-owner"])
        self.assertFalse(is_platform_admin(self.owner, self.config))
        for identity in (self.owner, self.auditor, self.approver, self.operator, self.admin):
            for action in ("ssh", "policy.write", "users.write", "credentials.read"):
                self.assertFalse(has_permission(identity, self.config, action, "payments-prod"))
            with self.assertRaises(PolicyDenied):
                resolve_grant(identity, project="payments-prod", grants=[])

    def test_combined_roles_union_their_scopes_without_cross_product_expansion(self):
        identity = {"groups": ["Auditors", "Inventory"]}
        self.assertEqual(role_names(identity, self.config), ["auditor", "inventory-operator"])
        self.assertTrue(has_permission(identity, self.config, "inventory.write", "payments-stage"))
        self.assertFalse(has_permission(identity, self.config, "inventory.write", "payments-prod"))
        self.assertTrue(has_permission(identity, self.config, "audit.read", "payments-prod"))
        self.assertFalse(has_permission(identity, self.config, "audit.read", "payments-stage"))

    def test_only_explicit_wildcard_scope_grants_all_projects(self):
        config = {"dashboard": {"role_bindings": [{"group": "Auditors", "role": "auditor", "projects": ["*"]}]}}
        self.assertTrue(has_permission(self.auditor, config, "audit.read", "any-project"))
        self.assertEqual(filter_projects([{"project": "any-project"}, {}], self.auditor, config, "audit.read"), [{"project": "any-project"}])

    def test_malformed_or_empty_bindings_fail_closed(self):
        bindings = [None, "role", {}, {"group": "Auditors", "role": [], "projects": ["*"]},
                    {"group": "Auditors", "role": "admin", "projects": ["*"]},
                    {"group": "Auditors", "role": "auditor"},
                    {"group": "Auditors", "role": "auditor", "projects": "*"},
                    {"group": "Auditors", "role": "auditor", "projects": ["*", None]},
                    {"group": "Auditors", "role": "auditor", "projects": [""]},
                    {"group": "Auditors", "role": "auditor", "project_globs": "*"}]
        for binding in bindings:
            config = {"dashboard": {"role_bindings": [binding]}}
            with self.subTest(binding=binding):
                self.assertFalse(has_permission(self.auditor, config, "audit.read"))
                self.assertEqual(role_names(self.auditor, config), [])
        for container in ("*", {"group": "Auditors"}, True):
            config = {"dashboard": {"role_bindings": container}}
            self.assertFalse(has_permission(self.auditor, config, "audit.read"))

    def test_groups_are_exact_verified_group_values(self):
        for identity in ({}, {"groups": "Payments-Owners"}, {"groups": ["Payments-Owners", None]},
                         {"groups": ["payments-owners"]}, {"roles": ["Payments-Owners"]},
                         {"username": "Payments-Owners", "groups": []}):
            with self.subTest(identity=identity):
                self.assertFalse(has_permission(identity, self.config, "inventory.write", "payments-prod"))

    def test_global_admin_fallback_preserved_without_scoped_escalation(self):
        self.assertTrue(is_platform_admin(self.admin, self.config))
        self.assertEqual(role_names(self.admin, self.config), ["admin"])
        self.assertTrue(has_permission(self.admin, self.config, "audit.read", "any-project"))
        self.assertEqual(filter_projects([{}, {"project": "x"}], self.admin, self.config, "audit.read"), [{}, {"project": "x"}])
        config = {"dashboard": {"admin_groups": []}, "history": {"admin_groups": ["History-Admins"]}}
        self.assertTrue(is_platform_admin({"groups": ["History-Admins"]}, config))
        config["dashboard"]["admin_groups"] = ["Other-Admins"]
        self.assertFalse(is_platform_admin({"groups": ["History-Admins"]}, config))
        config["dashboard"]["admin_groups"] = "History-Admins"
        self.assertFalse(is_platform_admin({"groups": ["History-Admins"]}, config))

    def test_removing_group_or_binding_revokes_management_permissions(self):
        self.assertTrue(has_permission(self.owner, self.config, "sessions.approve", "payments-prod"))
        self.assertFalse(has_permission(dict(self.owner, groups=[]), self.config, "sessions.approve", "payments-prod"))
        config = copy.deepcopy(self.config)
        config["dashboard"]["role_bindings"] = []
        self.assertFalse(has_permission(self.owner, config, "sessions.approve", "payments-prod"))

    def test_inventory_authorizer_allows_metadata_but_protects_routes_and_security(self):
        current = {"project_name": "payments-stage", "server_ip": "192.0.2.1", "server_port": 22,
                   "server_user": "support", "server_nosudo": True, "server_vip": True}
        authorize_inventory_change(self.operator, self.config, current, dict(current, resource_owner="payments", environment="stage"))
        for name, value in (("server_ip", "192.0.2.2"), ("server_port", 2222), ("server_user", "root"),
                            ("server_nosudo", False), ("server_vip", False), ("proxy_id", "12"),
                            ("privileged_access_url", "https://untrusted.example")):
            with self.subTest(name=name), self.assertRaises(PermissionDenied):
                authorize_inventory_change(self.operator, self.config, current, dict(current, **{name: value}))
        authorize_inventory_change(self.admin, self.config, current, dict(current, server_user="root", project_name="elsewhere"))

    def test_inventory_move_requires_old_and_new_project_scope(self):
        current = {"project_name": "payments-stage"}
        with self.assertRaises(PermissionDenied):
            authorize_inventory_change(self.operator, self.config, current, {"project_name": "payments-prod"})
        with self.assertRaises(PermissionDenied):
            authorize_inventory_change(self.operator, self.config, {"project_name": "payments-prod"}, current)
        config = copy.deepcopy(self.config)
        config["dashboard"]["role_bindings"][-1]["projects"].append("payments-prod")
        authorize_inventory_change(self.operator, config, current, {"project_name": "payments-prod"})


if __name__ == "__main__":
    unittest.main()
