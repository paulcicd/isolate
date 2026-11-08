import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from flask import Flask
from isolate_api import register_api_routes
from isolate_config import DEFAULT_CONFIG
from isolate_openapi import build_openapi, catalogue, registered_operations, register_openapi_routes, undocumented_operations


class OpenAPIContractTest(unittest.TestCase):
    def app(self, enabled=True):
        app = Flask(__name__)
        config = copy.deepcopy(DEFAULT_CONFIG)
        config["api"]["enabled"] = enabled
        register_api_routes(app, config, lambda _: None, lambda: None, lambda: "csrf", lambda: None)
        # Application integration may register these centrally or in the API registrar.
        if "/api/v1/openapi.json" not in {rule.rule for rule in app.url_map.iter_rules()}:
            register_openapi_routes(app, config)
        return app

    def test_every_registered_control_operation_has_an_explicit_contract(self):
        app = self.app()
        self.assertEqual(undocumented_operations(app), [])
        document = build_openapi(app)
        actual = {(path, method) for path, methods in document["paths"].items() for method in methods}
        self.assertEqual(actual, registered_operations(app))
        self.assertNotIn("/me/terminal", document["paths"])

    def test_unknown_operation_fails_coverage_instead_of_being_guessed(self):
        app = self.app()
        app.add_url_rule("/api/v1/undocumented/<int:resource_id>", view_func=lambda resource_id: "", methods=["PUT"])
        self.assertEqual(undocumented_operations(app), [("/api/v1/undocumented/{resource_id}", "put")])
        with self.assertRaisesRegex(ValueError, "missing registered operations"):
            build_openapi(app)

    def test_json_yaml_match_and_document_is_independent(self):
        import yaml
        app = self.app()
        client = app.test_client()
        document = client.get("/api/v1/openapi.json").get_json()
        response = client.get("/api/v1/openapi.yaml")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(yaml.safe_load(response.data), document)
        document["paths"].clear()
        self.assertTrue(build_openapi(app)["paths"])
        self.assertEqual(self.app(False).test_client().get("/api/v1/openapi.json").status_code, 404)
        version = client.get("/api/v1/version")
        self.assertEqual(version.status_code, 200)
        self.assertIsInstance(version.get_json()["schema_version"], int)

    def test_authentication_mutations_and_revisions_are_explicit(self):
        document = build_openapi()
        self.assertEqual(document["openapi"], "3.1.1")
        paths = document["paths"]
        for path, methods in paths.items():
            for method, operation in methods.items():
                self.assertTrue(operation["operationId"])
                self.assertTrue(operation["responses"])
                if method in ("post", "put", "patch", "delete") and path != "/auth/backchannel-logout":
                    self.assertIn({"BrowserSession": [], "CSRFToken": []}, operation["security"])
        for kind in ("host", "grant"):
            paths_for_kind = paths["/api/v1/admin/" + kind + "s/{" + kind + "_id}"]
            for method in ("put", "delete"):
                self.assertIn("428", paths_for_kind[method]["responses"])
                self.assertIn({"$ref": "#/components/parameters/IfMatch"}, paths_for_kind[method]["parameters"])
            self.assertNotIn("content", paths_for_kind["delete"]["responses"]["204"])

    def test_local_references_and_operation_ids_are_valid(self):
        document = build_openapi()
        identifiers = []
        def walk(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    target = document
                    for piece in value["$ref"].removeprefix("#/").split("/"):
                        target = target[piece]
                    self.assertIsInstance(target, dict)
                if "operationId" in value:
                    identifiers.append(value["operationId"])
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(document)
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertGreater(len(identifiers), 25)
        # Every path variable must be required and explicitly typed.
        import re
        for path, methods in catalogue().items():
            for operation in methods.values():
                names = {p.get("name") for p in operation.get("parameters", []) if p.get("in") == "path" and p.get("required")}
                self.assertEqual(set(re.findall(r"\{([^}]+)\}", path)), names)


if __name__ == "__main__":
    unittest.main()
