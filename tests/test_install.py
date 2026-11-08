"""Release selection changes code, never authoritative state or secret material."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import runpy
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import isolate_install as install


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source, self.root = self.base / "source", self.base / "installation"
        for name in install.CODE_DIRECTORIES:
            (self.source / name).mkdir(parents=True)
        (self.source / "shared/isolate_state.py").write_text("SCHEMA_VERSION = 1\n")
        (self.source / "scripts/isolate-service.py").write_text("print('service')\n")
        (self.source / "wrappers/ssh.py").write_text("print('ssh')\n")
        (self.source / "requirements.txt").write_text("")
        (self.source / "keys").mkdir()
        (self.source / "keys/do-not-copy").write_text("SENSITIVE")
        (self.source / "configs").mkdir()
        (self.source / "configs/do-not-copy.yml").write_text("password: SENSITIVE")
        self.config = self.base / "config.yml"
        self.config.write_text("schema_version: 2\nstate:\n  backend: sqlite\n")
        self.config.chmod(0o600)
        self.state = self.base / "authority.sqlite"
        self.state.write_bytes(b"external SQL authority generation=stable epoch=stable")
        self.healthy = {"ok": True, "authority": {"backend": "sqlite", "schema_version": 1,
            "generation": "stable", "epoch": "stable"}, "issuer": "https://idp.example/realm",
            "keys": {"recordings.signing_key_file": "persistent-signing-key-hash"}}

    def environment(self, release):
        (release / ".venv").mkdir()
        (release / ".venv/library.py").write_text("trusted dependency")
        return "library==1.0\n"

    def stage(self, version="1.0.0"):
        plan = install.plan_release(self.root, self.source, version, self.config)
        return install.stage_release(self.root, self.source, version, self.config,
            plan["source_sha256"], dependency_installer=self.environment)

    def activate(self, staged, probe=None, rollback=False):
        operation = install.rollback_release if rollback else install.activate_release
        return operation(self.root, staged["version"], self.config, staged["release_sha256"],
            probe=probe or (lambda *args: copy.deepcopy(self.healthy)))

    def test_plan_is_read_only_and_excludes_secrets_and_runtime(self):
        plan = install.plan_release(self.root, self.source, "1.0.0", self.config)
        self.assertFalse(self.root.exists())
        self.assertFalse(plan["state_migration"])
        self.assertEqual(set(plan["files"]), {"requirements.txt", "shared/isolate_state.py",
            "scripts/isolate-service.py", "wrappers/ssh.py"})
        self.assertNotIn("SENSITIVE", json.dumps(plan))

    def test_stage_requires_reviewed_digest_and_is_immutable(self):
        with self.assertRaisesRegex(install.InstallError, "reviewed"):
            install.stage_release(self.root, self.source, "1.0.0", self.config, "0" * 64)
        self.assertFalse(self.root.exists())
        staged = self.stage()
        self.assertEqual(install.verify_release(self.root, "1.0.0", staged["release_sha256"])["state_schema_max"], 1)
        with self.assertRaisesRegex(install.InstallError, "immutable"):
            self.stage()
        self.assertFalse((Path(staged["path"]) / "keys").exists())
        self.assertFalse((Path(staged["path"]) / "configs").exists())

    def test_tampering_source_dependencies_and_extra_modules_is_rejected(self):
        for version, target in (("1.0.0", "shared/isolate_state.py"), ("1.0.1", ".venv/library.py"),
                ("1.0.2", "shared/sitecustomize.py")):
            with self.subTest(target=target):
                staged = self.stage(version)
                path = Path(staged["path"]) / target
                if path.exists():
                    path.chmod(0o600)
                path.write_text("injected")
                with self.assertRaises(install.InstallError):
                    install.verify_release(self.root, version, staged["release_sha256"])

    def test_failed_dependency_stage_cannot_be_selected(self):
        plan = install.plan_release(self.root, self.source, "1.0.0", self.config)
        def fail(path):
            raise install.InstallError("dependencies unavailable")
        with self.assertRaises(install.InstallError):
            install.stage_release(self.root, self.source, "1.0.0", self.config, plan["source_sha256"], fail)
        self.assertFalse((self.root / "releases/1.0.0/release.json").exists())
        self.assertIsNone(install.status(self.root)["active"])

    def test_activation_upgrade_and_rollback_preserve_external_authority(self):
        original_config, original_state = self.config.read_bytes(), self.state.read_bytes()
        first, second = self.stage(), self.stage("1.1.0")
        self.activate(first)
        self.assertEqual(install.status(self.root)["version"], "1.0.0")
        self.activate(second)
        selected = self.activate(first, rollback=True)
        self.assertEqual(selected["operation"], "rollback")
        self.assertFalse(selected["database_restored"])
        self.assertFalse(selected["restart_services"])
        self.assertEqual(self.config.read_bytes(), original_config)
        self.assertEqual(self.state.read_bytes(), original_state)
        if os.name == "posix":
            self.assertEqual((self.root / "current/scripts/isolate-service.py").read_text(), "print('service')\n")

    def test_unhealthy_candidate_does_not_replace_current(self):
        first, second = self.stage(), self.stage("1.1.0")
        self.activate(first)
        with self.assertRaisesRegex(install.InstallError, "health"):
            self.activate(second, probe=lambda *args: {"ok": False})
        self.assertEqual(install.status(self.root)["version"], "1.0.0")

    def test_service_bootstrap_execs_immutable_version_paths(self):
        first = self.stage()
        self.activate(first)
        bootstrap = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/isolate-run.py"))
        with mock.patch.object(os, "execv") as execute:
            bootstrap["main"](["--root", str(self.root), "dashboard", "--config", str(self.config), "--check"])
        executable, argv = execute.call_args.args
        self.assertIn(str(self.root / "releases/1.0.0/.venv"), executable)
        self.assertEqual(argv[3], str(self.root / "releases/1.0.0/scripts/isolate-service.py"))
        self.assertNotIn(str(self.root / "current"), executable)
        self.assertIn("--check", argv)

    def test_authority_issuer_or_signing_key_change_is_rejected(self):
        first, second = self.stage(), self.stage("1.1.0")
        self.activate(first)
        for field in ("authority", "issuer", "keys"):
            candidate = copy.deepcopy(self.healthy)
            candidate[field] = {"different": True} if field != "issuer" else "https://other.example"
            with self.subTest(field=field), self.assertRaisesRegex(install.InstallError, "authority"):
                self.activate(second, probe=lambda path, *args: candidate if path.name == "1.1.0" else self.healthy)
        self.assertEqual(install.status(self.root)["version"], "1.0.0")

    def test_rollback_rejects_newer_database_schema(self):
        first, second = self.stage(), self.stage("1.1.0")
        self.activate(first)
        self.activate(second)
        newer = copy.deepcopy(self.healthy)
        newer["authority"]["schema_version"] = 2
        with self.assertRaisesRegex(install.InstallError, "schema"):
            self.activate(first, probe=lambda *args: newer, rollback=True)
        self.assertEqual(install.status(self.root)["version"], "1.1.0")

    def test_config_credentials_relative_paths_and_traversal_are_rejected(self):
        self.config.write_text("oidc:\n  client_secret: NEVER-PRINT-THIS\n")
        with self.assertRaises(install.InstallError) as caught:
            install.plan_release(self.root, self.source, "1.0.0", self.config)
        self.assertNotIn("NEVER-PRINT-THIS", str(caught.exception))
        self.config.write_text("oidc: [NEVER-PRINT-THIS\n")
        with self.assertRaises(install.InstallError) as malformed:
            install.plan_release(self.root, self.source, "1.0.0", self.config)
        self.assertNotIn("NEVER-PRINT-THIS", str(malformed.exception))
        with self.assertRaises(install.InstallError):
            install.status("relative/path")
        with self.assertRaises(install.InstallError):
            install.verify_release(self.root, "../escape", "0" * 64)

    @unittest.skipUnless(os.name == "posix", "POSIX atomic service pointer")
    def test_pointer_failure_leaves_old_selection_consistent(self):
        first, second = self.stage(), self.stage("1.1.0")
        self.activate(first)
        original = os.replace
        def fail_pointer(source, destination):
            if Path(destination) == self.root / "current":
                raise OSError("simulated pointer failure")
            return original(source, destination)
        with mock.patch.object(install.os, "replace", side_effect=fail_pointer), self.assertRaises(OSError):
            self.activate(second)
        self.assertEqual(install.status(self.root)["version"], "1.0.0")

    @unittest.skipUnless(os.name == "posix", "POSIX ownership and symlinks")
    def test_untrusted_config_and_symlink_directory_rejected(self):
        self.config.chmod(0o644)
        with self.assertRaisesRegex(install.InstallError, "owner-only"):
            install.plan_release(self.root, self.source, "1.0.0", self.config)
        self.config.chmod(0o600)
        self.root.mkdir()
        (self.root / "releases").symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(install.InstallError):
            self.stage()

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0, "Linux deployment owner/service separation")
    def test_root_operator_accepts_private_config_owned_by_intended_service(self):
        import pwd
        account = pwd.getpwnam("auth")
        os.chown(self.config, account.pw_uid, account.pw_gid)
        plan = install.plan_release(self.root, self.source, "1.0.0", self.config)
        self.assertEqual(plan["config"], str(self.config))
        self.config.chmod(0o640)
        with self.assertRaises(install.InstallError):
            install.plan_release(self.root, self.source, "1.0.0", self.config)


class HelmTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("helm"), "Helm binary is required for chart integration")
    def test_chart_lint_render_security_and_external_dependencies(self):
        chart = Path(__file__).resolve().parents[1] / "deploy/helm/isolate"
        lint = subprocess.run(["helm", "lint", str(chart), "--strict"], capture_output=True, text=True)
        self.assertEqual(lint.returncode, 0, lint.stdout + lint.stderr)
        rendered = subprocess.run(["helm", "template", "test", str(chart)], capture_output=True, text=True)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        import yaml
        objects = list(yaml.safe_load_all(rendered.stdout))
        deployments = [item for item in objects if item and item["kind"] == "Deployment"]
        self.assertEqual(len(deployments), 1)
        all_components = subprocess.run(["helm", "template", "test", str(chart), "--set", "gateway.enabled=true,jobs.enabled=true,recordings.enabled=true"], capture_output=True, text=True)
        self.assertEqual(all_components.returncode, 0, all_components.stderr)
        self.assertEqual(sum(1 for item in yaml.safe_load_all(all_components.stdout) if item and item["kind"] == "Deployment"), 4)
        for item in deployments:
            pod = item["spec"]["template"]["spec"]
            self.assertFalse(pod["automountServiceAccountToken"])
            container = pod["containers"][0]
            security = container["securityContext"]
            self.assertTrue(security["runAsNonRoot"])
            self.assertTrue(security["readOnlyRootFilesystem"])
            self.assertFalse(security["allowPrivilegeEscalation"])
            self.assertEqual(security["capabilities"]["drop"], ["ALL"])
            self.assertIn("--config", container["args"])
            self.assertIn("readinessProbe", container)
        self.assertFalse(any(item and item["kind"] == "Secret" for item in objects))
        self.assertFalse(any(item and item["kind"] == "Job" for item in objects))
        self.assertIn("/ready", rendered.stdout)
        migration = subprocess.run(["helm", "template", "test", str(chart), "--set", "migration.enabled=true"],
            capture_output=True, text=True)
        self.assertNotEqual(migration.returncode, 0)
        invalid = subprocess.run(["helm", "template", "test", str(chart), "--set", "gateway.replicas=0"],
            capture_output=True, text=True)
        self.assertNotEqual(invalid.returncode, 0)


if __name__ == "__main__":
    unittest.main()
