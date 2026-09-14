import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class BootstrapRuntimeTest(unittest.TestCase):
    def test_python_entrypoints_use_configured_runtime(self):
        path = os.path.join(ROOT, "shared", "bootstrap.sh")
        with open(path, "r", encoding="utf-8") as bootstrap_f:
            source = bootstrap_f.read()

        self.assertIn('${ISOLATE_DATA_ROOT}/.venv/bin/python3', source)
        self.assertIn('export ISOLATE_PYTHON;', source)
        self.assertIn('"${ISOLATE_PYTHON}" "${ISOLATE_CLI}"', source)
        self.assertIn('"${ISOLATE_PYTHON}" "${ISOLATE_HELPER}"', source)
        self.assertNotIn('auth_callback "${ISOLATE_HELPER}"', source)

    def test_permission_repair_preserves_virtualenv_runtime(self):
        path = os.path.join(ROOT, "scripts", "fix-perms.sh")
        with open(path, "r", encoding="utf-8") as permissions_f:
            source = permissions_f.read()

        self.assertIn('${AUTH_DATA_ROOT}/.venv/bin', source)
        self.assertIn('-type d -print0', source)
        self.assertIn('-maxdepth 1 -type f -print0', source)
        self.assertIn('chmod 0750', source)


if __name__ == "__main__":
    unittest.main()
