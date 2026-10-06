import os
import sys
import subprocess
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))
from isolate_service_discovery import discover_services, save_discovery, service_display
from isolate_ssh import SSHArgumentError


class MemoryRedis:
    def __init__(self):
        self.values = {}
    def get(self, key):
        return self.values.get(key)
    def set(self, key, value):
        self.values[key] = value


class ServiceDiscoveryTest(unittest.TestCase):
    host = {"server_id": "10001", "server_ip": "example.org", "server_services": "Payment API"}
    config = {"ssh": {}, "service_discovery": {"remote_user": "observer"}}

    def test_running_services_and_strict_noninteractive_ssh(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0,
            b"nginx.service loaded active running Web server\nssh.service loaded active running SSH server\n", b""))
        result = discover_services(self.host, self.config, runner=runner)
        self.assertTrue(result["ok"])
        self.assertEqual(result["services"], ["nginx.service", "ssh.service"])
        argv = runner.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertNotIn("-tt", argv)

    def test_failure_retains_previous_snapshot_and_manual_services(self):
        redis = MemoryRedis()
        save_discovery(redis, {"host_id": "10001", "ok": True, "services": ["nginx.service"], "checked_at": 100})
        runner = mock.Mock(side_effect=subprocess.TimeoutExpired("ssh", 10))
        result = save_discovery(redis, discover_services(self.host, self.config, runner=runner))
        self.assertFalse(result["ok"])
        self.assertEqual(result["services"], ["nginx.service"])
        self.assertEqual(result["checked_at"], 100)
        self.assertIn("Payment API", service_display(self.host, result))
        self.assertIn("latest scan failed", service_display(self.host, result))
        self.assertEqual(self.host["server_services"], "Payment API")

    def test_empty_success_replaces_previous_services(self):
        redis = MemoryRedis()
        save_discovery(redis, {"host_id": "10001", "ok": True, "services": ["old.service"]})
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
        result = save_discovery(redis, discover_services(self.host, self.config, runner=runner))
        self.assertEqual(result["services"], [])

    def test_invalid_output_is_not_a_successful_empty_scan(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"Permission denied\n", b""))
        self.assertFalse(discover_services(self.host, self.config, runner=runner)["ok"])

    def test_invalid_target_does_not_run_ssh(self):
        runner = mock.Mock()
        with self.assertRaises(SSHArgumentError):
            discover_services(dict(self.host, server_ip="-oProxyCommand=evil"), self.config, runner=runner)
        runner.assert_not_called()

    def test_inventory_snapshot_is_searchable_without_changing_revision(self):
        import json
        from isolate_inventory import get_host, list_hosts, update_host
        redis = MemoryRedis()
        redis.keys = lambda pattern: ["server_10001"]
        redis.set("server_10001", json.dumps(dict(self.host, project_name="prod", server_name="node")))
        before = get_host(redis, "10001")
        save_discovery(redis, {"host_id": "10001", "ok": True, "services": ["nginx.service"], "checked_at": 100})
        after = get_host(redis, "10001")
        self.assertEqual(after["_revision"], before["_revision"])
        self.assertEqual(after["server_services"], "Payment API")
        self.assertEqual(len(list_hosts(redis, query="nginx")), 1)
        update_host(redis, "10001", {"server_note": "edited"}, expected_revision=before["_revision"])
        self.assertEqual(get_host(redis, "10001")["server_services"], "Payment API")
