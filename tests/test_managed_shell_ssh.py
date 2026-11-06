"""Real OpenSSH integration, confined to a temporary loopback-only sshd."""

import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from isolate_audit_export import AuditExporter
from isolate_logging import SessionLogger
from isolate_managed_shell import run_managed_shell
from isolate_ssh import build_ssh_argv


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
                     "Local SSH integration requires Linux root")
class ManagedSSHIntegrationTest(unittest.TestCase):
    def test_remote_status_closed_stdin_and_export_over_real_ssh(self):
        import pwd
        try:
            pwd.getpwnam("ubuntu")
        except KeyError:
            self.skipTest("Loopback integration fixture requires the Ubuntu admin account")
        if not Path("/usr/sbin/sshd").exists() or not shutil.which("ssh-keygen"):
            self.skipTest("OpenSSH server/keygen not installed")
        with tempfile.TemporaryDirectory(prefix="isolate-ssh-test-") as name:
            root = Path(name)
            root.chmod(0o755)
            for key in ("host", "client"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / key)], check=True)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            server_config = root / "sshd_config"
            server_config.write_text("\n".join([
                "ListenAddress 127.0.0.1", "Port {}".format(port), "HostKey {}".format(root / "host"),
                "PidFile {}".format(root / "sshd.pid"), "AuthorizedKeysFile {}".format(root / "client.pub"),
                "AllowUsers ubuntu", "PermitRootLogin no", "PubkeyAuthentication yes", "PasswordAuthentication no",
                "KbdInteractiveAuthentication no", "UsePAM yes", "StrictModes no", "AllowTcpForwarding no",
                "AllowAgentForwarding no", "PermitTTY no", "X11Forwarding no", "PermitTunnel no", "LogLevel ERROR", ""]))
            public_host = (root / "host.pub").read_text().split()
            (root / "known_hosts").write_text("[127.0.0.1]:{} {} {}\n".format(port, *public_host[:2]))
            client_config = root / "ssh_config"
            client_config.write_text("Host *\n  IdentityFile {}\n  UserKnownHostsFile {}\n  IdentitiesOnly yes\n  ConnectTimeout 5\n".format(root / "client", root / "known_hosts"))
            with (root / "sshd.log").open("w+") as server_log:
                server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(server_config)],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=server_log)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        if server.poll() is not None:
                            server_log.seek(0)
                            self.fail("Temporary sshd failed: " + server_log.read())
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                self.fail("Temporary sshd did not start")
                            time.sleep(0.05)
                    logs, spool = root / "logs", root / "spool"
                    spool.mkdir()
                    audit = SessionLogger(str(logs), {"username": "alice", "keycloak_sub": "test-only"}, session_id="ssh-test",
                                          logging_config={"sinks": [{"type": "jsonl", "path": str(spool / "audit.jsonl")}]})
                    argv = build_ssh_argv({"config_path": str(client_config), "managed_commands": True},
                                          {"hostname": "127.0.0.1", "port": port, "user": "ubuntu"})
                    def execute(argv, raw, control, stdin_null):
                        self.assertTrue(stdin_null)
                        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE, timeout=10)
                        self.assertEqual(completed.stderr, b"")
                        return completed.returncode
                    metadata = {"username": "alice", "keycloak_sub": "test-only", "connection_id": "ssh-test",
                                "host_id": "test-loopback", "sudo_mode": "none", "test_only": True}
                    code = run_managed_shell(argv, io.StringIO(), audit, metadata,
                                             {"command_audit": {"enabled": True, "mode": "managed"}}, execute,
                                             before_execute=lambda: False, control=lambda: False,
                                             input_stream=io.StringIO("test 'one two' = 'one two'; exit 7\nread ignored\nexit 255\necho not-run\n"),
                                             output_stream=io.StringIO())
                    self.assertEqual(code, 255)
                    with AuditExporter(logs, spool, spool / "events.jsonl", root / "state") as exporter:
                        self.assertEqual(exporter.run_once()["exported"], 6)
                    records = [json.loads(line) for line in (spool / "events.jsonl").read_text().splitlines()]
                    completed = [r for r in records if r["event"] == "command"]
                    self.assertEqual([r["exitcode"] for r in completed], [7, 1, None])
                    self.assertEqual([r["ssh_returncode"] for r in completed], [7, 1, 255])
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
