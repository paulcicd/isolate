"""Actual loopback SSH and WebSocket exchanges through the gateway.

Only the control-plane/credential provider is a fixture. Both SSH legs use real
host keys, real protocol negotiation and real channels; no external host is used.
"""

import asyncio
from contextlib import contextmanager
import copy
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

try:
    import asyncssh
    import aiohttp
    from aiohttp.test_utils import TestServer
    import isolate_gateway as gateway
except ImportError:
    asyncssh = None


class FixtureRuntime:
    def __init__(self, config, host):
        self.config = config
        self.host = host
        self.tickets = {}
        self.started = []
        self.finished = []
        self.output = []
        self.events = []
        self.revoked = threading.Event()
        self.lock = threading.Lock()

    def ticket(self, name, protocol="ssh"):
        self.tickets[name] = {
            "connection_id": name, "protocol": protocol,
            "host": dict(self.host), "decision": {"remote_user": "support", "sudo_mode": "none"},
            "identity": {"username": "alice", "keycloak_sub": "human-1"}, "proxy": None,
        }
        return name

    def consume_ticket(self, value, protocol="ssh", source_ip=None):
        with self.lock:
            context = self.tickets.pop(value, None)
        if context is None or context["protocol"] != protocol:
            raise ValueError("Invalid or used ticket")
        return context

    def prepare(self, context):
        self.recheck(context)
        return context

    def start(self, context):
        self.started.append(context["connection_id"])

    def recheck(self, context):
        if self.revoked.is_set():
            raise ValueError("Revoked by identity provider")

    def finish(self, context, exit_code=None):
        self.finished.append((context["connection_id"], exit_code))

    def record_output(self, context, value):
        self.output.append(value)

    def authorize_channel(self, context, action, destination=None):
        self.recheck(context)
        if action == "ssh":
            return None
        if action not in context.get("channel_actions", []):
            raise ValueError("Channel action is not permitted")
        if action == "forward":
            for item in self.config.get("gateway", {}).get("forwarding_targets", {}).get("42", []):
                if destination == {"host": item["host"], "port": item["port"]}:
                    return {"host": item["address"], "port": item["port"]}
            raise ValueError("Forward destination is not permitted")
        return None

    def channel_event(self, context, event, **fields):
        self.events.append({"event": event, **fields})


@unittest.skipUnless(asyncssh, "Gateway integration requires asyncssh and aiohttp")
class GatewayIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="isolate-gateway-")
        self.root = Path(self.temporary.name)
        self.upstream_key = asyncssh.generate_private_key("ssh-ed25519")
        self.gateway_key = asyncssh.generate_private_key("ssh-ed25519")
        self.gateway_key.write_private_key(str(self.root / "gateway_key"))
        self.target_users = []
        self.sftp_root = self.root / "target-files"
        self.sftp_root.mkdir()
        owner = self

        class Target(asyncssh.SSHServer):
            def begin_auth(self, username):
                owner.target_users.append(username)
                return False

            def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
                return True

        async def target_process(process):
            if process.command:
                process.stdout.write(b"exec:" + process.command.encode() + b"\n")
                process.exit(7)
                return
            process.stdout.write(b"target-ready\n")
            while True:
                try:
                    value = await process.stdin.read(32768)
                except asyncssh.TerminalSizeChanged:
                    continue
                if not value or value == b"exit\n":
                    break
                process.stdout.write(b"target:" + value)
            process.exit(0)

        self.target = await asyncssh.create_server(
            Target, "127.0.0.1", 0, server_host_keys=[self.upstream_key],
            process_factory=target_process, encoding=None,
            sftp_factory=lambda channel: asyncssh.SFTPServer(channel, chroot=str(self.sftp_root)),
        )
        target_port = self.target.get_port()
        (self.root / "known_hosts").write_bytes(
            ("[127.0.0.1]:{} ".format(target_port)).encode() + self.upstream_key.export_public_key()
        )
        self.config = {"gateway": {
            "enabled": True, "host_key_file": str(self.root / "gateway_key"),
            "known_hosts": str(self.root / "known_hosts"), "recheck_interval": 0.2,
            "allowed_origins": ["https://isolate.example.org"],
        }}
        self.runtime = FixtureRuntime(self.config, {
            "server_id": "42", "server_ip": "127.0.0.1", "server_port": target_port,
        })

        @contextmanager
        def credentials(config, host, identity, connection_id):
            # Malicious provider username cannot override policy's support.
            yield {"client_keys": [], "known_hosts": str(self.root / "known_hosts"), "username": "root"}

        self.provider = mock.patch.dict(sys.modules, {
            "isolate_credentials": type("Credentials", (), {"ssh_credentials": staticmethod(credentials)})
        })
        self.provider.start()
        self.gateway = await gateway.create_native_listener(self.runtime, "127.0.0.1", 0)
        self.native_port = self.gateway.get_port()
        (self.root / "gateway_known_hosts").write_bytes(
            ("[127.0.0.1]:{} ".format(self.native_port)).encode() + self.gateway_key.export_public_key()
        )
        self.web = TestServer(gateway.create_web_app(self.runtime))
        await self.web.start_server()
        self.http = aiohttp.ClientSession()

    async def asyncTearDown(self):
        await self.http.close()
        await self.web.close()
        self.gateway.close()
        await self.gateway.wait_closed()
        self.target.close()
        await self.target.wait_closed()
        self.provider.stop()
        self.temporary.cleanup()

    async def connect(self, ticket, username="42"):
        return await asyncssh.connect(
            "127.0.0.1", self.native_port, username=username, password=ticket,
            known_hosts=str(self.root / "gateway_known_hosts"), config=[], client_keys=[],
            agent_path=None, preferred_auth="password", login_timeout=3,
        )

    async def wait_finished(self, connection_id):
        async with asyncio.timeout(5):
            while not any(item[0] == connection_id for item in self.runtime.finished):
                await asyncio.sleep(0.01)

    async def test_native_exec_preserves_exit_status_and_policy_remote_user(self):
        ticket = self.runtime.ticket("native-exec")
        async with await self.connect(ticket) as client:
            result = await client.run("id -un", check=False)
        self.assertEqual(result.stdout, "exec:id -un\n")
        self.assertEqual(result.exit_status, 7)
        self.assertEqual(self.target_users, ["support"])
        self.assertEqual(self.runtime.output, [b"exec:id -un\n"])
        self.assertIn((ticket, 7), self.runtime.finished)
        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(ticket)

    async def test_wrong_resource_username_and_protocol_are_denied(self):
        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(self.runtime.ticket("wrong-name"), username="root")
        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(self.runtime.ticket("web-only", "webssh"))
        self.assertEqual(self.target_users, [])

    async def test_native_forwarding_and_second_session_are_denied(self):
        async with await self.connect(self.runtime.ticket("one-channel")) as client:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await client.open_connection("127.0.0.1", self.target.get_port())
            process = await client.create_process()
            self.assertEqual(await process.stdout.readline(), "target-ready\n")
            with self.assertRaises(asyncssh.ChannelOpenError):
                await client.run("id", check=False)
            process.stdin.write("exit\n")
            await asyncio.wait_for(process.wait(), 3)

    async def test_revocation_closes_live_native_session(self):
        async with await self.connect(self.runtime.ticket("revoke")) as client:
            process = await client.create_process()
            self.assertEqual(await process.stdout.readline(), "target-ready\n")
            self.runtime.revoked.set()
            result = await asyncio.wait_for(process.wait(), 3)
            self.assertIn(result.exit_status, (None, 255))
        await self.wait_finished("revoke")
        self.assertIn(("revoke", 255), self.runtime.finished)

    async def test_upstream_host_key_mismatch_fails_closed(self):
        self.upstream_key = asyncssh.generate_private_key("ssh-ed25519")
        (self.root / "known_hosts").write_bytes(
            ("[127.0.0.1]:{} ".format(self.target.get_port())).encode() + self.upstream_key.export_public_key()
        )
        async with await self.connect(self.runtime.ticket("bad-host-key")) as client:
            result = await client.run("id", check=False)
        self.assertEqual(result.exit_status, 255)
        self.assertEqual(self.target_users, [])

    async def test_managed_profile_cannot_be_bypassed_using_native_ingress(self):
        self.config["command_audit"] = {"enabled": True, "mode": "managed"}
        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(self.runtime.ticket("managed"))
        self.assertEqual(self.target_users, [])

    async def test_legacy_config_cannot_override_inventory_route_or_remote_user(self):
        config_path = self.root / "client.conf"
        config_path.write_text("Host *\n  HostName 127.0.0.2\n  User root\n  ProxyCommand false\n  StrictHostKeyChecking no\n")

        @contextmanager
        def legacy(config, host, identity, connection_id):
            yield {"config": [str(config_path)], "known_hosts": str(self.root / "known_hosts")}

        with mock.patch.object(sys.modules["isolate_credentials"], "ssh_credentials", legacy):
            async with await self.connect(self.runtime.ticket("legacy-config")) as client:
                result = await client.run("id", check=False)
        self.assertEqual(result.stdout, "exec:id\n")
        self.assertEqual(self.target_users, ["support"])

    async def test_websocket_streams_input_output_and_exit(self):
        ticket = self.runtime.ticket("web-stream", "webssh")
        async with self.http.ws_connect(self.web.make_url("/ssh"), origin="https://isolate.example.org") as ws:
            await ws.send_json({"ticket": ticket, "cols": 80, "rows": 24})
            self.assertEqual((await ws.receive_json())["state"], "waiting")
            self.assertEqual((await ws.receive_json())["state"], "connected")
            self.assertEqual((await ws.receive()).data, b"target-ready\n")
            await ws.send_json({"type": "resize", "cols": 100, "rows": 30})
            await ws.send_json({"type": "input", "data": "hello\n"})
            self.assertEqual((await ws.receive()).data, b"target:hello\n")
            await ws.send_json({"type": "input", "data": "exit\n"})
            value = await ws.receive_json()
            self.assertEqual(value, {"type": "exit", "code": 0})
        self.assertEqual(self.target_users, ["support"])

    async def test_websocket_origin_and_protocol_ticket_boundaries(self):
        with self.assertRaises(aiohttp.WSServerHandshakeError) as failure:
            await self.http.ws_connect(self.web.make_url("/ssh"), origin="https://evil.example.org")
        self.assertEqual(failure.exception.status, 403)
        async with self.http.ws_connect(self.web.make_url("/ssh"), origin="https://isolate.example.org") as ws:
            await ws.send_json({"ticket": self.runtime.ticket("native-only", "ssh")})
            self.assertEqual((await ws.receive_json())["type"], "error")
        self.assertEqual(self.target_users, [])

    async def test_websocket_revocation_closes_live_terminal(self):
        async with self.http.ws_connect(self.web.make_url("/ssh"), origin="https://isolate.example.org") as ws:
            await ws.send_json({"ticket": self.runtime.ticket("web-revoke", "webssh")})
            await ws.receive_json()
            await ws.receive_json()
            await ws.receive()
            self.runtime.revoked.set()
            value = await asyncio.wait_for(ws.receive_json(), 3)
            self.assertEqual(value["type"], "error")

    async def test_disconnecting_during_approval_does_not_open_target(self):
        def prepare(context):
            while not context["_cancel_event"].wait(0.01):
                pass
            raise ValueError("Client disconnected")

        self.runtime.prepare = prepare
        async with self.http.ws_connect(self.web.make_url("/ssh"), origin="https://isolate.example.org") as ws:
            await ws.send_json({"ticket": self.runtime.ticket("pending-web", "webssh")})
            self.assertEqual((await ws.receive_json())["state"], "waiting")
            await ws.close()
        deadline = time.monotonic() + 3
        while not self.runtime.finished and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        self.assertEqual(self.target_users, [])
        self.assertEqual(self.runtime.started, [])
        self.assertIn(("pending-web", 255), self.runtime.finished)

    async def test_service_shutdown_closes_live_native_channels_and_finishes_context(self):
        listener_created = asyncio.Event()
        created = []
        original = gateway.create_native_listener

        async def listener(runtime):
            item = await original(runtime, "127.0.0.1", 0)
            created.append(item)
            listener_created.set()
            return item

        self.config["gateway"]["web_enabled"] = False
        with mock.patch.object(gateway, "create_native_listener", listener):
            service = asyncio.create_task(gateway.serve(self.runtime))
            await listener_created.wait()
            port = created[0].get_port()
            known = self.root / "shutdown_known_hosts"
            known.write_bytes(("[127.0.0.1]:{} ".format(port)).encode() + self.gateway_key.export_public_key())
            async with await asyncssh.connect("127.0.0.1", port, username="42",
                    password=self.runtime.ticket("shutdown"), config=[], client_keys=[],
                    known_hosts=str(known), agent_path=None, preferred_auth="password") as client:
                process = await client.create_process()
                self.assertEqual(await process.stdout.readline(), "target-ready\n")
                service.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await service
                await asyncio.wait_for(client.wait_closed(), 3)
        self.assertIn(("shutdown", 255), self.runtime.finished)
        self.assertEqual(len(created[0].isolate_tasks), 0)

    async def test_readiness_reports_draining_or_unavailable_redis(self):
        self.config["cluster"] = {"draining": True}
        async with self.http.get(self.web.make_url("/healthz")) as response:
            self.assertEqual(response.status, 503)
        self.config["cluster"]["draining"] = False
        self.runtime.redis = mock.Mock()
        self.runtime.redis.ping.side_effect = OSError("Unavailable")
        async with self.http.get(self.web.make_url("/healthz")) as response:
            self.assertEqual(response.status, 503)


@unittest.skipUnless(asyncssh, "Gateway unit checks require asyncssh")
class GatewayBoundaryTest(unittest.TestCase):
    def test_nonlocal_web_binding_requires_tls(self):
        with self.assertRaises(gateway.GatewayError):
            gateway.web_ssl_context({"gateway": {"web_host": "0.0.0.0"}})
        self.assertIsNone(gateway.web_ssl_context({"gateway": {"web_host": "127.0.0.1"}}))

    def test_sudo_command_is_quoted_and_managed_profile_is_rejected(self):
        context = {"decision": {"sudo_mode": "sudo-i"}}
        self.assertEqual(gateway._command(context, None), "sudo -n -i")
        self.assertEqual(gateway._command(context, "echo '$HOME'; id"),
                         "sudo -n -i -- /bin/sh -c 'echo '\"'\"'$HOME'\"'\"'; id'")
        with self.assertRaises(gateway.GatewayError):
            gateway._size(0, 24)
