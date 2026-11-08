"""Real SSH multiplex, file-transfer and explicitly pinned forwarding exchanges."""

import asyncio
import contextlib
import json
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

import asyncssh
import test_gateway as fixtures


class GatewayChannelsTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await fixtures.GatewayIntegrationTest.asyncSetUp(self)
        self.config["gateway"]["ssh_features"] = {"multiple_channels": True, "max_channels": 4,
            "sftp": True, "scp": True, "forwarding": True}

    async def asyncTearDown(self):
        await fixtures.GatewayIntegrationTest.asyncTearDown(self)

    connect = fixtures.GatewayIntegrationTest.connect
    wait_finished = fixtures.GatewayIntegrationTest.wait_finished

    def ticket(self, name, actions=()):
        value = self.runtime.ticket(name)
        self.runtime.tickets[value]["channel_actions"] = list(actions)
        return value

    async def test_idle_authenticated_transport_cannot_outlive_its_authorization(self):
        value = self.ticket("idle-expiry")
        self.runtime.tickets[value]["deadline"] = time.time() + 2
        async with await self.connect(value) as client:
            await asyncio.wait_for(client.wait_closed(), 5)
        await self.wait_finished(value)
        self.assertEqual(self.runtime.started, [])

    async def test_multiple_channels_share_target_and_session_and_revoke_together(self):
        self.config["gateway"]["ssh_features"]["max_channels"] = 3
        async with await self.connect(self.ticket("multiplex")) as client:
            first = await client.create_process()
            second = await client.create_process()
            self.assertEqual(await first.stdout.readline(), "target-ready\n")
            self.assertEqual(await second.stdout.readline(), "target-ready\n")
            result = await client.run("id", check=False)
            self.assertEqual(result.stdout, "exec:id\n")
            third = await client.create_process()
            self.assertEqual(await third.stdout.readline(), "target-ready\n")
            with self.assertRaises(asyncssh.ChannelOpenError):
                await client.create_process()
            self.assertEqual(self.target_users, ["support"])
            self.assertEqual(self.runtime.started, ["multiplex"])
            self.runtime.revoked.set()
            await asyncio.wait_for(client.wait_closed(), 4)
            for process in (first, second, third):
                result = await asyncio.wait_for(process.wait(), 4)
                self.assertNotEqual(result.exit_status, 0)
        await self.wait_finished("multiplex")
        self.assertEqual(len(self.runtime.finished), 1)
        self.assertEqual(self.runtime.finished[0], ("multiplex", 255))

    async def test_sftp_binary_upload_download_and_file_operation_audit(self):
        payload = b"secret-file-payload\0\xff" * 50000
        async with await self.connect(self.ticket("files", ["sftp"])) as client:
            async with client.start_sftp_client() as sftp:
                await sftp.mkdir("/nested")
                async with sftp.open("/nested/original.bin", "wb") as file:
                    await file.write(payload)
                await sftp.rename("/nested/original.bin", "/nested/renamed.bin")
                async with sftp.open("/nested/renamed.bin", "rb") as file:
                    self.assertEqual(await file.read(), payload)
                self.assertEqual(await sftp.listdir("/nested"), [".", "..", "renamed.bin"])
                self.assertEqual((self.sftp_root / "nested" / "renamed.bin").read_bytes(), payload)
                self.assertEqual((await client.run("id", check=False)).stdout, "exec:id\n")
                await sftp.remove("/nested/renamed.bin")
                await sftp.rmdir("/nested")
            self.assertEqual(self.target_users, ["support"])
        await self.wait_finished("files")
        events = self.runtime.events
        operations = [event.get("operation") for event in events if event["event"] == "sftp_operation"]
        self.assertIn("rename", operations)
        self.assertIn("remove", operations)
        closes = [event for event in events if event.get("operation") == "close"]
        self.assertEqual(sum(event.get("written_bytes", 0) for event in closes), len(payload))
        self.assertEqual(sum(event.get("read_bytes", 0) for event in closes), len(payload))
        self.assertNotIn("secret-file-payload", json.dumps(events))
        self.assertEqual(self.runtime.output, [b"exec:id\n"])

    async def test_legacy_scp_uses_audited_upstream_sftp(self):
        local = self.root / "source.txt"
        local.write_bytes(b"legacy-scp-data\0\xff")
        async with await self.connect(self.ticket("scp", ["sftp"])) as client:
            await asyncssh.scp(str(local), (client, "/uploaded.txt"))
            self.assertEqual((self.sftp_root / "uploaded.txt").read_bytes(), local.read_bytes())
            downloaded = self.root / "downloaded.txt"
            await asyncssh.scp((client, "/uploaded.txt"), str(downloaded))
            self.assertEqual(downloaded.read_bytes(), local.read_bytes())
        await self.wait_finished("scp")
        self.assertEqual(self.runtime.output, [])
        self.assertTrue(any(event.get("transfer") == "scp" for event in self.runtime.events))

    async def test_sftp_needs_separate_grant_and_cannot_inherit_sudo(self):
        for name, actions, sudo in (("no-file-grant", [], "none"), ("sudo-file-grant", ["sftp"], "sudo-i")):
            value = self.ticket(name, actions)
            self.runtime.tickets[value]["decision"]["sudo_mode"] = sudo
            async with await self.connect(value) as client:
                with self.assertRaises((asyncssh.Error, OSError)):
                    await asyncio.wait_for(client.start_sftp_client(), 3)
        self.assertEqual(list(self.sftp_root.iterdir()), [])

    async def test_file_grant_revocation_closes_sftp_even_when_shell_grant_remains(self):
        value = self.ticket("sftp-revoke", ["sftp"])
        context = self.runtime.tickets[value]
        async with await self.connect(value) as client:
            sftp = await client.start_sftp_client()
            file = await sftp.open("/unfinished.txt", "wb")
            await file.write(b"first chunk")
            context["channel_actions"] = []
            await asyncio.wait_for(client.wait_closed(), 4)
            with self.assertRaises(asyncssh.Error):
                await file.write(b"must be denied")
            with contextlib.suppress(asyncssh.Error):
                await file.close()
            sftp.exit()
        await self.wait_finished(value)
        self.assertEqual((self.sftp_root / "unfinished.txt").read_bytes(), b"first chunk")

    async def test_only_exact_pinned_forwarding_target_is_reachable_and_revocable(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(32768):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
        listener = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        self.config["gateway"]["forwarding_targets"] = {"42": [
            {"host": "ide.example.invalid", "address": "127.0.0.1", "port": port}]}
        value = self.ticket("forward", ["forward"])
        context = self.runtime.tickets[value]
        try:
            async with await self.connect(value) as client:
                for host, requested_port in (("127.0.0.1", port), ("ide.example.invalid", port + 1)):
                    with self.assertRaises(asyncssh.ChannelOpenError):
                        await client.open_connection(host, requested_port)
                reader, writer = await client.open_connection("ide.example.invalid", port, encoding=None)
                payload = b"forward-payload-private" * 10000
                writer.write(payload)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 4), payload)
                context["channel_actions"] = []
                await asyncio.wait_for(client.wait_closed(), 4)
                writer.close()
        finally:
            listener.close()
            await listener.wait_closed()
        await self.wait_finished(value)
        starts = [event for event in self.runtime.events if event["event"] == "ssh_forward_start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["destination_host"], "127.0.0.1")
        self.assertEqual(self.runtime.output, [])
        self.assertNotIn("forward-payload-private", json.dumps(self.runtime.events))

    async def test_proxy_hop_uses_independent_credentials_and_known_host_keys(self):
        users = []
        class Jump(asyncssh.SSHServer):
            def begin_auth(self, username):
                users.append(username)
                return False
            def connection_requested(self, *args):
                return True
        key = asyncssh.generate_private_key("ssh-ed25519")
        jump = await asyncssh.create_server(Jump, "127.0.0.1", 0, server_host_keys=[key])
        port = jump.get_port()
        with (self.root / "known_hosts").open("ab") as known:
            known.write(("[127.0.0.1]:{} ".format(port)).encode() + key.export_public_key())
        value = self.ticket("jump")
        self.runtime.tickets[value]["proxy_chain"] = [{
            "host": {"server_id": "17", "server_ip": "127.0.0.1", "server_port": port},
            "decision": {"remote_user": "jump-observer", "sudo_mode": "none"},
            "identity": {"username": "alice", "keycloak_sub": "human-1"}, "connection_id": value + "-hop"}]
        try:
            async with await self.connect(value) as client:
                self.assertEqual((await client.run("id", check=False)).stdout, "exec:id\n")
            await self.wait_finished(value)
        finally:
            jump.close()
            await jump.wait_closed()
        self.assertEqual(users, ["jump-observer"])
        self.assertEqual(self.target_users, ["support"])
