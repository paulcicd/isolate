import asyncio
import contextlib
import copy
import datetime
import importlib.util
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))

from isolate_protocols import (ProtocolError, register_protocol_routes, resolve_target,
                              upstream_headers, validate_http_request)

try:
    import aiohttp
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
except ImportError:
    aiohttp = None


class Runtime:
    """Adapter fixture; signed identity/policy checks are Runtime's own tests."""
    def __init__(self, config):
        self.config = config
        self.host = {"server_id": "10001", "server_ip": "127.0.0.1", "project_name": "prod"}
        self.identity = {"keycloak_sub": "alice-sub", "username": "alice", "groups": ["Support"]}
        self.tickets = {}
        self.started = []
        self.finished = []
        self.revoked = False
        self.counter = 0

    def authorize(self, token, host_id, protocol="http", source_ip=None):
        if token != "valid" or host_id != "10001" or self.revoked:
            raise ProtocolError("unauthorized")
        self.counter += 1
        return {"connection_id": str(self.counter), "protocol": protocol, "host": dict(self.host),
                "identity": dict(self.identity), "decision": {"sudo_mode": "none"}}

    def consume_ticket(self, ticket, protocol="postgresql", source_ip=None):
        if self.tickets.pop(ticket, None) != protocol:
            raise ProtocolError("ticket invalid or already consumed")
        return self.authorize("valid", "10001", protocol, source_ip)

    def prepare(self, context):
        return context

    def start(self, context):
        self.started.append(context)

    def recheck(self, context):
        if self.revoked:
            raise ProtocolError("revoked")

    def finish(self, context, exit_code=None):
        self.finished.append((context, exit_code))


def certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upstream.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("upstream.test"), x509.DNSName("db.test")]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
    keyfile = str(Path(directory) / "tls.key")
    certfile = str(Path(directory) / "tls.pem")
    Path(keyfile).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    Path(certfile).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(certfile, keyfile)
    client = ssl.create_default_context(cafile=certfile)
    return certfile, server, client


class ProtocolValidationTest(unittest.TestCase):
    def setUp(self):
        self.host = {"server_id": "10001", "server_ip": "192.0.2.1", "project_name": "prod"}
        self.target = {"protocol": "http", "project": "prod", "upstream": "https://api.example"}
        self.config = {"protocols": {"enabled": True, "targets": {"10001": self.target}}}

    def test_disabled_wrong_protocol_project_and_literal_address_are_denied(self):
        self.assertEqual(resolve_target(self.config, self.host, "http")["address"], "192.0.2.1")
        for update in ({"protocol": "mysql"}, {"project": "other"},
                       {"upstream": "https://192.0.2.9"}, {"upstream": "https://secret:password@api.example"},
                       {"upstream": "https://api.example/#fragment"}, {"upstream": "http://api.example"}):
            with self.subTest(update=update), self.assertRaises(ProtocolError):
                changed = copy.deepcopy(self.config)
                changed["protocols"]["targets"]["10001"].update(update)
                resolve_target(changed, self.host, "http")
        self.config["protocols"]["enabled"] = False
        with self.assertRaises(ProtocolError):
            resolve_target(self.config, self.host, "http")

    def test_ambiguous_paths_and_unlisted_actions_are_denied(self):
        target = resolve_target(self.config, self.host, "http")
        for method, path in (("POST", "/api"), ("CONNECT", "/api"), ("GET", "//evil.example"),
                             ("GET", "/x/../secret"), ("GET", "/%252e%252e/secret"),
                             ("GET", "/api\\secret"), ("GET", "/api%2f..%2fsecret")):
            with self.subTest(method=method, path=path), self.assertRaises(ProtocolError):
                validate_http_request(target, method, path)

    def test_database_native_auth_and_tls_must_be_acknowledged(self):
        self.target.update(protocol="postgresql", upstream="postgresql://db.example:5432")
        with self.assertRaises(ProtocolError):
            resolve_target(self.config, self.host, "postgresql")
        self.target["database_native_auth"] = True
        self.assertEqual(resolve_target(self.config, self.host, "postgresql")["audit_profile"], "connection")
        self.target["require_native_tls"] = False
        with self.assertRaises(ProtocolError):
            resolve_target(self.config, self.host, "postgresql")

    def test_kubernetes_requires_impersonation_scope_and_prefixes(self):
        self.target.update(protocol="kubernetes", upstream="https://kube.example", bearer_token_file="token")
        with self.assertRaises(ProtocolError):
            resolve_target(self.config, self.host, "kubernetes")
        self.target.update(impersonation=True, allowed_paths=["/api/v1/namespaces/prod/pods*"])
        target = resolve_target(self.config, self.host, "kubernetes")
        self.assertEqual(validate_http_request(target, "GET", "/api/v1/namespaces/prod/pods")[0], "GET")
        for path in ("/api/v1/namespaces/secret/pods", "/api/v1/namespaces/prod/pods/name/exec"):
            with self.assertRaises(ProtocolError):
                validate_http_request(target, "GET", path)
        self.target["impersonation_group_prefix"] = "system:"
        with self.assertRaises(ProtocolError):
            resolve_target(self.config, self.host, "kubernetes")


@unittest.skipUnless(aiohttp is not None, "aiohttp is not installed")
class ProtocolHTTPTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.certfile, self.server_tls, self.client_tls = certificate(self.directory.name)
        self.received = []

        async def upstream(request):
            self.received.append({"headers": list(request.headers.items()), "path": request.path_qs,
                                  "body": await request.read()})
            if request.path == "/redirect":
                return web.Response(status=302, headers={"Location": "https://escape.example/secret"})
            if request.path == "/stream":
                response = web.StreamResponse()
                await response.prepare(request)
                await response.write(b"first")
                await asyncio.sleep(0.5)
                with contextlib.suppress(ConnectionError):
                    await response.write(b"last")
                return response
            return web.json_response({"ok": True}, headers={"Set-Cookie": "secret=upstream", "X-Secret": "hidden"})

        import contextlib
        upstream_app = web.Application()
        upstream_app.router.add_route("*", "/{path:.*}", upstream)
        self.upstream = TestServer(upstream_app)
        await self.upstream.start_server(ssl=self.server_tls)
        self.addAsyncCleanup(self.upstream.close)
        self.target = {"protocol": "http", "project": "prod",
                       "upstream": "https://upstream.test:{}".format(self.upstream.port),
                       "ca_file": self.certfile, "allowed_methods": ["GET", "POST"]}
        self.config = {"gateway": {"recheck_interval": 0.1},
                       "protocols": {"enabled": True, "targets": {"10001": self.target},
                                     "allowed_origins": ["https://console.example"]}}
        self.runtime = Runtime(self.config)
        app = web.Application()
        register_protocol_routes(app, self.runtime)
        self.client = TestClient(TestServer(app))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)

    async def test_https_forwarding_is_pinned_and_caller_credentials_are_stripped(self):
        tokenfile = Path(self.directory.name) / "service-token"
        tokenfile.write_text("trusted-service-token", encoding="utf-8")
        tokenfile.chmod(0o600)
        self.target["bearer_token_file"] = str(tokenfile)
        response = await self.client.post("/protocols/http/10001/api?x=1", data=b"payload", headers={
            "Authorization": "Bearer valid", "Cookie": "admin=true", "Impersonate-User": "system:admin",
            "X-Forwarded-For": "1.2.3.4", "Content-Type": "application/json", "Connection": "X-Danger",
            "X-Danger": "injected"})
        self.assertEqual(response.status, 200, await response.text())
        self.assertEqual(await response.json(), {"ok": True})
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("X-Secret", response.headers)
        headers = {key.lower(): value for key, value in self.received[0]["headers"]}
        self.assertEqual(headers["authorization"], "Bearer trusted-service-token")
        self.assertEqual(headers["host"], "upstream.test:{}".format(self.upstream.port))
        for name in ("cookie", "impersonate-user", "x-forwarded-for", "x-danger"):
            self.assertNotIn(name, headers)
        self.assertEqual(self.received[0]["body"], b"payload")
        for _ in range(20):
            if self.runtime.finished:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.runtime.finished[0][1], 0)
        self.assertEqual(self.runtime.finished[0][0]["audit_profile"], "http-request")

    async def test_redirects_unknown_origins_and_bearer_bypass_are_denied(self):
        response = await self.client.get("/protocols/http/10001/redirect", headers={"Authorization": "Bearer valid"})
        self.assertEqual(response.status, 403)
        self.assertNotIn("Location", response.headers)
        count = len(self.received)
        for headers in ({}, {"Authorization": "Bearer invalid"},
                        {"Authorization": "Bearer valid", "Origin": "https://evil.example"}):
            response = await self.client.get("/protocols/http/10001/api", headers=headers)
            self.assertEqual(response.status, 403)
        self.assertEqual(len(self.received), count)

    async def test_wrong_upstream_tls_identity_fails(self):
        self.target["upstream"] = "https://wrong-name.test:{}".format(self.upstream.port)
        response = await self.client.get("/protocols/http/10001/api", headers={"Authorization": "Bearer valid"})
        self.assertEqual(response.status, 502)
        self.assertEqual(self.received, [])

    async def test_request_limit_and_disallowed_methods_stop_before_upstream(self):
        self.target["max_request_bytes"] = 4
        response = await self.client.post("/protocols/http/10001/api", data=b"too large", headers={"Authorization": "Bearer valid"})
        self.assertEqual(response.status, 403)
        response = await self.client.delete("/protocols/http/10001/api", headers={"Authorization": "Bearer valid"})
        self.assertEqual(response.status, 403)
        self.assertEqual(self.received, [])

    async def test_kubernetes_impersonation_is_derived_from_verified_identity(self):
        tokenfile = Path(self.directory.name) / "service-token"
        tokenfile.write_text("sa-token", encoding="utf-8")
        tokenfile.chmod(0o600)
        self.target.update(protocol="kubernetes", bearer_token_file=str(tokenfile), impersonation=True,
                           allowed_paths=["/api/v1/namespaces/prod/pods*"])
        response = await self.client.get("/protocols/kubernetes/10001/api/v1/namespaces/prod/pods",
            headers={"Authorization": "Bearer valid", "Impersonate-User": "system:admin", "Impersonate-Group": "system:masters"})
        self.assertEqual(response.status, 200, await response.text())
        headers = self.received[0]["headers"]
        self.assertIn(("Impersonate-User", "isolate:alice-sub"), headers)
        self.assertIn(("Impersonate-Group", "isolate:Support"), headers)
        self.assertNotIn(("Impersonate-Group", "system:masters"), headers)
        response = await self.client.get("/protocols/kubernetes/10001/api/v1/namespaces/prod/pods?watch=false&watch=true",
                                        headers={"Authorization": "Bearer valid"})
        self.assertEqual(response.status, 403)

    async def test_revocation_closes_a_stream_and_marks_failure(self):
        response = await self.client.get("/protocols/http/10001/stream", headers={"Authorization": "Bearer valid"})
        self.assertEqual(await response.content.readexactly(5), b"first")
        self.runtime.revoked = True
        with self.assertRaises((aiohttp.ClientPayloadError, aiohttp.ServerDisconnectedError)):
            await asyncio.wait_for(response.read(), timeout=2)
        for _ in range(20):
            if self.runtime.finished:
                break
            await asyncio.sleep(0.02)
        self.assertEqual(self.runtime.finished[-1][1], 1)

    async def test_disconnect_cancels_pending_http_approval_before_upstream(self):
        entered, cancelled = threading.Event(), threading.Event()

        def pending(context):
            entered.set()
            if context["_cancel_event"].wait(2):
                cancelled.set()
            raise ProtocolError("approval wait stopped")
        self.runtime.prepare = pending
        request = asyncio.create_task(self.client.get("/protocols/http/10001/api", headers={"Authorization": "Bearer valid"}))
        self.assertTrue(await asyncio.to_thread(entered.wait, 1))
        request.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await request
        self.assertTrue(await asyncio.to_thread(cancelled.wait, 1))
        self.assertEqual(self.received, [])
        self.assertEqual(self.runtime.started, [])


@unittest.skipUnless(aiohttp is not None, "aiohttp is not installed")
class DatabaseTransportTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.certfile, self.server_tls, self.client_tls = certificate(self.directory.name)
        self.received = []
        self.connections = 0
        self.tasks = set()
        self.protocol = "postgresql"

        async def database(reader, writer):
            task = asyncio.current_task()
            self.tasks.add(task)
            self.connections += 1
            try:
                if self.protocol == "mysql":
                    greeting = b"\x0a8.4.0\x00" + b"\x01\x00\x00\x00" + b"12345678\x00" + b"\xff\xff" + b"\x21\x00\x00\xff\xff" + b"\x00" * 15
                    writer.write(len(greeting).to_bytes(3, "little") + b"\x00" + greeting)
                    await writer.drain()
                    request = await reader.readexactly(36)
                    if not int.from_bytes(request[4:8], "little") & 0x800:
                        return
                else:
                    request = await reader.readexactly(8)
                    self.received.append(request)
                    writer.write(b"S")
                    await writer.drain()
                await writer.start_tls(self.server_tls)
                data = await reader.readexactly(4)
                self.received.append(data)
                writer.write(b"reply:" + data)
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
                pass
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                self.tasks.discard(task)

        import contextlib
        self.database = await asyncio.start_server(database, "127.0.0.1", 0)
        self.dbport = self.database.sockets[0].getsockname()[1]
        self.addAsyncCleanup(self.close_database)
        self.target = {"protocol": "postgresql", "project": "prod", "database_native_auth": True,
                       "upstream": "postgresql://db.test:{}".format(self.dbport)}
        self.config = {"gateway": {"recheck_interval": 0.1},
                       "protocols": {"enabled": True, "targets": {"10001": self.target}}}
        self.runtime = Runtime(self.config)
        app = web.Application()
        register_protocol_routes(app, self.runtime)

        async def ticket(request):
            if request.headers.get("Authorization") != "Bearer valid":
                return web.Response(status=403)
            payload = await request.json()
            secret = "ticket-{}".format(len(self.runtime.tickets))
            self.runtime.tickets[secret] = payload["protocol"]
            return web.json_response({"ticket": secret})
        app.router.add_post("/api/v1/connections", ticket)
        self.client = TestClient(TestServer(app))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)

    async def close_database(self):
        self.database.close()
        await self.database.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def tunnel(self):
        spec = importlib.util.spec_from_file_location("isolate_protocol_proxy", ROOT / "scripts" / "isolate-protocol-proxy.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cache = Path(self.directory.name) / "identity.json"
        cache.write_text(json.dumps({"schema_version": 3, "id_token": "valid"}), encoding="utf-8")
        with socket.socket() as allocation:
            allocation.bind(("127.0.0.1", 0))
            localport = allocation.getsockname()[1]
        url = str(self.client.make_url("/")).rstrip("/")
        args = SimpleNamespace(api_url=url, gateway_url=url.replace("http://", "ws://"), identity_file=str(cache),
                               host_id="10001", protocol=self.protocol, ca_file=None, listen_port=localport,
                               allow_loopback_http=True)
        task = asyncio.create_task(module.database_tunnel(args))
        self.addAsyncCleanup(self.stop_tunnel, task)
        for _ in range(100):
            try:
                return await asyncio.open_connection("127.0.0.1", localport)
            except ConnectionRefusedError:
                await asyncio.sleep(0.01)
        self.fail("local tunnel did not start")

    async def stop_tunnel(self, task):
        import contextlib
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def test_postgresql_native_tls_crosses_websocket_and_local_helper(self):
        reader, writer = await self.tunnel()
        writer.write(struct.pack("!II", 8, 80877103))
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 5), b"S")
        await writer.start_tls(self.client_tls, server_hostname="db.test")
        writer.write(b"data")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(10), 5), b"reply:data")
        writer.close()
        await writer.wait_closed()
        self.assertIn(b"data", self.received)
        self.assertEqual(self.runtime.started[0]["audit_profile"], "connection")

    async def test_mysql_native_tls_crosses_websocket_and_local_helper(self):
        self.protocol = "mysql"
        self.target.update(protocol="mysql", upstream="mysql://db.test:{}".format(self.dbport))
        reader, writer = await self.tunnel()
        header = await asyncio.wait_for(reader.readexactly(4), 5)
        greeting = await reader.readexactly(int.from_bytes(header[:3], "little"))
        self.assertEqual(greeting[0], 10)
        payload = (0x800 | 0x200).to_bytes(4, "little") + b"\0" * 28
        writer.write(len(payload).to_bytes(3, "little") + b"\x01" + payload)
        await writer.drain()
        await writer.start_tls(self.client_tls, server_hostname="db.test")
        writer.write(b"data")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(10), 5), b"reply:data")
        writer.close()
        await writer.wait_closed()

    async def test_plaintext_postgresql_credentials_are_never_forwarded(self):
        self.runtime.tickets["one"] = "postgresql"
        async with self.client.ws_connect("/protocols/database") as websocket:
            await websocket.send_json({"ticket": "one", "protocol": "postgresql"})
            self.assertEqual((await websocket.receive_json())["type"], "ready")
            await websocket.send_bytes(struct.pack("!II", 40, 196608) + b"user\0password\0secret")
            self.assertEqual((await websocket.receive_json())["type"], "error")
        self.assertEqual(self.received, [])
        async with self.client.ws_connect("/protocols/database") as websocket:
            await websocket.send_json({"ticket": "one", "protocol": "postgresql"})
            self.assertEqual((await websocket.receive_json())["type"], "error")
        self.assertEqual(self.connections, 1)

    async def test_wrong_protocol_ticket_and_unknown_origin_do_not_connect(self):
        self.runtime.tickets["mysql-ticket"] = "mysql"
        async with self.client.ws_connect("/protocols/database") as websocket:
            await websocket.send_json({"ticket": "mysql-ticket", "protocol": "postgresql"})
            self.assertEqual((await websocket.receive_json())["type"], "error")
        with self.assertRaises(aiohttp.WSServerHandshakeError):
            await self.client.ws_connect("/protocols/database", headers={"Origin": "https://evil.example"})
        self.assertEqual(self.connections, 0)

    async def test_disconnect_cancels_pending_database_approval(self):
        entered, cancelled = threading.Event(), threading.Event()

        def pending(context):
            entered.set()
            if context["_cancel_event"].wait(2):
                cancelled.set()
            raise ProtocolError("approval wait stopped")
        self.runtime.prepare = pending
        self.runtime.tickets["pending"] = "postgresql"
        websocket = await self.client.ws_connect("/protocols/database")
        await websocket.send_json({"ticket": "pending", "protocol": "postgresql"})
        self.assertTrue(await asyncio.to_thread(entered.wait, 1))
        await websocket.close()
        self.assertTrue(await asyncio.to_thread(cancelled.wait, 1))
        self.assertEqual(self.connections, 0)
        self.assertEqual(self.runtime.started, [])

    async def test_shutdown_closes_database_websockets_and_pending_approvals(self):
        entered, cancelled = threading.Event(), threading.Event()

        def pending(context):
            entered.set()
            if context["_cancel_event"].wait(2):
                cancelled.set()
            raise ProtocolError("approval wait stopped")
        self.runtime.prepare = pending
        self.runtime.tickets["pending"] = "postgresql"
        websocket = await self.client.ws_connect("/protocols/database")
        await websocket.send_json({"ticket": "pending", "protocol": "postgresql"})
        self.assertTrue(await asyncio.to_thread(entered.wait, 1))
        shutdown = asyncio.create_task(self.client.server.close())
        message = await asyncio.wait_for(websocket.receive(), 2)
        self.assertIn(message.type, (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED))
        await asyncio.wait_for(shutdown, 3)
        self.assertTrue(cancelled.is_set())
        self.assertEqual(self.connections, 0)


if __name__ == "__main__":
    unittest.main()
