"""Native Kubernetes multiplexing over verified TLS and current action grants."""
import asyncio
import contextlib
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))
from aiohttp import web, WSMsgType, ClientSession, TCPConnector, ClientPayloadError
from aiohttp.test_utils import TestServer, TestClient
from multidict import MultiDict
from isolate_kubernetes import (SPDYPortForward, RemoteCommandChannels, REMOTE_PROTOCOLS,
    PORTFORWARD_PROTOCOL, _SPDY_DICTIONARY, classify_request, validate_kubernetes_target, proxy_kubernetes_request)
from isolate_protocols import ProtocolError
from isolate_runtime import Runtime
import test_runtime_api_index as fixtures


def control_frame(kind, payload, flags=0):
    return struct.pack("!II", 0x80030000 | kind, flags << 24 | len(payload)) + payload


def data_frame(stream, payload, flags=0):
    return struct.pack("!II", stream, flags << 24 | len(payload)) + payload


def headers(compressor, values):
    raw = struct.pack("!I", len(values))
    for name, value in values.items():
        name, value = name.encode(), value.encode()
        raw += struct.pack("!I", len(name)) + name + struct.pack("!I", len(value)) + value
    return compressor.compress(raw) + compressor.flush(zlib.Z_SYNC_FLUSH)


def stream(compressor, stream_id=1, port=8080, kind="data", request_id="0"):
    return control_frame(1, struct.pack("!IIH", stream_id, 0, 0) + headers(compressor,
        {"streamtype": kind, "port": str(port), "requestid": request_id}))


class KubernetesValidationTest(unittest.TestCase):
    def setUp(self):
        self.target = {"protocol": "kubernetes", "allowed_methods": ["GET", "POST"], "allowed_paths": ["/*"],
            "kubernetes": {"enabled": True, "allowed_namespaces": ["stage"],
                "allowed_operations": ["exec", "attach", "logs", "watch", "portforward"], "allowed_ports": [8080]}}

    def test_namespace_operation_query_and_proxy_scopes_are_explicit(self):
        for path, query in (("/api/v1/namespaces/prod/pods/x/exec", {"command": "sh"}),
                            ("/api/v1/namespaces/stage/services/x/proxy/private", {}),
                            ("/api/v1/nodes", {}), ("/api/v1/namespaces/stage/pods/x/portforward", {"ports": "22"}),
                            ("/api/v1/namespaces/stage/pods/x/exec", {"command": "sh", "stdin": "sometimes"})):
            with self.subTest(path=path), self.assertRaises(ProtocolError):
                classify_request(self.target, "GET", path, query)
        with self.assertRaises(ProtocolError):
            classify_request(self.target, "GET", "/api/v1/namespaces/stage/pods", MultiDict([("watch", "false"), ("watch", "true")]))
        self.assertEqual(classify_request(self.target, "GET", "/api/v1/namespaces/stage/pods/x/log", {"follow": "true"})["action"], "kubernetes-logs")
        self.assertEqual(classify_request(self.target, "GET", "/api/v1/namespaces/stage/pods", {"watch": "1"})["action"], "kubernetes-watch")
        self.assertIsNone(classify_request(self.target, "GET", "/api/v1", {})["action"])
        self.target["kubernetes"]["allowed_operations"] = []
        with self.assertRaises(ProtocolError):
            classify_request(self.target, "GET", "/api/v1/namespaces/stage/pods/x/attach", {})

    def test_remote_stream_directions_resize_and_v5_half_close_are_checked(self):
        intent = {"stdin": True, "stdout": True, "stderr": False, "tty": True}
        channels = RemoteCommandChannels(REMOTE_PROTOCOLS[0], intent)
        channels.validate(b"\x00input")
        channels.validate(b'\x04{"Width":120,"Height":40}')
        channels.validate(b"\x01output", upstream=True)
        channels.validate(b"\xff\x00")
        for packet, incoming in ((b"\x00after-close", False), (b"\x01spoofed-output", False),
                                 (b"\x02stderr-with-tty", True), (b'\x04{"Width":0,"Height":1}', False),
                                 (b"\xff\x03", False), (b"", True)):
            with self.subTest(packet=packet), self.assertRaises(ProtocolError):
                channels.validate(packet, upstream=incoming)
        with self.assertRaises(ProtocolError):
            RemoteCommandChannels(REMOTE_PROTOCOLS[1], intent).validate(b"\xff\x00")

    def test_spdy_real_dictionary_stream_ports_fragmentation_and_closed_streams(self):
        self.assertEqual(hashlib.sha256(_SPDY_DICTIONARY).hexdigest(), "51d27341373f923f3cd88e1eb7162aeaa3723d7585ff2399201dc06498407f02")
        compressor = zlib.compressobj(zdict=_SPDY_DICTIONARY)
        inspector = SPDYPortForward([8080], max_channels=2)
        packet = stream(compressor, kind="error")
        self.assertEqual(inspector.feed(packet[:9]), [])
        result = inspector.feed(packet[9:])
        self.assertEqual(result[0][1]["port"], 8080)
        inspector.feed(stream(compressor, stream_id=3))
        self.assertEqual(inspector.feed(data_frame(3, b"binary\0\xff"))[0][1]["bytes"], 8)
        with self.assertRaises(ProtocolError):
            inspector.feed(stream(compressor, stream_id=5, request_id="1"))
        fresh = SPDYPortForward([8080])
        with self.assertRaises(ProtocolError):
            fresh.feed(stream(zlib.compressobj(zdict=_SPDY_DICTIONARY), port=22))
        with self.assertRaises(ProtocolError):
            SPDYPortForward([8080]).feed(data_frame(1, b"unopened-stream"))
        with self.assertRaises(ProtocolError):
            SPDYPortForward([8080], max_frame_bytes=1024).feed(struct.pack("!II", 1, 1048576))

    def test_configuration_rejects_implicit_namespaces_ports_and_unbounded_limits(self):
        for changes in ({"allowed_namespaces": []}, {"allowed_ports": []}, {"max_channels": 999},
                        {"allowed_operations": ["proxy"]}, {"allowed_operations": [{}]}, {"record_output": "true"}):
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                validate_kubernetes_target(dict(self.target, kubernetes=dict(self.target["kubernetes"], **changes)))


def certificate(directory):
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Kubernetes TLS fixture")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("upstream.test"), x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False).sign(key, hashes.SHA256()))
    certfile, keyfile = Path(directory) / "kubernetes-ca.pem", Path(directory) / "tls.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(certfile), str(keyfile))
    return str(certfile), server, ssl.create_default_context(cafile=str(certfile))


class KubernetesNetworkTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = Path(self.fixture.directory.name)
        self.ca, self.server_tls, self.client_tls = certificate(self.root)
        self.calls, self.frames = [], []
        self.pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "demo", "namespace": "prod", "uid": "fixture-pod", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "synthetic-image"}]}, "status": {"phase": "Running"}}
        upstream_app = web.Application()
        upstream_app.router.add_route("*", "/{path:.*}", self.upstream_request)
        self.upstream = TestServer(upstream_app)
        await self.upstream.start_server(ssl=self.server_tls)
        self.addAsyncCleanup(self.upstream.close)
        tokenfile = self.root / "kube-service-token"
        tokenfile.write_text("private-upstream-service-token")
        tokenfile.chmod(0o600)
        self.target = {"protocol": "kubernetes", "project": "prod", "upstream": "https://upstream.test:" + str(self.upstream.port),
            "ca_file": self.ca, "bearer_token_file": str(tokenfile), "impersonation": True,
            "allowed_paths": ["/*"], "allowed_methods": ["GET", "POST"],
            "kubernetes": {"enabled": True, "allowed_namespaces": ["prod"], "allowed_operations": sorted(OPERATIONS_FOR_TEST),
                "allowed_ports": [8080], "record_output": True, "record_logs": True, "stream_timeout_seconds": 10}}
        self.fixture.config["protocols"] = {"enabled": True, "targets": {"1": self.target}}
        self.fixture.config["gateway"]["recheck_interval"] = .1
        self.grant = {"subject": "group", "name": "Support", "project": "prod", "remote_user": "support", "sudo_mode": "none",
            "allowed_actions": ["kubernetes"] + ["kubernetes-" + name for name in OPERATIONS_FOR_TEST]}
        # Operation actions supplement the base capability in the selected
        # rule. A second equal-specificity rule must not bypass an existing
        # rule's deny-by-omission semantics.
        self.fixture.redis.set("grant_1", json.dumps(self.grant))
        self.runtime = Runtime(self.fixture.config, self.fixture.redis)
        proxy_app = web.Application()
        async def proxy(request):
            return await proxy_kubernetes_request(request, self.runtime)
        proxy_app.router.add_route("*", "/protocols/kubernetes/{host_id}/{path:.*}", proxy)
        self.proxy = TestServer(proxy_app)
        await self.proxy.start_server(ssl=self.server_tls)
        self.client = TestClient(self.proxy, connector=TCPConnector(ssl=self.client_tls))
        self.addAsyncCleanup(self.client.close)
        await self.client.start_server()
        self.auth = {"Authorization": "Bearer " + self.fixture.token}
        self.base = "/protocols/kubernetes/1"

    async def upstream_request(self, request):
        self.calls.append({"path": request.path, "headers": list(request.headers.items()), "commands": request.query.getall('command', [])})
        if request.path.endswith("/exec") or request.path.endswith("/attach"):
            websocket = web.WebSocketResponse(protocols=REMOTE_PROTOCOLS)
            await websocket.prepare(request)
            await websocket.send_bytes(b"\x01native-kubernetes-output\n")
            if request.query.get("stdin") == "true" or request.query.get("stdin") == "1":
                async for packet in websocket:
                    if packet.type != WSMsgType.BINARY:
                        break
                    self.frames.append(packet.data)
                    if packet.data[0] == 0:
                        await websocket.send_bytes(b"\x01echo:" + packet.data[1:])
                    elif packet.data[0] == 4:
                        await websocket.send_bytes(b"\x01resized\n")
                    elif packet.data[:2] == b"\xff\x00":
                        break
            with contextlib.suppress(ConnectionError):
                await websocket.send_bytes(b'\x03{"kind":"Status","apiVersion":"v1","status":"Success"}')
            await websocket.close()
            return websocket
        if request.path.endswith("/portforward"):
            websocket = web.WebSocketResponse(protocols=[PORTFORWARD_PROTOCOL])
            await websocket.prepare(request)
            inspector = SPDYPortForward([8080])
            compressor = zlib.compressobj(zdict=_SPDY_DICTIONARY)
            async for packet in websocket:
                if packet.type != WSMsgType.BINARY:
                    break
                self.frames.append(packet.data)
                for frame, event in inspector.feed(packet.data):
                    if event and event["event"] == "open":
                        reply = control_frame(2, struct.pack("!I", event["channel"]) + headers(compressor, {}))
                        await websocket.send_bytes(reply)
                    elif event and event["event"] == "data" and event["stream_type"] == "data":
                        payload = frame[8:]
                        await websocket.send_bytes(data_frame(event["channel"], b"echo:" + payload) if payload else data_frame(event["channel"], b"", flags=1))
                    elif struct.unpack_from("!I", frame)[0] == 0x80030006:
                        await websocket.send_bytes(frame)
            return websocket
        if request.path.endswith("/log"):
            return web.Response(text="synthetic pod log\n")
        if request.query.get("watch") in ("true", "1"):
            response = web.StreamResponse(headers={"Content-Type": "application/json"})
            await response.prepare(request)
            await response.write(json.dumps({"type": "MODIFIED", "object": self.pod}).encode() + b"\n")
            await asyncio.sleep(.5)
            with contextlib.suppress(ConnectionError):
                await response.write(json.dumps({"type": "DELETED", "object": self.pod}).encode() + b"\n")
                await response.write_eof()
            return response
        if request.path == "/version":
            return web.json_response({"major": "1", "minor": "31", "gitVersion": "v1.31.3", "platform": "linux/amd64"})
        if request.path == "/api":
            return web.json_response({"kind": "APIVersions", "versions": ["v1"], "serverAddressByClientCIDRs": []})
        if request.path == "/apis":
            return web.json_response({"kind": "APIGroupList", "apiVersion": "v1", "groups": []})
        if request.path == "/api/v1":
            return web.json_response({"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "v1", "resources": [
                {"name": "pods", "singularName": "pod", "namespaced": True, "kind": "Pod", "verbs": ["get", "list", "watch"]},
                {"name": "pods/log", "singularName": "", "namespaced": True, "kind": "Pod", "verbs": ["get"]}]})
        if request.path.endswith("/pods/demo"):
            return web.json_response(self.pod)
        if request.path.endswith("/pods"):
            return web.json_response({"kind": "PodList", "apiVersion": "v1", "metadata": {"resourceVersion": "1"}, "items": [self.pod]})
        return web.json_response({"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404}, status=404)

    async def test_exec_attach_binary_channels_record_output_but_not_stdin_or_argv(self):
        path = self.base + "/api/v1/namespaces/prod/pods/demo/exec?command=private-password-argument&command=a%2Bb%2F%252F%26x%3D%3F&stdin=true&stdout=true&tty=true"
        async with self.client.ws_connect(path, headers=dict(self.auth, **{"Impersonate-User": "system:admin", "Impersonate-Group": "system:masters"}), protocols=REMOTE_PROTOCOLS) as socket:
            self.assertEqual((await socket.receive()).data, b"\x01native-kubernetes-output\n")
            await socket.send_bytes(b"\x00input-value")
            self.assertEqual((await socket.receive()).data, b"\x01echo:input-value")
            await socket.send_bytes(b'\x04{"Width":120,"Height":40}')
            self.assertEqual((await socket.receive()).data, b"\x01resized\n")
            await socket.send_bytes(b"\xff\x00")
            self.assertEqual((await socket.receive()).data[0], 3)
        self.assertIn(("Impersonate-User", "isolate:alice-stable"), self.calls[0]["headers"])
        self.assertEqual(self.calls[0]['commands'], ['private-password-argument', 'a+b/%2F&x=?'])
        self.assertIn(("Impersonate-Group", "isolate:Support"), self.calls[0]["headers"])
        self.assertNotIn(("Impersonate-User", "system:admin"), self.calls[0]["headers"])
        await asyncio.sleep(.1)
        events = b"".join(path.read_bytes() for path in self.root.rglob("session.jsonl"))
        self.assertNotIn(b"private-password-argument", events)
        self.assertNotIn(b"input-value", events)
        self.assertNotIn(self.fixture.token.encode(), events)
        self.assertIn(b"kubernetes_operation_start", events)
        transcript = b"".join(path.read_bytes() for path in self.root.rglob("terminal.log"))
        self.assertIn(b"native-kubernetes-output", transcript)

    async def test_operation_grant_revocation_closes_live_stream_with_base_grant_intact(self):
        path = self.base + "/api/v1/namespaces/prod/pods/demo/attach?stdin=true&stdout=true"
        async with self.client.ws_connect(path, headers=self.auth, protocols=REMOTE_PROTOCOLS) as socket:
            self.assertEqual((await socket.receive()).data[0], 1)
            self.grant["allowed_actions"].remove("kubernetes-attach")
            self.fixture.redis.set("grant_1", json.dumps(self.grant))
            result = await asyncio.wait_for(socket.receive(), timeout=2)
            self.assertIn(result.type, (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING))
        count = len(self.calls)
        response = await self.client.get(self.base + "/api/v1/namespaces/prod/pods/demo/attach", headers=self.auth)
        self.assertEqual(response.status, 403)
        self.assertEqual(len(self.calls), count)

    async def test_spdy_port_forward_validates_each_stream_before_upstream_write(self):
        path = self.base + "/api/v1/namespaces/prod/pods/demo/portforward"
        async with self.client.ws_connect(path, headers=self.auth, protocols=[PORTFORWARD_PROTOCOL]) as socket:
            compressor = zlib.compressobj(zdict=_SPDY_DICTIONARY)
            await socket.send_bytes(stream(compressor, kind="error"))
            await socket.receive()
            await socket.send_bytes(stream(compressor, stream_id=3))
            await socket.receive()
            await socket.send_bytes(data_frame(3, b"binary\0payload"))
            echoed = await socket.receive()
            self.assertEqual(echoed.data[8:], b"echo:binary\0payload")
            before = len(self.frames)
            await socket.send_bytes(stream(compressor, stream_id=5, port=22, request_id="1"))
            self.assertIn((await socket.receive()).type, (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING))
            self.assertEqual(len(self.frames), before)

    async def test_watch_and_logs_use_separate_actions_and_stream_revocation(self):
        response = await self.client.get(self.base + "/api/v1/namespaces/prod/pods/demo/log", headers=self.auth)
        self.assertEqual(await response.text(), "synthetic pod log\n")
        response = await self.client.get(self.base + "/api/v1/namespaces/prod/pods?watch=true", headers=self.auth)
        self.assertEqual(json.loads(await response.content.readline())["type"], "MODIFIED")
        self.grant["allowed_actions"].remove("kubernetes-watch")
        self.fixture.redis.set("grant_1", json.dumps(self.grant))
        with self.assertRaises((ClientPayloadError, ConnectionError)):
            await asyncio.wait_for(response.read(), 2)
        denied = await self.client.get(self.base + "/api/v1/namespaces/prod/pods?watch=true", headers=self.auth)
        self.assertEqual(denied.status, 403)

    @unittest.skipUnless(shutil.which("kubectl"), "native kubectl is needed for client integration")
    async def test_unmodified_kubectl_exec_attach_logs_watch_and_portforward(self):
        kubeconfig = self.root / "kubeconfig.json"
        kubeconfig.write_text(json.dumps({"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "fixture", "cluster": {
            "server": str(self.proxy.make_url(self.base)), "certificate-authority": self.ca}}],
            "users": [{"name": "isolate", "user": {"token": self.fixture.token}}], "contexts": [{"name": "fixture", "context": {
                "cluster": "fixture", "user": "isolate", "namespace": "prod"}}], "current-context": "fixture"}))
        kubeconfig.chmod(0o600)
        env = dict(os.environ, KUBECONFIG=str(kubeconfig), KUBECTL_REMOTE_COMMAND_WEBSOCKETS="true", KUBECTL_PORT_FORWARD_WEBSOCKETS="true")
        binary = shutil.which("kubectl")
        async def run(*args):
            result = await asyncio.to_thread(subprocess.run, [binary, "--request-timeout=5s", "--cache-dir=" + str(self.root / "kubecache"), *args],
                env=env, capture_output=True, timeout=15, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout
        self.assertIn("native-kubernetes-output", await run("exec", "demo", "-c", "app", "--", "echo", "fixture"))
        self.assertIn("native-kubernetes-output", await run("attach", "demo", "-c", "app"))
        self.assertIn("synthetic pod log", await run("logs", "demo", "-c", "app"))
        watched = await run("get", "pods", "--watch-only", "--output-watch-events", "-o", "json")
        self.assertIn("MODIFIED", watched)
        process = subprocess.Popen([binary, "--request-timeout=5s", "--cache-dir=" + str(self.root / "kubecache"), "port-forward", "pod/demo", ":8080", "--address=127.0.0.1"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            line = await asyncio.wait_for(asyncio.to_thread(process.stdout.readline), 10)
            self.assertIn("Forwarding from 127.0.0.1:", line)
            local_port = int(line.split("127.0.0.1:", 1)[1].split()[0])
            reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
            try:
                writer.write(b"native-port-forward")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(24), 5), b"echo:native-port-forward")
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            process.terminate()
            await asyncio.to_thread(process.wait, 10)
            process.stdout.close()


OPERATIONS_FOR_TEST = ("exec", "attach", "logs", "watch", "portforward")


if __name__ == "__main__":
    unittest.main()
