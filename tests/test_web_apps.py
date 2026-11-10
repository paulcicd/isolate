"""Real HTTP/WebSocket browser-app proxy with SQL state and signed identities."""
import asyncio
import copy
import gzip
from http.cookies import SimpleCookie
import json
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import aiohttp
from aiohttp import web, WSMsgType
import test_runtime_api_index as fixtures
from isolate_runtime import Runtime
from isolate_state import StateClient, SQLState
import isolate_web_apps as apps
from test_kubernetes_streams import certificate


class BrowserApplicationsTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.config = self.fixture.config
        self.config["dashboard"]["public_url"] = "https://access.example.com"
        self.config["gateway"]["public_web_url"] = "https://gateway.example.com"
        self.config["gateway"]["recheck_interval"] = .1
        self.config["web_apps"] = {"enabled": True, "session_ttl_seconds": 300, "launch_ttl": 30,
            "idle_timeout_seconds": 60, "max_requests_per_session": 16}
        self.seen = []
        self.ca, self.server_tls, _ = certificate(self.fixture.directory.name)
        async def upstream(request):
            self.seen.append({"path": request.path, "query": request.query_string, "headers": dict(request.headers), "body": await request.read()})
            if request.path == "/login":
                response = web.Response(status=302, headers={"Location": self.upstream_url + "/dashboard?next=%2Fapi%2Fv1"})
                response.headers.add("Set-Cookie", "app_login=current-user; Domain=.example.com; Path=/; HttpOnly; SameSite=Lax")
                response.headers.add("Set-Cookie", apps.COOKIE_NAME + "=forged; Path=/")
                return response
            if request.path == "/external":
                return web.Response(status=302, headers={"Location": "https://evil.example.org/collect?credential=upstream-private"})
            if request.path == "/ws":
                socket = web.WebSocketResponse(protocols=("chat",))
                await socket.prepare(request)
                async for message in socket:
                    if message.type == WSMsgType.TEXT:
                        await socket.send_str("echo:" + message.data)
                    elif message.type == WSMsgType.BINARY:
                        await socket.send_bytes(message.data[::-1])
                return socket
            if request.path == '/compressed':
                return web.Response(text='ok')
            return web.json_response({"ok": True, "cookie": request.headers.get("Cookie"), "body": self.seen[-1]["body"].decode()})
        application = web.Application(handler_args={"auto_decompress": False})
        application.router.add_route("*", "/{path:.*}", upstream)
        self.upstream_runner = web.AppRunner(application, access_log=None)
        await self.upstream_runner.setup()
        site = web.TCPSite(self.upstream_runner, "127.0.0.1", 0, ssl_context=self.server_tls)
        await site.start()
        self.upstream_url = "https://127.0.0.1:" + str(site._server.sockets[0].getsockname()[1])
        self.origin = "https://app1.isolate-apps.test"
        self.config["protocols"] = {"enabled": True, "targets": {"1": {"protocol": "http", "mode": "web-application",
            "project": "prod", "upstream": self.upstream_url, "ca_file": self.ca,
            "public_origin": self.origin, "allowed_methods": ["GET", "HEAD", "POST", "OPTIONS"], "allowed_paths": ["/*"]}}}
        grant = json.loads(self.fixture.redis.get("grant_1"))
        grant["allowed_actions"] = ["http"]
        self.fixture.redis.set("grant_1", json.dumps(grant))
        self.config["state"] = {"backend": "sqlite", "sqlite_path": str(Path(self.fixture.directory.name) / "authority.sqlite")}
        SQLState(self.config["state"]).initialize()
        self.store = StateClient(self.fixture.redis, self.config["state"])
        for key in ("server_1", "grant_1"):
            self.store.set(key, self.fixture.redis.get(key))
            self.fixture.redis.delete(key)
        self.runtime = Runtime(self.config, self.store)
        gateway = web.Application(handler_args={"auto_decompress": False})
        self.sessions = apps.register_web_app_routes(gateway, self.runtime)
        gateway.router.add_get("/healthz", lambda _: web.Response(text="control-health"))
        self.gateway_runner = web.AppRunner(gateway, access_log=None)
        await self.gateway_runner.setup()
        gateway_site = web.TCPSite(self.gateway_runner, "127.0.0.1", 0)
        await gateway_site.start()
        self.base = "http://127.0.0.1:" + str(gateway_site._server.sockets[0].getsockname()[1])
        self.client = aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar(), timeout=aiohttp.ClientTimeout(total=8))

    async def asyncTearDown(self):
        await self.client.close()
        await self.gateway_runner.cleanup()
        await self.upstream_runner.cleanup()
        self.fixture.doCleanups()

    def headers(self, cookie=None, origin=None, **extra):
        result = {"Host": self.origin.removeprefix("https://")}
        if cookie:
            result["Cookie"] = apps.COOKIE_NAME + "=" + cookie
        if origin:
            result["Origin"] = origin
        result.update(extra)
        return result

    async def launch(self, browser_session=None):
        intent = apps.create_launch(self.runtime, self.fixture.token, "1", browser_session=browser_session)
        response = await self.client.post(self.base + "/_isolate/launch", headers=self.headers(origin=self.config["dashboard"]["public_url"]),
            data={"code": intent["code"]}, allow_redirects=False)
        self.assertEqual(response.status, 303, await response.text())
        cookie = SimpleCookie()
        for header in response.headers.getall("Set-Cookie", []):
            cookie.load(header)
        morsel = cookie[apps.COOKIE_NAME]
        self.assertTrue(morsel["secure"])
        self.assertTrue(morsel["httponly"])
        self.assertEqual(morsel["samesite"], "Lax")
        self.assertFalse(morsel["domain"])
        return morsel.value, intent

    async def test_real_http_cookies_redirects_headers_queries_and_single_runtime_session(self):
        self.config['protocols']['targets']['1']['pass_authorization'] = True
        cookie, intent = await self.launch()
        self.assertNotIn(self.fixture.token, json.dumps(intent))
        self.assertNotIn(intent["code"], intent["launch_url"])
        headers = self.headers(cookie, Authorization="Bearer NEVER-FORWARD-IDP", **{"X-Forwarded-Host": "evil.example", "Impersonate-User": "root"})
        first = await self.client.get(self.base + "/login", headers=headers, allow_redirects=False)
        self.assertEqual(first.status, 302, await first.text())
        self.assertEqual(first.headers["Location"], self.origin + "/dashboard?next=%2Fapi%2Fv1")
        upstream_cookies = first.headers.getall("Set-Cookie")
        self.assertEqual(len(upstream_cookies), 1)
        self.assertNotIn("Domain=", upstream_cookies[0])
        self.assertIn("Secure", upstream_cookies[0])
        self.assertNotIn("Authorization", self.seen[-1]["headers"])
        self.assertNotIn("Impersonate-User", self.seen[-1]["headers"])
        self.assertEqual(self.seen[-1]["headers"]["X-Forwarded-Host"], "app1.isolate-apps.test")
        headers["Cookie"] += "; app_login=current-user; preexisting=another-user"
        second = await self.client.post(self.base + "/api?next=%2Fapi%2Fv1&x=a+b", headers=dict(headers, Origin=self.origin), data=b"payload")
        self.assertEqual(second.status, 200, await second.text())
        self.assertEqual(self.seen[-1]["query"], "next=/api/v1&x=a b")
        self.assertEqual(self.seen[-1]["body"], b"payload")
        self.assertEqual(self.seen[-1]["headers"]["Cookie"], "app_login=current-user")
        self.assertEqual(len(self.sessions.active), 1)
        self.assertEqual(len(self.store.keys("web_app_session_*")), 1)
        self.assertEqual(self.fixture.redis.keys("web_app_session_*"), [])
        logs = "\n".join(path.read_text() for path in Path(self.fixture.directory.name).rglob("session.jsonl"))
        self.assertIn('"event": "web_request"', logs)
        self.assertNotIn(self.fixture.token, logs)
        self.assertNotIn("payload", logs)
        self.assertNotIn("app_login=", logs)

    async def test_launch_replay_origin_cookie_fixation_and_control_routes_are_denied(self):
        cookie, intent = await self.launch()
        replay = await self.client.post(self.base + "/_isolate/launch", headers=self.headers(origin=self.config["dashboard"]["public_url"]), data={"code": intent["code"]})
        self.assertEqual(replay.status, 403)
        control_path = await self.client.get(self.base + "/healthz", headers=self.headers())
        self.assertEqual(control_path.status, 403)
        self.assertNotEqual(await control_path.text(), "control-health")
        for host in ('app1.isolate-apps.test:443', 'APP1.ISOLATE-APPS.TEST', 'app1.isolate-apps.test.', 'app1.isolate-apps.test:8443', 'user@app1.isolate-apps.test'):
            variant = await self.client.get(self.base + '/healthz', headers={'Host': host})
            self.assertIn(variant.status, (400, 403))
            self.assertNotEqual(await variant.text(), 'control-health')
        duplicate = await self.client.get(self.base + "/", headers=self.headers(cookie, Cookie=apps.COOKIE_NAME + "=" + cookie + "; " + apps.COOKIE_NAME + "=" + cookie))
        self.assertEqual(duplicate.status, 403)
        mutation = await self.client.post(self.base + "/api", headers=self.headers(cookie, origin="https://evil.example"), data=b"attack")
        self.assertEqual(mutation.status, 403)
        external = await self.client.get(self.base + "/external", headers=self.headers(cookie), allow_redirects=False)
        self.assertEqual(external.status, 403)
        self.assertNotIn("Location", external.headers)

    async def test_websocket_text_binary_and_control_logout_close_the_same_owner(self):
        handle = "browser-session-owner-0001"
        self.store.set("isolate_browser_" + handle, json.dumps({"sub": self.fixture.claims["sub"], "token": self.fixture.token}))
        cookie, _ = await self.launch(handle)
        socket = await self.client.ws_connect(self.base + "/ws", headers=self.headers(cookie, origin=self.origin), protocols=["chat"])
        self.assertEqual(socket.protocol, "chat")
        await socket.send_str("hello")
        self.assertEqual((await socket.receive()).data, "echo:hello")
        await socket.send_bytes(b"binary")
        self.assertEqual((await socket.receive()).data, b"yranib")
        self.store.delete("isolate_browser_" + handle)
        message = await asyncio.wait_for(socket.receive(), 3)
        self.assertIn(message.type, (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING))
        self.assertFalse(self.sessions.active)

    async def test_revocation_recovery_owner_loss_and_expiry_fail_closed(self):
        from isolate_recovery import rotate_authority_epoch
        for kind in ("grant", "epoch", "owner", "expiry"):
            cookie, _ = await self.launch()
            key, entry = next(iter(self.sessions.active.items()))
            before = self.store.get("grant_1")
            if kind == "grant":
                self.store.delete("grant_1")
            elif kind == "epoch":
                rotate_authority_epoch(self.store, self.config, "test", "explicit recovery")
            elif kind == "owner":
                record = json.loads(self.store.get(key))
                record["owner_node"] = "different-node"
                self.store.set(key, json.dumps(record))
            else:
                entry["expires_at"] = time.time() - 1
            response = await self.client.get(self.base + "/", headers=self.headers(cookie))
            self.assertEqual(response.status, 403, kind)
            await self.sessions.close(key)
            if kind == "grant":
                self.store.set("grant_1", before)

    async def test_upstream_credentials_never_forward_the_proxy_or_identity_cookie(self):
        secret = Path(self.fixture.directory.name) / "app-token"
        secret.write_text("upstream-private-secret")
        secret.chmod(0o600)
        self.config["protocols"]["targets"]["1"]["bearer_token_file"] = str(secret)
        cookie, _ = await self.launch()
        response = await self.client.get(self.base + "/", headers=self.headers(cookie, Authorization="Bearer idp-private"))
        self.assertEqual(response.status, 200, await response.text())
        self.assertEqual(self.seen[-1]["headers"]["Authorization"], "Bearer upstream-private-secret")
        self.assertNotIn("Cookie", self.seen[-1]["headers"])
        self.assertNotIn("upstream-private-secret", await response.text())

    async def test_parallel_assets_reuse_one_approval_and_one_lease(self):
        cookie, _ = await self.launch()
        key, entry = next(iter(self.sessions.active.items()))
        connection = entry["context"]["connection_id"]
        async def request(index):
            response = await self.client.get(self.base + "/asset-" + str(index), headers=self.headers(cookie))
            self.assertEqual(response.status, 200, await response.text())
        await asyncio.gather(*(request(index) for index in range(24)))
        self.assertEqual(self.sessions.active[key]["context"]["connection_id"], connection)
        self.assertEqual(len(self.sessions.active), 1)

    async def test_compressed_request_keeps_its_wire_encoding(self):
        cookie, _ = await self.launch()
        payload = gzip.compress(b'compressed-app-request')
        response = await self.client.post(self.base + '/compressed', data=payload,
            headers=self.headers(cookie, origin=self.origin, **{'Content-Encoding': 'gzip'}))
        await response.read()
        self.assertEqual(response.status, 200)
        self.assertEqual(self.seen[-1]['body'], payload)
        self.assertEqual(self.seen[-1]['headers']['Content-Encoding'], 'gzip')

    async def test_untrusted_upstream_tls_does_not_receive_credentials_or_requests(self):
        import ssl
        cookie, _ = await self.launch()
        entry = next(iter(self.sessions.active.values()))
        entry['ssl'] = ssl.create_default_context()
        response = await self.client.get(self.base + '/', headers=self.headers(cookie))
        self.assertEqual(response.status, 502)
        self.assertEqual(self.seen, [])

    async def test_actual_approval_is_consumed_once_and_revocation_ends_application(self):
        from isolate_session_approvals import list_session_approvals, decide_session_approval, revoke_session_approval
        self.config['session_approval'] = {'enabled': True, 'required_projects': ['prod'], 'poll_interval_seconds': 1}
        self.config['dashboard']['role_bindings'] = [{'group': 'Managers', 'role': 'approver', 'projects': ['prod']}]
        launch = asyncio.create_task(self.launch())
        for _ in range(100):
            requests = await asyncio.to_thread(list_session_approvals, self.store)
            if requests:
                break
            await asyncio.sleep(.02)
        self.assertEqual(len(requests), 1)
        actor = {'keycloak_sub': 'manager-subject', 'username': 'manager', 'groups': ['Managers']}
        self.assertEqual(requests[0]['status'], 'pending')
        self.assertFalse(self.seen)
        await asyncio.to_thread(decide_session_approval, self.store, self.config, requests[0]['id'], actor)
        cookie, _ = await asyncio.wait_for(launch, 4)
        for path in ('/asset-1', '/asset-2'):
            response = await self.client.get(self.base + path, headers=self.headers(cookie))
            self.assertEqual(response.status, 200, await response.text())
        requests = list_session_approvals(self.store)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]['status'], 'active')
        await asyncio.to_thread(revoke_session_approval, self.store, self.config, requests[0]['id'], actor)
        response = await self.client.get(self.base + '/', headers=self.headers(cookie))
        self.assertEqual(response.status, 403)


class ApplicationValidationTest(unittest.TestCase):
    def config(self):
        return {"web_apps": {"enabled": True}, "api": {"enabled": True},
            "dashboard": {"public_url": "https://access.example.com"},
            "gateway": {"public_web_url": "https://gateway.example.com"},
            "oidc": {"enabled": True, "issuer": "https://login.identity.net/tenant", "client_id": "isolate",
                     "trusted_endpoint_origins": ["https://tokens.identity.org"]},
            "protocols": {"enabled": True, "targets": {"1": {"protocol": "http", "mode": "web-application", "public_origin": "https://app1.isolate-apps.test"}}}}

    def test_control_gateway_idp_shared_suffixes_ip_and_ambiguous_origins_are_rejected(self):
        for origin in ("https://app.example.com", "https://app.identity.net", "https://app.identity.org",
                       "https://127.0.0.1", "http://app1.isolate-apps.test", "https://USER:secret@app1.isolate-apps.test", "https://app1.isolate-apps.test/path"):
            config = self.config()
            config["protocols"]["targets"]["1"]["public_origin"] = origin
            with self.subTest(origin=origin), self.assertRaises(apps.ProtocolError):
                apps.configured_applications(config)
        self.assertEqual(apps.configured_applications(self.config()), {"https://app1.isolate-apps.test": "1"})

    def test_redirects_remain_bound_to_the_trusted_application(self):
        target = {"scheme": "https", "hostname": "internal.example", "port": 8443, "public_origin": "https://app.isolate-apps.test"}
        self.assertEqual(apps.rewrite_location(target, "/login?next=%2F"), "https://app.isolate-apps.test/login?next=%2F")
        self.assertEqual(apps.rewrite_location(target, "https://internal.example:8443/login"), "https://app.isolate-apps.test/login")
        for value in ("javascript:alert(1)", "//evil.example/login", "https://internal.example:8443@evil.example/login", "/login\nSet-Cookie:evil"):
            with self.subTest(location=value), self.assertRaises(apps.ProtocolError):
                apps.rewrite_location(target, value)


if __name__ == "__main__":
    unittest.main()
