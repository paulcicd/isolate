"""Policy-bound HTTP/Kubernetes proxies and encrypted database transport.

Legacy database transport preserves end-to-end native authentication/TLS.
Explicit database_proxy, web-application and Kubernetes streaming modes extend
this boundary with credential mediation and channel-aware runtime checks.
"""

import asyncio
import contextlib
import fnmatch
import ipaddress
import json
import socket
import ssl
import struct
from urllib.parse import unquote, urlsplit, urlunsplit


class ProtocolError(ValueError):
    pass


HTTP_PROTOCOLS = frozenset(("http", "kubernetes"))
DATABASE_PROTOCOLS = frozenset(("postgresql", "mysql"))
PROTOCOLS = HTTP_PROTOCOLS | DATABASE_PROTOCOLS
_HOP_HEADERS = frozenset(("connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "authorization", "cookie", "host",
    "forwarded", "x-real-ip", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"))
_REQUEST_HEADERS = frozenset(("accept", "accept-encoding", "content-type", "content-encoding",
    "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "user-agent"))
_RESPONSE_HEADERS = frozenset(("content-type", "content-encoding", "etag", "last-modified",
    "retry-after", "warning", "www-authenticate"))


def _port(value):
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid target port") from exc
    if result < 1 or result > 65535:
        raise ProtocolError("invalid target port")
    return result


def _path(value):
    """Normalize for policy checks without accepting ambiguous path traversal."""
    value = str(value or "/")
    decoded = value
    for _ in range(4):
        current = unquote(decoded, errors="strict")
        if current == decoded:
            break
        decoded = current
    else:
        raise ProtocolError("excessively encoded path")
    if not decoded.startswith("/") or "//" in decoded or "\\" in decoded or "://" in decoded:
        raise ProtocolError("invalid proxy path")
    if any(ord(char) < 32 or ord(char) == 127 for char in decoded) or "#" in decoded or "?" in decoded:
        raise ProtocolError("invalid proxy path")
    if any(segment in (".", "..") for segment in decoded.split("/")):
        raise ProtocolError("path traversal is not permitted")
    return decoded


def resolve_target(config, host, protocol):
    """Resolve a trusted adapter target and pin it to the inventory IP.

    A configured DNS name is retained only for HTTP Host/TLS verification. DNS
    resolution never chooses the actual network address used by this adapter.
    """
    host = host or {}
    options = config.get("protocols") or {}
    if options.get("enabled") is not True or protocol not in PROTOCOLS:
        raise ProtocolError("protocol adapters are disabled or unsupported")
    target = dict((options.get("targets") or {}).get(str((host or {}).get("server_id"))) or {})
    if target.get("protocol") != protocol:
        raise ProtocolError("resource is not configured for this protocol")
    for feature in ("database_proxy", "kubernetes"):
        value = target.get(feature, {})
        if not isinstance(value, dict) or "enabled" in value and not isinstance(value["enabled"], bool):
            raise ProtocolError(feature + " must be an object with a boolean enabled flag")
    if not host.get("project_name") or target.get("project") != host["project_name"]:
        raise ProtocolError("target project differs from inventory")
    try:
        address = str(ipaddress.ip_address(host["server_ip"]))
        parsed = urlsplit(str(target.get("upstream") or ""))
        port = parsed.port
    except (ValueError, KeyError) as exc:
        raise ProtocolError("target must have a valid inventory IP and upstream URL") from exc
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or any(char.isspace() or ord(char) < 32 for char in parsed.netloc)):
        raise ProtocolError("upstream must be a fixed URL without credentials, query or fragment")
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal is not None and str(literal) != address:
        raise ProtocolError("literal upstream IP differs from inventory")
    if protocol in HTTP_PROTOCOLS:
        if parsed.scheme not in ("https", "http"):
            raise ProtocolError("HTTP target requires an HTTP(S) upstream")
        if parsed.scheme != "https" and not (
                target.get("allow_loopback_http") is True and ipaddress.ip_address(address).is_loopback):
            raise ProtocolError("HTTPS is required for upstream HTTP connections")
        if protocol == "kubernetes" and parsed.scheme != "https":
            raise ProtocolError("Kubernetes requires HTTPS")
        base_path = _path(parsed.path or "/").rstrip("/")
        port = _port(port or (443 if parsed.scheme == "https" else 80))
        if protocol == "kubernetes":
            if target.get("impersonation") is not True or not target.get("bearer_token_file"):
                raise ProtocolError("Kubernetes requires a service token and explicit impersonation")
            for key in ("impersonation_user_prefix", "impersonation_group_prefix"):
                prefix = target.get(key, "isolate:")
                if not isinstance(prefix, str) or not prefix or prefix.startswith("system:") or any(ord(c) < 33 for c in prefix):
                    raise ProtocolError("Kubernetes impersonation prefixes must be nonempty and outside system:")
            if not target.get("allowed_paths"):
                raise ProtocolError("Kubernetes requires explicit allowed_paths")
        profile = "http-request"
    else:
        if parsed.scheme != protocol or parsed.path not in ("", "/"):
            raise ProtocolError("database upstream must use its protocol scheme and contain no path")
        brokered = target.get("database_proxy") or {}
        if not isinstance(brokered, dict):
            raise ProtocolError("database_proxy must be an object")
        if "enabled" in brokered and not isinstance(brokered["enabled"], bool):
            raise ProtocolError("database_proxy.enabled must be a boolean")
        if not brokered.get("enabled") and target.get("database_native_auth") is not True:
            raise ProtocolError("database transport requires explicit database_native_auth acknowledgement")
        if target.get("require_native_tls", True) is not True:
            raise ProtocolError("database transport requires native database TLS")
        port = _port(port or (5432 if protocol == "postgresql" else 3306))
        base_path = ""
        profile = "sql-query" if brokered.get("enabled") else "connection"
    target.update(protocol=protocol, address=address, hostname=parsed.hostname, port=port,
                  base_path=base_path, scheme=parsed.scheme, audit_profile=profile)
    if protocol == "http" and target.get("mode") == "web-application":
        from isolate_web_apps import validate_web_app_target
        validate_web_app_target(config, target)
    if protocol in DATABASE_PROTOCOLS and (target.get("database_proxy") or {}).get("enabled"):
        from isolate_database_proxy import validate_database_target
        validate_database_target(target)
    if protocol == "kubernetes" and (target.get("kubernetes") or {}).get("enabled"):
        from isolate_kubernetes import validate_kubernetes_target
        validate_kubernetes_target(target)
    return target


def validate_http_request(target, method, path, query=None):
    method = str(method).upper()
    path = _path(path)
    methods = target.get("allowed_methods") or ["GET", "HEAD"]
    if method not in methods or method in ("CONNECT", "TRACE"):
        raise ProtocolError("HTTP method is not permitted")
    paths = target.get("allowed_paths") or ["/*"]
    if not isinstance(paths, list) or not all(isinstance(pattern, str) and pattern.startswith("/") for pattern in paths):
        raise ProtocolError("invalid allowed_paths configuration")
    if not any(fnmatch.fnmatchcase(path, pattern) for pattern in paths):
        raise ProtocolError("HTTP path is not permitted")
    if target["protocol"] == "kubernetes":
        # Upgrade/SPDY/WebSocket subresources need separate channel semantics.
        if any(part in ("exec", "attach", "portforward", "proxy") for part in path.split("/")):
            raise ProtocolError("interactive Kubernetes subresources are not supported")
        watch_values = query.getall("watch", []) if hasattr(query, "getall") else [(query or {}).get("watch", "")]
        if any(str(value).lower() in ("1", "true") for value in watch_values) and target.get("allow_watch") is not True:
            raise ProtocolError("Kubernetes watch is not enabled")
    return method, path


def _read_secret(path):
    try:
        from isolate_credentials import _read_file
        secret = _read_file(path, secret=True, maximum=65536).decode("utf-8").strip()
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise ProtocolError("cannot read configured upstream credential") from exc
    if not secret or len(secret) > 65536 or any(ord(c) < 33 or ord(c) == 127 for c in secret):
        raise ProtocolError("invalid upstream credential")
    return secret


def upstream_headers(target, headers, identity):
    connection_tokens = {item.strip().lower() for item in str(headers.get("Connection", "")).split(",")}
    result = {name: value for name, value in headers.items() if name.lower() in _REQUEST_HEADERS
              and name.lower() not in _HOP_HEADERS and name.lower() not in connection_tokens}
    if target.get("bearer_token_file"):
        result["Authorization"] = "Bearer " + _read_secret(target["bearer_token_file"])
    if target["protocol"] == "kubernetes":
        subject = str(identity.get("keycloak_sub") or "")
        if not subject or any(ord(c) < 33 or ord(c) == 127 for c in subject):
            raise ProtocolError("a stable authenticated subject is required")
        result["Impersonate-User"] = target.get("impersonation_user_prefix", "isolate:") + subject
        # Multiple headers are required by the Kubernetes impersonation API.
        result = list(result.items())
        prefix = target.get("impersonation_group_prefix", "isolate:")
        for group in sorted(set(identity.get("groups") or [])):
            if not isinstance(group, str) or any(ord(c) < 33 or ord(c) == 127 for c in group):
                raise ProtocolError("invalid signed identity group")
            result.append(("Impersonate-Group", prefix + group))
    return result


def _ssl_context(target):
    context = ssl.create_default_context(cafile=target.get("ca_file"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if target.get("client_cert_file"):
        context.load_cert_chain(target["client_cert_file"], target.get("client_key_file"))
    return context


def _request_url(target, path, query_string=""):
    from yarl import URL
    # URL.with_path quotes decoded paths; user input never becomes an authority.
    hostname = "[{}]".format(target["hostname"]) if ":" in target["hostname"] else target["hostname"]
    base = URL(urlunsplit((target["scheme"], "{}:{}".format(hostname, target["port"]), "", "", "")))
    return base.with_path(target["base_path"] + path).with_query(query_string)


def _pinned_resolver(target):
    from aiohttp.abc import AbstractResolver

    class PinnedResolver(AbstractResolver):
        async def resolve(self, host, port=0, family=socket.AF_INET):
            if host.lower().rstrip(".") != target["hostname"].lower().rstrip("."):
                raise OSError("proxy attempted to resolve a different upstream")
            address = ipaddress.ip_address(target["address"])
            return [{"hostname": host, "host": str(address), "port": target["port"],
                     "family": socket.AF_INET6 if address.version == 6 else socket.AF_INET,
                     "proto": 0, "flags": socket.AI_NUMERICHOST}]

        async def close(self):
            pass

    return PinnedResolver()


def _secure_ingress(request):
    if request.secure:
        return True
    try:
        return ipaddress.ip_address(request.remote or "").is_loopback
    except ValueError:
        return False


def _check_origin(request, config):
    origin = request.headers.get("Origin")
    if origin:
        allowed = (config.get("protocols") or {}).get("allowed_origins") or []
        if origin not in allowed:
            raise ProtocolError("browser origin is not permitted")
    if not _secure_ingress(request):
        raise ProtocolError("encrypted ingress or a loopback TLS terminator is required")


async def _call(runtime, method, *args, **kwargs):
    return await asyncio.to_thread(getattr(runtime, method), *args, **kwargs)


async def _prepare(runtime, context, disconnected):
    # Keep approval cancellation and lease cleanup identical to SSH ingress.
    from isolate_gateway import _prepare as prepare_session
    await prepare_session(runtime, context, disconnected)


async def _http_disconnected(request):
    while request.transport is not None and not request.transport.is_closing():
        await asyncio.sleep(0.05)


async def _database_disconnected(websocket):
    from aiohttp import WSMsgType
    message = await websocket.receive()
    if message.type not in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
        raise ProtocolError("database input is not accepted before authorization completes")


async def _guard(runtime, context):
    interval = max(0.1, min(5.0, float((runtime.config.get("gateway") or {}).get("recheck_interval", 1))))
    while True:
        await asyncio.sleep(interval)
        await _call(runtime, "recheck", context)


async def _guarded(runtime, context, operation):
    task = asyncio.create_task(operation)
    guard = asyncio.create_task(_guard(runtime, context))
    try:
        finished, _ = await asyncio.wait((task, guard), return_when=asyncio.FIRST_COMPLETED)
        if guard in finished:
            guard.result()
            raise ProtocolError("session guard stopped")
        return await task
    finally:
        for pending in (task, guard):
            if not pending.done():
                pending.cancel()
        await asyncio.gather(task, guard, return_exceptions=True)


async def proxy_http_request(request, runtime, protocol):
    """Forward one authenticated request with bounded bodies and no redirects."""
    import aiohttp
    from aiohttp import web
    context = None
    downstream = None
    exit_code = 1

    def failure(message, status):
        if downstream is not None and downstream.prepared:
            if request.transport:
                request.transport.close()
            return downstream
        return web.json_response({"error": message}, status=status)

    try:
        _check_origin(request, runtime.config)
        if request.headers.get("Upgrade"):
            raise ProtocolError("HTTP upgrades are not supported")
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) > 65536:
            raise ProtocolError("a bearer token is required")
        host_id = request.match_info["host_id"]
        context = await _call(runtime, "authorize", authorization[7:], host_id, protocol=protocol, source_ip=request.remote)
        target = resolve_target(runtime.config, context["host"], protocol)
        if target.get("mode") == "web-application":
            raise ProtocolError("use the isolated application origin from the workspace")
        method, path = validate_http_request(target, request.method, "/" + request.match_info.get("path", ""), request.query)
        context["audit_profile"] = "http-request"
        context["protocol_request"] = {"method": method, "path": path}
        await _prepare(runtime, context, _http_disconnected(request))
        await _call(runtime, "start", context)
        await _call(runtime, "recheck", context)
        limit = max(1, min(16777216, int(target.get("max_request_bytes", 1048576))))
        if request.content_length is not None and request.content_length > limit:
            raise ProtocolError("request body exceeds target limit")
        body = bytearray()

        async def read_body():
            async for chunk in request.content.iter_chunked(65536):
                body.extend(chunk)
                if len(body) > limit:
                    raise ProtocolError("request body exceeds target limit")
        await _guarded(runtime, context, asyncio.wait_for(read_body(), timeout=30))
        await _call(runtime, "recheck", context)
        headers = upstream_headers(target, request.headers, context["identity"])
        timeout = aiohttp.ClientTimeout(total=max(1, min(300, int(target.get("timeout_seconds", 60)))))
        connector = aiohttp.TCPConnector(resolver=_pinned_resolver(target), use_dns_cache=False,
                                         ssl=_ssl_context(target))

        async def forward():
            nonlocal downstream
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, auto_decompress=False,
                    trust_env=False, cookie_jar=aiohttp.DummyCookieJar()) as client:
                async with client.request(method, _request_url(target, path, request.query_string),
                        headers=headers, data=bytes(body), allow_redirects=False) as upstream:
                    if 300 <= upstream.status < 400 and upstream.status != 304:
                        raise ProtocolError("upstream redirects are not permitted")
                    response_headers = {name: value for name, value in upstream.headers.items()
                                        if name.lower() in _RESPONSE_HEADERS}
                    response_headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                        "Content-Security-Policy": "sandbox; default-src 'none'", "Referrer-Policy": "no-referrer",
                        "Cross-Origin-Resource-Policy": "same-origin"})
                    response = web.StreamResponse(status=upstream.status, headers=response_headers)
                    downstream = response
                    await response.prepare(request)
                    received = 0
                    maximum = max(1, min(67108864, int(target.get("max_response_bytes", 8388608))))
                    async for chunk in upstream.content.iter_chunked(65536):
                        received += len(chunk)
                        if received > maximum:
                            raise ProtocolError("response body exceeds target limit")
                        await response.write(chunk)
                    context["protocol_request"].update(status=upstream.status, response_bytes=received)
                    await response.write_eof()
                    return response
        response = await _guarded(runtime, context, forward())
        exit_code = 0
        return response
    except ProtocolError as exc:
        return failure(str(exc), 403)
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
        return failure("upstream connection failed", 502)
    except Exception:
        # Do not send IdP, credential files or target details to callers.
        return failure("protocol authorization or session failed", 403)
    finally:
        if context is not None:
            with contextlib.suppress(Exception):
                await _call(runtime, "finish", context, exit_code=exit_code)


class _WebSocketReader:
    def __init__(self, websocket):
        self.websocket = websocket
        self.buffer = bytearray()

    async def read(self, size=65536):
        from aiohttp import WSMsgType
        if self.buffer:
            chunk = bytes(self.buffer[:size])
            del self.buffer[:size]
            return chunk
        message = await self.websocket.receive()
        if message.type == WSMsgType.BINARY:
            if len(message.data) > size:
                self.buffer.extend(message.data[size:])
            return message.data[:size]
        if message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
            return b""
        raise ProtocolError("database transport accepts only binary frames after authentication")

    async def readexactly(self, size):
        result = bytearray()
        while len(result) < size:
            chunk = await self.read(size - len(result))
            if not chunk:
                raise ProtocolError("database TLS handshake was interrupted")
            result.extend(chunk)
        return bytes(result)


async def require_database_tls(protocol, client, websocket, reader, writer):
    """Permit only native TLS upgrade, before credentials can be submitted."""
    if protocol == "postgresql":
        packet = await client.readexactly(8)
        if packet != struct.pack("!II", 8, 80877103):
            raise ProtocolError("PostgreSQL SSLRequest is required; use sslmode=verify-full")
        writer.write(packet)
        await writer.drain()
        reply = await reader.readexactly(1)
        if reply != b"S":
            raise ProtocolError("PostgreSQL upstream refused TLS")
        await websocket.send_bytes(reply)
    elif protocol == "mysql":
        greeting_header = await reader.readexactly(4)
        size = int.from_bytes(greeting_header[:3], "little")
        if size < 20 or size > 65536 or greeting_header[3] != 0:
            raise ProtocolError("invalid MySQL greeting")
        greeting = await reader.readexactly(size)
        if greeting[0] != 10:
            raise ProtocolError("MySQL protocol 10 is required")
        end_version = greeting.find(b"\0", 1)
        flags_offset = end_version + 1 + 4 + 8 + 1
        if end_version < 0 or flags_offset + 2 > len(greeting):
            raise ProtocolError("invalid MySQL greeting")
        if not int.from_bytes(greeting[flags_offset:flags_offset + 2], "little") & 0x800:
            raise ProtocolError("MySQL upstream does not advertise TLS")
        await websocket.send_bytes(greeting_header + greeting)
        header = await client.readexactly(4)
        if int.from_bytes(header[:3], "little") != 32 or header[3] != 1:
            raise ProtocolError("MySQL SSLRequest is required")
        payload = await client.readexactly(32)
        if not int.from_bytes(payload[:4], "little") & 0x800:
            raise ProtocolError("MySQL SSLRequest is required")
        writer.write(header + payload)
        await writer.drain()
    else:
        raise ProtocolError("unsupported database protocol")


async def database_websocket(request, runtime, registry=None):
    """One-time ticket -> inventory-pinned TCP channel with native TLS gate."""
    from aiohttp import web, WSMsgType
    try:
        _check_origin(request, runtime.config)
    except ProtocolError as exc:
        return web.json_response({"error": str(exc)}, status=403)
    websocket = web.WebSocketResponse(max_msg_size=65536, heartbeat=20)
    await websocket.prepare(request)
    if registry is not None:
        registry.add(websocket)
    context = None
    writer = None
    exit_code = 1
    try:
        message = await asyncio.wait_for(websocket.receive(), timeout=10)
        if message.type != WSMsgType.TEXT or len(message.data) > 4096:
            raise ProtocolError("initial authentication frame is required")
        auth = json.loads(message.data)
        if not isinstance(auth, dict) or auth.get("protocol") not in DATABASE_PROTOCOLS:
            raise ProtocolError("unsupported database protocol")
        if set(auth) - {"ticket", "protocol", "frontend_password", "cancel"}:
            raise ProtocolError("unsupported database authentication fields")
        ticket = auth.get("ticket")
        if not isinstance(ticket, str) or len(ticket) > 2048:
            raise ProtocolError("a one-time ticket is required")
        context = await _call(runtime, "consume_ticket", ticket, protocol=auth["protocol"], source_ip=request.remote)
        target = resolve_target(runtime.config, context["host"], auth["protocol"])
        if (target.get("database_proxy") or {}).get("enabled"):
            from isolate_database_proxy import proxy_database_session, cancel_database_query
            if auth.get("cancel") is not None:
                if auth["protocol"] != "postgresql":
                    raise ProtocolError("only PostgreSQL has a separate cancellation channel")
                await cancel_database_query(runtime, context, target, auth["cancel"])
                await websocket.send_json({"type": "cancelled"})
                exit_code = 0
                return websocket
            password = auth.get("frontend_password")
            if (not isinstance(password, str) or not 32 <= len(password) <= 512
                    or any(ord(char) < 33 or ord(char) > 126 for char in password)):
                raise ProtocolError("private local frontend credential is required")
            context["audit_profile"] = "sql-query"
            context["protocol_stats"] = {"received_bytes": 0, "sent_bytes": 0}
            await _prepare(runtime, context, _database_disconnected(websocket))
            await _call(runtime, "start", context)
            await _call(runtime, "recheck", context)
            await websocket.send_json({"type": "ready", "protocol": target["protocol"], "audit_profile": "sql-query",
                "database_native_auth": False, "require_native_tls": True})
            await _guarded(runtime, context, proxy_database_session(runtime, context, target,
                _WebSocketReader(websocket), websocket, frontend_password=password))
            exit_code = 0
            return websocket
        if auth.get("cancel") is not None or auth.get("frontend_password") is not None:
            raise ProtocolError("credential brokering is not enabled for this target")
        context["audit_profile"] = "connection"
        context["protocol_stats"] = {"received_bytes": 0, "sent_bytes": 0}
        await _prepare(runtime, context, _database_disconnected(websocket))
        await _call(runtime, "start", context)
        await _call(runtime, "recheck", context)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target["address"], target["port"]),
                                                timeout=min(30, max(1, int(target.get("connect_timeout", 5)))))
        await websocket.send_json({"type": "ready", "protocol": target["protocol"], "audit_profile": "connection",
                                    "database_native_auth": True, "require_native_tls": True})
        client = _WebSocketReader(websocket)
        await asyncio.wait_for(require_database_tls(target["protocol"], client, websocket, reader, writer), timeout=10)
        await _call(runtime, "recheck", context)

        async def client_to_database():
            while True:
                data = await client.read()
                if not data:
                    return
                context["protocol_stats"]["received_bytes"] += len(data)
                writer.write(data)
                await writer.drain()

        async def database_to_client():
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                context["protocol_stats"]["sent_bytes"] += len(data)
                await websocket.send_bytes(data)

        async def transfer():
            incoming = asyncio.create_task(client_to_database())
            outgoing = asyncio.create_task(database_to_client())
            try:
                completed, _ = await asyncio.wait((incoming, outgoing), return_when=asyncio.FIRST_COMPLETED)
                for task in completed:
                    task.result()
            finally:
                for task in (incoming, outgoing):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(incoming, outgoing, return_exceptions=True)
        await _guarded(runtime, context, transfer())
        exit_code = 0
    except asyncio.CancelledError:
        raise
    except Exception:
        if not websocket.closed:
            with contextlib.suppress(Exception):
                await websocket.send_json({"type": "error", "message": "database connection denied or closed"})
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await websocket.close(code=1000 if exit_code == 0 else 1008)
        if registry is not None:
            registry.discard(websocket)
        if context is not None:
            with contextlib.suppress(Exception):
                await _call(runtime, "finish", context, exit_code=exit_code)
    return websocket


def register_protocol_routes(app, runtime):
    """Register on the gateway's aiohttp app; all routes remain opt-in."""
    from aiohttp import web
    options = runtime.config.get("protocols") or {}
    if options.get("enabled") is not True:
        return
    maximum = max(1, min(4096, int(options.get("max_connections", 100))))
    active = 0
    handlers = set()
    sockets = set()

    def bounded(handler):
        async def handle(request):
            nonlocal active
            if active >= maximum:
                return web.json_response({"error": "protocol connection limit reached"}, status=503)
            active += 1
            task = asyncio.current_task()
            handlers.add(task)
            try:
                return await handler(request)
            finally:
                active -= 1
                handlers.discard(task)
        return handle

    async def http(request):
        return await proxy_http_request(request, runtime, "http")

    async def kubernetes(request):
        target = (runtime.config.get("protocols", {}).get("targets", {}).get(request.match_info["host_id"]) or {})
        if (target.get("kubernetes") or {}).get("enabled"):
            from isolate_kubernetes import proxy_kubernetes_request
            return await proxy_kubernetes_request(request, runtime, sockets)
        return await proxy_http_request(request, runtime, "kubernetes")

    async def database(request):
        return await database_websocket(request, runtime, sockets)

    app.router.add_route("*", "/protocols/http/{host_id}/{path:.*}", bounded(http))
    app.router.add_route("*", "/protocols/kubernetes/{host_id}/{path:.*}", bounded(kubernetes))
    app.router.add_get("/protocols/database", bounded(database))

    async def shutdown(application):
        await asyncio.gather(*(socket.close(code=1001, message=b"Gateway restarting")
                               for socket in tuple(sockets)), return_exceptions=True)
        pending = tuple(handlers)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    app.on_shutdown.append(shutdown)
