"""Policy-bound Kubernetes HTTP and versioned multiplexed stream proxy.

No browser/client header supplies upstream identity. Remote command streams are
decoded before forwarding; SPDY-over-WebSocket port-forward headers are inspected
before a new stream is allowed to reach the API server. Legacy HTTP SPDY is not
silently tunneled. Per-operation grants supplement the base kubernetes grant.
"""

import asyncio
import base64
import contextlib
import fnmatch
import hashlib
import json
import re
import struct
import zlib

from isolate_protocols import ProtocolError


REMOTE_PROTOCOLS = ("v5.channel.k8s.io", "v4.channel.k8s.io")
PORTFORWARD_PROTOCOL = "SPDY/3.1+portforward.k8s.io"
OPERATIONS = frozenset(("exec", "attach", "logs", "watch", "portforward"))
_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_POD = re.compile(r"^/api/v1/namespaces/([^/]+)/pods/([^/]+)/(exec|attach|log|portforward)$")
_NAMESPACE = re.compile(r"/namespaces/([^/]+)(?:/|$)")
_DISCOVERY = re.compile(r"^/(?:version|api(?:/v[0-9]+)?|apis(?:/[a-z0-9.-]+(?:/v[0-9]+(?:(?:alpha|beta)[0-9]+)?)?)?|openapi/v[23](?:/[A-Za-z0-9._/-]+)?)$")

# SPDY/3 standard compression dictionary, not executable third-party code.
# Source: github.com/moby/spdystream/spdy/dictionary.go, Go Authors (2013),
# BSD-3-Clause; attribution/license link is retained in deploy/KUBERNETES.md.
_SPDY_DICTIONARY = base64.b64decode(
    "AAAAB29wdGlvbnMAAAAEaGVhZAAAAARwb3N0AAAAA3B1dAAAAAZkZWxldGUAAAAFdHJhY2UAAAAGYWNjZXB0AAAADmFjY2VwdC1jaGFyc2V0AAAAD2FjY2VwdC1lbmNvZGluZwAAAA9hY2NlcHQtbGFuZ3VhZ2UAAAANYWNjZXB0LXJhbmdlcwAAAANhZ2UAAAAFYWxsb3cAAAANYXV0aG9yaXphdGlvbgAAAA1jYWNoZS1jb250cm9sAAAACmNvbm5lY3Rpb24AAAAMY29udGVudC1iYXNlAAAAEGNvbnRlbnQtZW5jb2RpbmcAAAAQY29udGVudC1sYW5ndWFnZQAAAA5jb250ZW50LWxlbmd0aAAAABBjb250ZW50LWxvY2F0aW9uAAAAC2NvbnRlbnQtbWQ1AAAADWNvbnRlbnQtcmFuZ2UAAAAMY29udGVudC10eXBlAAAABGRhdGUAAAAEZXRhZwAAAAZleHBlY3QAAAAHZXhwaXJlcwAAAARmcm9tAAAABGhvc3QAAAAIaWYtbWF0Y2gAAAARaWYtbW9kaWZpZWQtc2luY2UAAAANaWYtbm9uZS1tYXRjaAAAAAhpZi1yYW5nZQAAABNpZi11bm1vZGlmaWVkLXNpbmNlAAAADWxhc3QtbW9kaWZpZWQAAAAIbG9jYXRpb24AAAAMbWF4LWZvcndhcmRzAAAABnByYWdtYQAAABJwcm94eS1hdXRoZW50aWNhdGUAAAATcHJveHktYXV0aG9yaXphdGlvbgAAAAVyYW5nZQAAAAdyZWZlcmVyAAAAC3JldHJ5LWFmdGVyAAAABnNlcnZlcgAAAAJ0ZQAAAAd0cmFpbGVyAAAAEXRyYW5zZmVyLWVuY29kaW5nAAAAB3VwZ3JhZGUAAAAKdXNlci1hZ2VudAAAAAR2YXJ5AAAAA3ZpYQAAAAd3YXJuaW5nAAAAEHd3dy1hdXRoZW50aWNhdGUAAAAGbWV0aG9kAAAAA2dldAAAAAZzdGF0dXMAAAAGMjAwIE9LAAAAB3ZlcnNpb24AAAAISFRUUC8xLjEAAAADdXJsAAAABnB1YmxpYwAAAApzZXQtY29va2llAAAACmtlZXAtYWxpdmUAAAAGb3JpZ2luMTAwMTAxMjAxMjAyMjA1MjA2MzAwMzAyMzAzMzA0MzA1MzA2MzA3NDAyNDA1NDA2NDA3NDA4NDA5NDEwNDExNDEyNDEzNDE0NDE1NDE2NDE3NTAyNTA0NTA1MjAzIE5vbi1BdXRob3JpdGF0aXZlIEluZm9ybWF0aW9uMjA0IE5vIENvbnRlbnQzMDEgTW92ZWQgUGVybWFuZW50bHk0MDAgQmFkIFJlcXVlc3Q0MDEgVW5hdXRob3JpemVkNDAzIEZvcmJpZGRlbjQwNCBOb3QgRm91bmQ1MDAgSW50ZXJuYWwgU2VydmVyIEVycm9yNTAxIE5vdCBJbXBsZW1lbnRlZDUwMyBTZXJ2aWNlIFVuYXZhaWxhYmxlSmFuIEZlYiBNYXIgQXByIE1heSBKdW4gSnVsIEF1ZyBTZXB0IE9jdCBOb3YgRGVjIDAwOjAwOjAwIE1vbiwgVHVlLCBXZWQsIFRodSwgRnJpLCBTYXQsIFN1biwgR01UY2h1bmtlZCx0ZXh0L2h0bWwsaW1hZ2UvcG5nLGltYWdlL2pwZyxpbWFnZS9naWYsYXBwbGljYXRpb24veG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCx0ZXh0L3BsYWluLHRleHQvamF2YXNjcmlwdCxwdWJsaWNwcml2YXRlbWF4LWFnZT1nemlwLGRlZmxhdGUsc2RjaGNoYXJzZXQ9dXRmLThjaGFyc2V0PWlzby04ODU5LTEsdXRmLSwqLGVucT0wLg=="
)


def _bounded(value, default, low, high, field):
    value = default if value is None else value
    if type(value) is not int or not low <= value <= high:
        raise ProtocolError("invalid Kubernetes " + field)
    return value


def validate_kubernetes_target(target):
    """Offline validation; no cluster, discovery or secret content is read."""
    options = target.get("kubernetes") or {}
    if not isinstance(options, dict):
        raise ProtocolError("kubernetes options must be an object")
    if options.get("enabled") is not True:
        raise ProtocolError("Kubernetes streaming must be explicitly enabled")
    namespaces = options.get("allowed_namespaces")
    if (not isinstance(namespaces, list) or not namespaces or len(namespaces) > 1000
            or any(not isinstance(value, str) or value != "*" and not _NAME.fullmatch(value) for value in namespaces)):
        raise ProtocolError("Kubernetes requires explicit allowed_namespaces")
    operations = options.get("allowed_operations", [])
    if (not isinstance(operations, list) or any(not isinstance(value, str) or value not in OPERATIONS for value in operations)
            or len(operations) != len(set(operations))):
        raise ProtocolError("invalid Kubernetes allowed_operations")
    ports = options.get("allowed_ports", [])
    if (not isinstance(ports, list) or len(ports) > 1000
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)):
        raise ProtocolError("invalid Kubernetes allowed_ports")
    if "portforward" in operations and not ports:
        raise ProtocolError("Kubernetes port-forward requires exact allowed_ports")
    for field in ("record_output", "record_logs"):
        if field in options and type(options[field]) is not bool:
            raise ProtocolError("Kubernetes " + field + " must be boolean")
    _bounded(options.get("max_channels"), 16, 2, 128, "max_channels")
    _bounded(options.get("max_frame_bytes"), 1048576, 1024, 4194304, "max_frame_bytes")
    _bounded(options.get("max_stream_bytes"), 1073741824, 1024, 1099511627776, "max_stream_bytes")
    _bounded(options.get("stream_timeout_seconds"), 3600, 1, 86400, "stream_timeout_seconds")
    return dict(options)


def _values(query, name):
    if hasattr(query, "getall"):
        return query.getall(name, [])
    value = (query or {}).get(name)
    return value if isinstance(value, list) else [] if value is None else [value]


def _boolean(query, name, default=False):
    values = _values(query, name)
    if len(values) > 1 or values and str(values[0]).lower() not in ("true", "false", "1", "0"):
        raise ProtocolError("invalid or duplicate Kubernetes boolean query")
    return default if not values else str(values[0]).lower() in ("true", "1")


def classify_request(target, method, path, query=None):
    from isolate_protocols import validate_http_request
    options = validate_kubernetes_target(target)
    # Retain exactly the API adapter's URL/method allowlist and traversal checks;
    # this module supplies the channel semantics previously denied there.
    method, path = validate_http_request(dict(target, protocol="http"), method, path, query)
    if re.search(r"/(?:pods|services|nodes)/[^/]+/proxy(?:/|$)", path) or re.match(r"^/api/[^/]+/proxy(?:/|$)", path):
        raise ProtocolError("Kubernetes API proxy subresources are not supported")
    namespace = _NAMESPACE.search(path)
    namespace = namespace.group(1) if namespace else None
    if namespace and not _NAME.fullmatch(namespace):
        raise ProtocolError("invalid Kubernetes namespace")
    if namespace and namespace not in options["allowed_namespaces"] and "*" not in options["allowed_namespaces"]:
        raise ProtocolError("Kubernetes namespace is not permitted")
    if not namespace and "*" not in options["allowed_namespaces"] and not (method in ("GET", "HEAD") and _DISCOVERY.fullmatch(path)):
        raise ProtocolError("cluster-scoped Kubernetes requests require explicit global namespace scope")
    matched = _POD.fullmatch(path)
    operation = None
    pod = None
    if matched:
        namespace, pod, operation = matched.groups()
        if not _NAME.fullmatch(pod):
            raise ProtocolError("invalid Kubernetes pod")
        operation = "logs" if operation == "log" else operation
    watch = _boolean(query, "watch")
    if watch or re.match(r"^/(?:api/[^/]+|apis/[^/]+/[^/]+)/watch/", path):
        if operation:
            raise ProtocolError("watch is not a valid pod stream parameter")
        operation = "watch"
    if operation and operation not in options.get("allowed_operations", []):
        raise ProtocolError("Kubernetes operation is not enabled")
    if operation in ("exec", "attach", "portforward") and method not in ("GET", "POST"):
        raise ProtocolError("invalid Kubernetes streaming method")
    if operation in ("logs", "watch") and method != "GET":
        raise ProtocolError("Kubernetes logs/watch requires GET")
    intent = {"operation": operation, "action": "kubernetes-" + operation if operation else None,
              "namespace": namespace, "pod": pod, "path": path, "method": method}
    if operation in ("exec", "attach"):
        for name in ("stdin", "stdout", "stderr", "tty"):
            intent[name] = _boolean(query, name)
        commands = _values(query, "command")
        if len(commands) > 256 or any(not isinstance(value, str) or len(value) > 8192 or "\x00" in value for value in commands):
            raise ProtocolError("Kubernetes command arguments exceed bounds")
        # The digest provides correlation without storing passwords in argv.
        if operation == "exec":
            if not commands:
                raise ProtocolError("exec requires a command")
            intent["command_sha256"] = hashlib.sha256(json.dumps(commands, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
        if intent["tty"]:
            intent["stderr"] = False
    if operation == "portforward":
        raw = _values(query, "ports")
        requested = []
        for value in raw:
            for port in str(value).split(","):
                if not port.isdecimal() or not 1 <= int(port) <= 65535:
                    raise ProtocolError("invalid Kubernetes port")
                requested.append(int(port))
        if any(port not in options.get("allowed_ports", []) for port in requested):
            raise ProtocolError("Kubernetes port is not permitted")
        intent["ports"] = sorted(set(requested))
    return intent


def authorize_operation(runtime, context, intent):
    """Read current action grants; cached base kubernetes access never expands it."""
    action = intent.get("action")
    if not action:
        return
    from isolate import load_grants, load_project_sets
    from isolate_identity_security import assert_workload_action
    from isolate_policy import resolve_grant
    assert_workload_action(runtime.config, context["identity"], action)
    decision = resolve_grant(context["identity"], project=context["host"]["project_name"], host=context["host"],
        grants=load_grants(runtime.redis), project_sets=load_project_sets(runtime.redis),
        defaults={**runtime.config.get("policy", {}), **runtime.config.get("ssh", {})}, action=action)
    if (decision.get("remote_user"), decision.get("sudo_mode")) != (context["decision"].get("remote_user"), context["decision"].get("sudo_mode")):
        raise ProtocolError("Kubernetes operation identity differs from its session")
    expires = decision.get("matched_rule", {}).get("expires_at")
    if expires:
        context["deadline"] = min(context["deadline"], int(expires))
    return decision


class RemoteCommandChannels:
    def __init__(self, protocol, intent):
        if protocol not in REMOTE_PROTOCOLS:
            raise ProtocolError("unsupported Kubernetes remote command protocol")
        self.protocol, self.intent = protocol, intent
        self.closed = set()

    def validate(self, payload, *, upstream=False):
        if not isinstance(payload, bytes) or not payload:
            raise ProtocolError("Kubernetes channels require nonempty binary frames")
        channel = payload[0]
        if upstream:
            allowed = ({1} if self.intent.get("stdout") else set()) | ({2} if self.intent.get("stderr") else set()) | {3}
        else:
            allowed = ({0} if self.intent.get("stdin") else set()) | ({4} if self.intent.get("tty") else set())
        if channel == 255:
            if self.protocol != REMOTE_PROTOCOLS[0] or len(payload) != 2 or payload[1] not in allowed:
                raise ProtocolError("invalid Kubernetes stream close signal")
            self.closed.add((upstream, payload[1]))
            return {"channel": payload[1], "close": True}
        if channel not in allowed or (upstream, channel) in self.closed:
            raise ProtocolError("Kubernetes channel is not permitted")
        if channel == 4:
            try:
                size = json.loads(payload[1:])
                if (not isinstance(size, dict) or set(size) != {"Width", "Height"}
                        or any(type(size[key]) is not int or not 1 <= size[key] <= 65535 for key in size)):
                    raise ValueError()
            except (ValueError, UnicodeError, RecursionError):
                raise ProtocolError("invalid Kubernetes terminal resize") from None
        return {"channel": channel, "bytes": len(payload) - 1}


class SPDYPortForward:
    """Inspect independent SPDY directions while preserving wire bytes verbatim."""
    def __init__(self, allowed_ports, *, max_channels=16, max_frame_bytes=1048576, requested_ports=()):
        self.allowed_ports = frozenset(allowed_ports)
        self.requested_ports = frozenset(requested_ports)
        self.maximum, self.maximum_frame = max_channels, max_frame_bytes
        self.buffers = {False: bytearray(), True: bytearray()}
        self.inflater = zlib.decompressobj(zdict=_SPDY_DICTIONARY)
        self.streams = {}
        self.highest = 0

    def _headers(self, compressed):
        try:
            data = self.inflater.decompress(compressed, 8193)
            if len(data) > 8192 or self.inflater.unconsumed_tail or self.inflater.unused_data or self.inflater.eof:
                raise ValueError()
            view, offset = memoryview(data), 0
            def number():
                nonlocal offset
                value = struct.unpack_from("!I", view, offset)[0]
                offset += 4
                return value
            count = number()
            if not 1 <= count <= 16:
                raise ValueError()
            result = {}
            for _ in range(count):
                size = number()
                if not 1 <= size <= 256 or offset + size > len(view):
                    raise ValueError()
                name = bytes(view[offset:offset + size]).decode("ascii")
                offset += size
                size = number()
                if not 1 <= size <= 1024 or offset + size > len(view):
                    raise ValueError()
                value = bytes(view[offset:offset + size]).decode("ascii")
                offset += size
                if name.lower() in result or name != name.lower() or any(ord(c) < 32 or ord(c) > 126 for c in value):
                    raise ValueError()
                result[name] = value
            if offset != len(view):
                raise ValueError()
            return result
        except (ValueError, UnicodeError, struct.error, zlib.error):
            raise ProtocolError("invalid bounded SPDY header block") from None

    def feed(self, data, *, upstream=False):
        if not isinstance(data, bytes):
            raise ProtocolError("SPDY tunnel requires binary frames")
        buffer = self.buffers[upstream]
        buffer.extend(data)
        output = []
        while len(buffer) >= 8:
            first, flags_size = struct.unpack_from("!II", buffer)
            size, flags = flags_size & 0xFFFFFF, flags_size >> 24
            if size > self.maximum_frame:
                raise ProtocolError("SPDY frame exceeds target limit")
            if len(buffer) < size + 8:
                break
            frame = bytes(buffer[:size + 8])
            del buffer[:size + 8]
            payload = frame[8:]
            event = None
            if first & 0x80000000:
                version, kind = (first >> 16) & 0x7FFF, first & 0xFFFF
                if version != 3:
                    raise ProtocolError("SPDY version is not supported")
                if kind == 1:
                    if upstream or len(payload) < 10 or flags & ~1:
                        raise ProtocolError("invalid port-forward stream creation")
                    stream_id, associated = struct.unpack_from("!II", payload)
                    if not stream_id or stream_id & 0x80000000 or stream_id % 2 != 1 or stream_id <= self.highest or associated:
                        raise ProtocolError("invalid or reused SPDY stream")
                    if len(self.streams) >= self.maximum:
                        raise ProtocolError("too many Kubernetes port-forward channels")
                    headers = self._headers(payload[10:])
                    if set(headers) != {"streamtype", "port", "requestid"}:
                        raise ProtocolError("unexpected port-forward stream headers")
                    port, request_id = headers["port"], headers["requestid"]
                    if not port.isdecimal() or len(port) > 5 or int(port) not in self.allowed_ports or self.requested_ports and int(port) not in self.requested_ports:
                        raise ProtocolError("Kubernetes port-forward channel port is not permitted")
                    if headers["streamtype"] not in ("data", "error") or not request_id.isdecimal() or len(request_id) > 20:
                        raise ProtocolError("invalid Kubernetes port-forward stream identity")
                    if any(row["request_id"] == request_id and (row["port"] != int(port) or row["stream_type"] == headers["streamtype"]) for row in self.streams.values()):
                        raise ProtocolError("Kubernetes port-forward request streams conflict")
                    self.highest = stream_id
                    row = {"port": int(port), "request_id": request_id, "stream_type": headers["streamtype"], "client_closed": bool(flags & 1), "server_closed": False}
                    self.streams[stream_id] = row
                    event = {"event": "open", "channel": stream_id, **{key: row[key] for key in ("port", "stream_type", "request_id")}}
                elif kind in (2, 8):
                    if not upstream or len(payload) < 4 or flags & ~1:
                        raise ProtocolError("unexpected SPDY headers")
                    stream_id = struct.unpack_from("!I", payload)[0]
                    if stream_id not in self.streams:
                        raise ProtocolError("unknown SPDY response stream")
                    if flags & 1:
                        self.streams[stream_id]["server_closed"] = True
                elif kind == 3:
                    if len(payload) != 8 or flags:
                        raise ProtocolError("invalid SPDY stream reset")
                    stream_id = struct.unpack_from("!I", payload)[0]
                    if not stream_id or stream_id > self.highest:
                        raise ProtocolError("unknown SPDY reset stream")
                    self.streams.pop(stream_id, None)
                    event = {"event": "close", "channel": stream_id}
                elif kind == 4:
                    if flags & ~1 or len(payload) < 4 or (len(payload) - 4) % 8 or struct.unpack_from("!I", payload)[0] != (len(payload) - 4) // 8 or len(payload) > 516:
                        raise ProtocolError("invalid SPDY settings")
                elif kind == 6:
                    if len(payload) != 4 or flags:
                        raise ProtocolError("invalid SPDY ping")
                elif kind == 7:
                    if len(payload) != 8 or flags:
                        raise ProtocolError("invalid SPDY shutdown")
                elif kind == 9:
                    if len(payload) != 8 or flags:
                        raise ProtocolError("invalid SPDY window update")
                    stream_id, delta = struct.unpack_from("!II", payload)
                    if stream_id > self.highest or not delta or delta & 0x80000000:
                        raise ProtocolError("invalid SPDY flow-control stream")
                else:
                    raise ProtocolError("unsupported SPDY control frame")
            else:
                stream_id = first
                row = self.streams.get(stream_id)
                if not row or flags & ~1 or row["server_closed" if upstream else "client_closed"]:
                    raise ProtocolError("unknown or closed SPDY data stream")
                if not upstream and row["stream_type"] == "error" and payload:
                    raise ProtocolError("client cannot write Kubernetes error stream")
                if flags & 1:
                    row["server_closed" if upstream else "client_closed"] = True
                event = {"event": "data", "channel": stream_id, "port": row["port"], "stream_type": row["stream_type"], "bytes": size}
            for stream_id in list(self.streams):
                if self.streams[stream_id]["client_closed"] and self.streams[stream_id]["server_closed"]:
                    del self.streams[stream_id]
            output.append((frame, event))
        if len(buffer) > self.maximum_frame + 8:
            raise ProtocolError("SPDY frame buffer exceeds target limit")
        return output


async def _check(runtime, context, intent):
    from isolate_protocols import _call
    await _call(runtime, "recheck", context)
    await asyncio.to_thread(authorize_operation, runtime, context, intent)


async def _guarded(runtime, context, intent, operation):
    interval = max(.1, min(5., float(runtime.config.get("gateway", {}).get("recheck_interval", 1))))
    async def guard():
        while True:
            await asyncio.sleep(interval)
            await _check(runtime, context, intent)
    task, watcher = asyncio.create_task(operation), asyncio.create_task(guard())
    try:
        completed, _ = await asyncio.wait((task, watcher), return_when=asyncio.FIRST_COMPLETED)
        if watcher in completed:
            watcher.result()
            raise ProtocolError("Kubernetes authorization guard stopped")
        return await task
    finally:
        for pending in (task, watcher):
            if not pending.done():
                pending.cancel()
        await asyncio.gather(task, watcher, return_exceptions=True)


async def proxy_kubernetes_request(request, runtime, registry=None):
    """Native kubectl HTTP/WS entry point; the listener itself supplies TLS."""
    import aiohttp
    from aiohttp import web, WSMsgType
    from isolate_protocols import (_call, _check_origin, _http_disconnected, _pinned_resolver,
        _prepare, _request_url, _ssl_context, resolve_target, upstream_headers, _RESPONSE_HEADERS)
    context = downstream = upstream_socket = None
    exit_code = 1
    try:
        _check_origin(request, runtime.config)
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) > 65536:
            raise ProtocolError("a bearer token is required")
        context = await _call(runtime, "authorize", authorization[7:], request.match_info["host_id"], protocol="kubernetes", source_ip=request.remote)
        target = resolve_target(runtime.config, context["host"], "kubernetes")
        options = validate_kubernetes_target(target)
        intent = classify_request(target, request.method, "/" + request.match_info.get("path", ""), request.query)
        if len(request.query_string) > 32768:
            raise ProtocolError("Kubernetes query exceeds target limit")
        await asyncio.to_thread(authorize_operation, runtime, context, intent)
        context["audit_profile"] = "kubernetes-stream" if intent["operation"] else "http-request"
        context["protocol_request"] = {key: value for key, value in intent.items() if key in ("operation", "namespace", "pod", "method", "path", "ports", "command_sha256")}
        context["protocol_stats"] = {"received_bytes": 0, "sent_bytes": 0, "frames": 0}
        interactive = intent["operation"] in ("exec", "attach", "portforward")
        websocket = request.headers.get("Upgrade", "").lower() == "websocket"
        if interactive != websocket or request.headers.get("Upgrade") and not websocket:
            raise ProtocolError("Kubernetes interactive operations require a supported WebSocket upgrade")
        if websocket:
            offered = [value.strip() for value in request.headers.get("Sec-WebSocket-Protocol", "").split(",")]
            supported = [PORTFORWARD_PROTOCOL] if intent["operation"] == "portforward" else list(REMOTE_PROTOCOLS)
            protocols = [name for name in supported if name in offered]
            if not protocols:
                raise ProtocolError("unsupported Kubernetes WebSocket subprotocol")
        await _prepare(runtime, context, _http_disconnected(request))
        await _call(runtime, "start", context)
        await _check(runtime, context, intent)
        event_fields = dict(context["protocol_request"])
        event_fields["http_method"] = event_fields.pop("method")
        await _call(runtime, "channel_event", context, "kubernetes_operation_start", **event_fields)
        headers = upstream_headers(target, request.headers, context["identity"])
        connector = aiohttp.TCPConnector(resolver=_pinned_resolver(target), use_dns_cache=False, ssl=_ssl_context(target))
        timeout = aiohttp.ClientTimeout(total=None, connect=max(1, min(30, int(target.get("connect_timeout", 5)))))
        maximum = _bounded(options.get("max_stream_bytes"), 1073741824, 1024, 1099511627776, "max_stream_bytes")
        frame_limit = _bounded(options.get("max_frame_bytes"), 1048576, 1024, 4194304, "max_frame_bytes")
        deadline = _bounded(options.get("stream_timeout_seconds"), 3600, 1, 86400, "stream_timeout_seconds")

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, auto_decompress=False, trust_env=False,
                                       cookie_jar=aiohttp.DummyCookieJar()) as client:
            if websocket:
                socket_request = client.ws_connect(_request_url(target, intent["path"], request.query), headers=headers,
                    protocols=protocols, max_msg_size=frame_limit, heartbeat=20, compress=0, autoclose=True, autoping=True)
                upstream = await _guarded(runtime, context, intent, asyncio.wait_for(socket_request, 15))
                async with upstream:
                    upstream_socket = upstream
                    if upstream.protocol not in protocols:
                        raise ProtocolError("upstream did not select a permitted Kubernetes subprotocol")
                    downstream = web.WebSocketResponse(protocols=[upstream.protocol], max_msg_size=frame_limit, heartbeat=20, compress=False)
                    await downstream.prepare(request)
                    if registry is not None:
                        registry.add(downstream)
                    channels = (SPDYPortForward(options["allowed_ports"], max_channels=options.get("max_channels", 16),
                        max_frame_bytes=frame_limit, requested_ports=intent.get("ports", ())) if intent["operation"] == "portforward"
                        else RemoteCommandChannels(upstream.protocol, intent))

                    async def relay(source, destination, incoming):
                        async for message in source:
                            if message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING):
                                return
                            if message.type != WSMsgType.BINARY:
                                raise ProtocolError("Kubernetes streams accept binary frames only")
                            await asyncio.to_thread(authorize_operation, runtime, context, intent)
                            count_key = "received_bytes" if incoming else "sent_bytes"
                            context["protocol_stats"][count_key] += len(message.data)
                            context["protocol_stats"]["frames"] += 1
                            if context["protocol_stats"][count_key] > maximum:
                                raise ProtocolError("Kubernetes stream exceeds target byte limit")
                            if isinstance(channels, SPDYPortForward):
                                frames = channels.feed(message.data, upstream=incoming)
                                for frame, event in frames:
                                    if event and event["event"] in ("open", "close"):
                                        await _call(runtime, "channel_event", context, "kubernetes_channel_" + event["event"],
                                            **{key: value for key, value in event.items() if key != "event"})
                                    await destination.send_bytes(frame)
                            else:
                                channel = channels.validate(message.data, upstream=incoming)
                                if incoming and channel.get("channel") in (1, 2) and not channel.get("close") and options.get("record_output"):
                                    await _call(runtime, "record_output", context, message.data[1:])
                                await destination.send_bytes(message.data)

                    async def bridge():
                        forward = asyncio.create_task(relay(downstream, upstream, False))
                        backward = asyncio.create_task(relay(upstream, downstream, True))
                        try:
                            finished, _ = await asyncio.wait((forward, backward), return_when=asyncio.FIRST_COMPLETED)
                            for task in finished:
                                task.result()
                        finally:
                            for task in (forward, backward):
                                if not task.done():
                                    task.cancel()
                            await asyncio.gather(forward, backward, return_exceptions=True)
                    await _guarded(runtime, context, intent, asyncio.wait_for(bridge(), deadline))
                    await downstream.close()
                    exit_code = 0
                    return downstream
            else:
                limit = max(1, min(16777216, int(target.get("max_request_bytes", 1048576))))
                body = bytearray()
                async def read_body():
                    async for chunk in request.content.iter_chunked(65536):
                        body.extend(chunk)
                        if len(body) > limit:
                            raise ProtocolError("Kubernetes request body exceeds target limit")
                await _guarded(runtime, context, intent, asyncio.wait_for(read_body(), 30))
                async def transfer():
                    nonlocal downstream
                    async with client.request(intent["method"], _request_url(target, intent["path"], request.query),
                            headers=headers, data=bytes(body), allow_redirects=False) as response:
                        if 300 <= response.status < 400 and response.status != 304:
                            raise ProtocolError("Kubernetes upstream redirects are not permitted")
                        outgoing = {key: value for key, value in response.headers.items() if key.lower() in _RESPONSE_HEADERS}
                        outgoing.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
                        downstream = web.StreamResponse(status=response.status, headers=outgoing)
                        await downstream.prepare(request)
                        async for chunk in response.content.iter_chunked(65536):
                            await asyncio.to_thread(authorize_operation, runtime, context, intent)
                            context["protocol_stats"]["received_bytes"] += len(chunk)
                            if context["protocol_stats"]["received_bytes"] > maximum:
                                raise ProtocolError("Kubernetes response exceeds target byte limit")
                            if intent["operation"] == "logs" and options.get("record_logs"):
                                await _call(runtime, "record_output", context, chunk)
                            await downstream.write(chunk)
                        await downstream.write_eof()
                        context["protocol_request"]["status"] = response.status
                        return downstream
                result = await _guarded(runtime, context, intent, asyncio.wait_for(transfer(), deadline))
                exit_code = 0
                return result
    except (aiohttp.ClientError, OSError, asyncio.TimeoutError):
        if downstream is None:
            return web.json_response({"error": "Kubernetes upstream is unavailable"}, status=502)
    except Exception:
        if downstream is None:
            return web.json_response({"error": "Kubernetes operation is not permitted or authorization is unavailable"}, status=403)
    finally:
        if downstream is not None and isinstance(downstream, web.WebSocketResponse):
            with contextlib.suppress(Exception):
                await downstream.close(code=1008 if exit_code else 1000)
            if registry is not None:
                registry.discard(downstream)
        elif downstream is not None and downstream.prepared and exit_code and request.transport:
            request.transport.close()
        if upstream_socket is not None:
            with contextlib.suppress(Exception):
                await upstream_socket.close()
        if context is not None:
            with contextlib.suppress(Exception):
                await _call(runtime, "finish", context, exit_code=exit_code)
    return downstream or web.json_response({"error": "Kubernetes stream ended"}, status=403)
