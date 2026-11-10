"""Host-isolated browser applications with one authorized owner per session.

The control origin issues a single-use POST launch intent.  The application
origin receives only an opaque, HttpOnly host cookie; its upstream never sees
the IdP credential, launch intent or proxy cookie.  Live Runtime contexts are
node-local so an HTTP load balancer must keep the application session sticky.
An owner restart or lost lease requires a new launch instead of reconstructing
an approved session from an old SQL/Redis record.
"""
import asyncio
import base64
import contextlib
import hashlib
import html
from http.cookies import SimpleCookie, CookieError
import ipaddress
import json
import re
import secrets
import time
from urllib.parse import urlsplit, urlunsplit, urljoin

from isolate_protocols import (ProtocolError, _path, _pinned_resolver, _ssl_context,
    _request_url, _secure_ingress, _read_secret)


COOKIE_NAME = "__Host-IsolateApp"
RESERVED_PREFIX = "/_isolate/"
_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_DNS = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_HOP = frozenset(("connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade"))
_PRIVATE = frozenset(("authorization", "cookie", "host", "forwarded", "x-real-ip",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "content-length"))
_RESPONSE_PRIVATE = frozenset(("set-cookie", "location", "clear-site-data", "alt-svc",
    "strict-transport-security", "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-expose-headers", "access-control-allow-headers", "access-control-allow-methods"))


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _decode(raw):
    try:
        record = json.loads(raw)
        if not isinstance(record, dict):
            raise ValueError()
        return record
    except (ValueError, TypeError, UnicodeError):
        raise ProtocolError("application session is unavailable") from None


def _origin(value):
    """Require one ASCII DNS HTTPS origin; callers cannot supply a destination."""
    try:
        parsed = urlsplit(value)
        if (not isinstance(value, str) or parsed.scheme != "https" or not parsed.hostname
                or not _DNS.fullmatch(parsed.hostname) or parsed.hostname != parsed.hostname.lower()
                or parsed.username or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or parsed.port is not None and not 1 <= parsed.port <= 65535
                or parsed.netloc != parsed.netloc.lower()
                or value.rstrip("/") != "https://" + parsed.netloc or any(ord(c) < 33 or ord(c) > 126 for c in value)):
            raise ValueError()
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise ProtocolError("application origins must use DNS names")
        return "https://" + parsed.hostname + (":" + str(parsed.port) if parsed.port not in (None, 443) else "")
    except (TypeError, ValueError):
        raise ProtocolError("application origins must be explicit HTTPS DNS origins") from None


def _suffix(origin):
    return ".".join(urlsplit(origin).hostname.split(".")[-2:])


def _integer(options, name, default, low, high):
    value = options.get(name, default)
    if type(value) is not int or not low <= value <= high:
        raise ProtocolError("invalid application setting: " + name)
    return value


def configured_applications(config):
    """Return the exact origin-to-inventory mapping, validating isolation first."""
    options = config.get("web_apps") or {}
    if options.get("enabled") is not True:
        return {}
    if not config.get("protocols", {}).get("enabled") or not config.get("api", {}).get("enabled"):
        raise ProtocolError("browser applications require the protocol gateway and control API")
    control = _origin(str(config.get("dashboard", {}).get("public_url") or ""))
    # Conservative last-two-label comparison intentionally refuses e.g. co.uk
    # sibling registrable domains too.  It never downloads/guesses a public
    # suffix list or treats an application as part of the privileged site.
    reserved = [control]
    gateway = config.get("gateway", {}).get("public_web_url")
    if gateway:
        parsed = urlsplit(gateway)
        if parsed.scheme not in ("https", "wss"):
            raise ProtocolError("application gateway public URL requires HTTPS")
        reserved.append(_origin("https://" + parsed.netloc))
    from isolate_oidc import identity_provider_config
    provider = identity_provider_config(config)
    for privileged in [provider.get("issuer"), config.get("api", {}).get("client_url")] + list(provider.get("trusted_endpoint_origins") or []):
        if privileged:
            parsed = urlsplit(privileged)
            if parsed.scheme != "https":
                raise ProtocolError("application identity/control origins require HTTPS")
            if parsed.hostname and _DNS.fullmatch(parsed.hostname):
                reserved.append(_origin("https://" + parsed.netloc))
    mapping = {}
    targets = config.get("protocols", {}).get("targets", {})
    if not isinstance(targets, dict):
        raise ProtocolError("protocol targets must be an object")
    for host_id, target in targets.items():
        if not isinstance(target, dict) or target.get("mode") != "web-application":
            continue
        if not str(host_id).isdigit() or target.get("protocol") != "http":
            raise ProtocolError("browser applications require an HTTP inventory target")
        public = _origin(target.get("public_origin"))
        if any(_suffix(public) == _suffix(other) for other in reserved):
            raise ProtocolError("application and control/gateway origins require separate DNS suffixes")
        if public in mapping or any(urlsplit(public).hostname == urlsplit(other).hostname for other in mapping):
            raise ProtocolError("each application needs a unique DNS hostname")
        if target.get("allowed_redirect_origins") is not None:
            allowed = target["allowed_redirect_origins"]
            if not isinstance(allowed, list) or len(allowed) > 16:
                raise ProtocolError("application redirect origins must be a bounded list")
            for origin in allowed:
                _origin(origin)
        client_cookies = target.get("client_cookie_names", [])
        if (not isinstance(client_cookies, list) or len(client_cookies) > 32
                or any(not isinstance(name, str) or not _NAME.fullmatch(name) or name == COOKIE_NAME for name in client_cookies)):
            raise ProtocolError("client_cookie_names must be explicit bounded cookie names")
        _integer(target, "max_request_bytes", 16777216, 1, 268435456)
        _integer(target, "max_response_bytes", 67108864, 1, 1073741824)
        _integer(target, "timeout_seconds", 120, 1, 3600)
        _integer(target, "max_websocket_message_bytes", 1048576, 1024, 16777216)
        mapping[public] = str(host_id)
    _integer(options, "session_ttl_seconds", 3600, 30, 28800)
    _integer(options, "launch_ttl", 30, 5, 60)
    _integer(options, "idle_timeout_seconds", 900, 10, 28800)
    _integer(options, "max_sessions", 100, 1, 4096)
    _integer(options, "max_requests_per_session", 16, 1, 128)
    return mapping


def resolve_web_app_target(config, host):
    from isolate_protocols import resolve_target
    mapping = configured_applications(config)
    target = resolve_target(config, host, "http")
    result = validate_web_app_target(config, target)
    if mapping.get(result["public_origin"]) != str(host.get("server_id")):
        raise ProtocolError("application origin belongs to another inventory target")
    return result


def validate_web_app_target(config, target):
    """Validate resolved fields without recursing through resolve_target."""
    mapping = configured_applications(config)
    public = _origin(target.get("public_origin"))
    target_id = next((str(identifier) for identifier, configured in config.get("protocols", {}).get("targets", {}).items()
        if isinstance(configured, dict) and configured.get("mode") == "web-application" and _origin(configured.get("public_origin")) == public), None)
    if target.get("protocol") != "http" or target.get("mode") != "web-application" or mapping.get(public) != target_id:
        raise ProtocolError("resource is not a configured browser application")
    if target.get("base_path"):
        raise ProtocolError("browser applications require an upstream origin without a base path")
    target["public_origin"] = public
    return target


def create_launch(runtime, token, host_id, source_ip=None, browser_session=None):
    """Authorize a short-lived POST-only intent; it does not consume approval."""
    from isolate_cluster import node_ready
    from isolate_state import state_epoch
    if not node_ready(runtime.redis, runtime.config):
        raise ProtocolError("application ingress is draining")
    context = runtime.authorize(token, str(host_id), protocol="http", source_ip=source_ip)
    target = resolve_web_app_target(runtime.config, context["host"])
    if context["identity"].get("principal_type") == "service":
        raise ProtocolError("browser applications require a human identity")
    if browser_session is not None and (not isinstance(browser_session, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", browser_session)):
        raise ProtocolError("invalid browser session reference")
    from isolate_admission import check_admission
    check_admission(runtime.redis, {"admission": dict(runtime.config.get("admission", {}), enabled=True)},
        context["identity"]["keycloak_sub"], source_ip, kind="webapp_launch")
    expires = min(int(context["deadline"]), int(time.time()) + runtime.config.get("web_apps", {}).get("launch_ttl", 30))
    if expires <= time.time():
        raise ProtocolError("identity expires before application launch")
    code = secrets.token_urlsafe(32)
    record = {"host_id": str(host_id), "token": token, "subject": context["identity"]["keycloak_sub"],
        "origin": target["public_origin"], "target_revision": context["target_revision"],
        "epoch": state_epoch(runtime.redis), "expires_at": expires, "browser_session": browser_session}
    if not runtime.redis.set("web_app_launch_" + _digest(code), _encode(record), ex=max(1, expires - int(time.time())), nx=True):
        raise ProtocolError("application launch could not be stored")
    return {"launch_url": target["public_origin"] + RESERVED_PREFIX + "launch", "code": code, "expires_at": expires}


def _cookie_value(request):
    values = []
    for header in request.headers.getall("Cookie", []):
        for part in header.split(";"):
            name, separator, value = part.strip().partition("=")
            if name == COOKIE_NAME and separator:
                values.append(value)
    if len(values) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", values[0]):
        raise ProtocolError("launch this application from the Isolate workspace")
    return values[0]


def _connection_tokens(headers):
    return {item.strip().lower() for header in headers.getall("Connection", []) for item in header.split(",")}


def _application_cookies(headers, entry):
    cookies = []
    permitted = set(entry["target"].get("client_cookie_names") or [])
    bindings = entry["cookies"]
    for header in headers.getall("Cookie", []):
        if len(header) > 32768:
            raise ProtocolError("application cookies exceed the allowed size")
        for part in header.split(";"):
            name, separator, value = part.strip().partition("=")
            if not separator or not _NAME.fullmatch(name) or name == COOKIE_NAME:
                continue
            if name in permitted or _digest(name + "=" + value) in bindings.get(name, ()):
                cookies.append(name + "=" + value)
    return "; ".join(cookies)


def _upstream_credentials(config, target):
    """Return request-only credentials; never put them in a response/session log."""
    if target.get("bearer_token_file"):
        return "Bearer " + _read_secret(target["bearer_token_file"])
    selected = target.get("web_credentials")
    if not selected:
        return None
    if not isinstance(selected, dict):
        raise ProtocolError("invalid application credential configuration")
    mode = selected.get("authentication", "bearer")
    if selected.get("type") == "file":
        from isolate_credentials import _read_file
        try:
            data = json.loads(_read_file(selected.get("path"), secret=True, maximum=65536))
        except (ValueError, OSError, TypeError):
            raise ProtocolError("application credentials are unavailable") from None
    elif selected.get("type") == "vault":
        from isolate_credentials import _vault_request
        provider = config.get("credentials", {}).get("providers", {}).get(selected.get("provider"))
        if not isinstance(provider, dict):
            raise ProtocolError("application credential provider is unavailable")
        data = _vault_request(provider, selected.get("path", ""))
        if selected.get("kv_version", 2) == 2:
            data = data.get("data")
    else:
        raise ProtocolError("unsupported application credential provider")
    if not isinstance(data, dict):
        raise ProtocolError("application credential response is invalid")
    if mode == "bearer":
        value = data.get(selected.get("token_field", "token"))
        if not isinstance(value, str) or not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
            raise ProtocolError("application credential response is invalid")
        return "Bearer " + value
    if mode == "basic":
        username, password = data.get(selected.get("username_field", "username")), data.get(selected.get("password_field", "password"))
        if (not isinstance(username, str) or not username or ":" in username or not isinstance(password, str)
                or any(ord(c) < 32 or ord(c) == 127 for c in username + password)):
            raise ProtocolError("application credential response is invalid")
        return "Basic " + base64.b64encode((username + ":" + password).encode()).decode()
    raise ProtocolError("unsupported application authentication mode")


def application_request_headers(config, request, entry):
    blocked = _HOP | _PRIVATE | _connection_tokens(request.headers)
    result = {name: value for name, value in request.headers.items() if name.lower() not in blocked
        and not name.lower().startswith(("x-isolate-", "impersonate-", "sec-websocket-"))}
    origin = urlsplit(entry["target"]["public_origin"])
    result.update(Host=origin.netloc, **{"X-Forwarded-Host": origin.netloc, "X-Forwarded-Proto": "https"})
    cookies = _application_cookies(request.headers, entry)
    if cookies:
        result["Cookie"] = cookies
    credential = _upstream_credentials(config, entry["target"])
    if credential:
        result["Authorization"] = credential
    return result


def rewrite_location(target, location):
    if not isinstance(location, str) or len(location) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in location):
        raise ProtocolError("invalid application redirect")
    host = "[" + target["hostname"] + "]" if ":" in target["hostname"] else target["hostname"]
    default = 443 if target["scheme"] == "https" else 80
    upstream = urlunsplit((target["scheme"], host + (":" + str(target["port"]) if target["port"] != default else ""), "/", "", ""))
    parsed = urlsplit(urljoin(upstream, location))
    if parsed.username or parsed.password or parsed.scheme not in ("https", "http"):
        raise ProtocolError("unsafe application redirect")
    if parsed.hostname == target["hostname"] and (parsed.port or (443 if parsed.scheme == "https" else 80)) == target["port"] and parsed.scheme == target["scheme"]:
        return target["public_origin"] + urlunsplit(("", "", parsed.path or "/", parsed.query, parsed.fragment))
    public = urlsplit(target["public_origin"])
    if parsed.scheme == public.scheme and parsed.netloc == public.netloc:
        return parsed.geturl()
    if parsed.scheme == "https" and "https://" + parsed.netloc in (target.get("allowed_redirect_origins") or []):
        return parsed.geturl()
    raise ProtocolError("application redirect origin is not explicitly allowed")


def application_response_headers(target, upstream, entry):
    from multidict import CIMultiDict
    blocked = _HOP | _RESPONSE_PRIVATE | _connection_tokens(upstream.headers)
    result = CIMultiDict((name, value) for name, value in upstream.headers.items() if name.lower() not in blocked)
    if upstream.headers.get("Location"):
        result["Location"] = rewrite_location(target, upstream.headers["Location"])
    for raw in upstream.headers.getall("Set-Cookie", []):
        if len(raw) > 16384:
            raise ProtocolError("application cookie exceeds the allowed size")
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            raise ProtocolError("application returned an invalid cookie") from None
        if len(cookie) != 1:
            raise ProtocolError("application returned an ambiguous cookie")
        name, morsel = next(iter(cookie.items()))
        if not _NAME.fullmatch(name) or name == COOKIE_NAME:
            continue
        morsel["domain"] = ""
        morsel["secure"] = True
        if not morsel["path"] or name.startswith("__Host-"):
            morsel["path"] = "/"
        bindings = entry["cookies"]
        if name not in bindings and len(bindings) >= 128:
            raise ProtocolError("application cookie inventory exceeds its limit")
        values = bindings.setdefault(name, [])
        binding = _digest(name + "=" + morsel.coded_value)
        if binding not in values:
            values.append(binding)
            del values[:-8]
        result.add("Set-Cookie", morsel.OutputString())
    result["Cache-Control"] = "no-store"
    result["Referrer-Policy"] = "no-referrer"
    result["Cross-Origin-Resource-Policy"] = "same-origin"
    result["X-Content-Type-Options"] = "nosniff"
    # Upstream 'self' continues to mean this application's isolated origin.
    result.add("Content-Security-Policy", "frame-ancestors 'none'")
    return result


class ApplicationSessions:
    def __init__(self, runtime, registry=None):
        self.runtime, self.active = runtime, {}
        self.pending = 0
        self.sockets = registry if registry is not None else set()

    async def call(self, method, *args, **kwargs):
        return await asyncio.to_thread(getattr(self.runtime, method), *args, **kwargs)

    async def recheck(self, entry):
        from isolate_state import state_epoch
        async with entry["check_lock"]:
            if entry["closed"]:
                raise ProtocolError("application session is closed")
            record = _decode(await asyncio.to_thread(self.runtime.redis.get, entry["key"]))
            if record.get("owner_node") != self.runtime.node_id or record.get("epoch") != await asyncio.to_thread(state_epoch, self.runtime.redis):
                raise ProtocolError("application session owner or recovery epoch changed")
            browser = record.get("browser_session")
            if browser:
                current = await asyncio.to_thread(self.runtime.redis.get, "isolate_browser_" + browser)
                if current is None or _decode(current).get("sub") != record.get("subject"):
                    raise ProtocolError("control browser session has ended")
            if time.time() >= entry["expires_at"]:
                raise ProtocolError("application session expired")
            await self.call("recheck", entry["context"])

    async def close(self, key, exit_code=1):
        entry = self.active.pop(key, None)
        if entry is None or entry["closed"]:
            return
        entry["closed"] = True
        guard = entry.get("guard")
        if guard and guard is not asyncio.current_task():
            guard.cancel()
            await asyncio.gather(guard, return_exceptions=True)
        await asyncio.gather(*(ws.close(code=1008, message=b"Application session ended") for ws in tuple(entry["sockets"])), return_exceptions=True)
        for transport in tuple(entry["transports"]):
            transport.close()
        with contextlib.suppress(Exception):
            await asyncio.to_thread(self.runtime.redis.delete, key)
        with contextlib.suppress(Exception):
            await self.call("finish", entry["context"], exit_code=exit_code)

    async def guard(self, key):
        options = self.runtime.config.get("web_apps") or {}
        interval = max(.1, min(5., float(self.runtime.config.get("gateway", {}).get("recheck_interval", 2))))
        try:
            while key in self.active:
                await asyncio.sleep(interval)
                entry = self.active[key]
                if time.monotonic() - entry["last_seen"] > options.get("idle_timeout_seconds", 900):
                    raise ProtocolError("application session became idle")
                await self.recheck(entry)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.close(key)

    async def launch(self, request, host_id, origin):
        from aiohttp import web
        from isolate_state import state_epoch
        from isolate_gateway import _prepare
        from isolate_protocols import _http_disconnected
        control = _origin(self.runtime.config.get("dashboard", {}).get("public_url"))
        if request.method != "POST" or request.headers.get("Origin") != control:
            raise ProtocolError("application launch requires a control-origin POST")
        if request.content_type != "application/x-www-form-urlencoded" or request.content_length is not None and request.content_length > 4096:
            raise ProtocolError("invalid application launch body")
        body = await asyncio.wait_for(request.content.read(4097), 10)
        if len(body) > 4096:
            raise ProtocolError("application launch body exceeds its limit")
        from urllib.parse import parse_qs
        values = parse_qs(body.decode("ascii"), strict_parsing=True)
        if set(values) != {"code"} or len(values["code"]) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", values["code"][0]):
            raise ProtocolError("invalid application launch code")
        raw = await asyncio.to_thread(self.runtime.redis.getdel, "web_app_launch_" + _digest(values["code"][0]))
        record = _decode(raw)
        if record.get("origin") != origin or record.get("host_id") != host_id or record.get("expires_at", 0) <= time.time():
            raise ProtocolError("application launch is expired, consumed or bound to another host")
        if record.get("epoch") != await asyncio.to_thread(state_epoch, self.runtime.redis):
            raise ProtocolError("application launch cannot cross recovery")
        if len(self.active) + self.pending >= self.runtime.config.get("web_apps", {}).get("max_sessions", 100):
            raise ProtocolError("application session capacity is exhausted")
        self.pending += 1
        try:
            return await self.activate(request, host_id, record)
        finally:
            self.pending -= 1

    async def activate(self, request, host_id, record):
        from aiohttp import web
        from isolate_gateway import _prepare
        from isolate_protocols import _http_disconnected
        context = await self.call("authorize", record["token"], host_id, protocol="http", source_ip=request.remote)
        target = resolve_web_app_target(self.runtime.config, context["host"])
        if context["identity"].get("keycloak_sub") != record.get("subject") or context["target_revision"] != record.get("target_revision"):
            raise ProtocolError("application authorization changed after launch was requested")
        try:
            context["audit_profile"] = "web-application"
            await _prepare(self.runtime, context, _http_disconnected(request))
            await self.call("start", context)
            cookie = secrets.token_urlsafe(32)
            key = "web_app_session_" + _digest(cookie)
            expires = min(context["deadline"], time.time() + self.runtime.config.get("web_apps", {}).get("session_ttl_seconds", 3600))
            session = dict(record, owner_node=self.runtime.node_id, expires_at=expires, created_at=time.time(), connection_id=context["connection_id"])
            if not await asyncio.to_thread(self.runtime.redis.set, key, _encode(session), ex=max(1, int(expires - time.time())), nx=True):
                raise ProtocolError("application session could not be stored")
            entry = {"key": key, "context": context, "target": target, "cookies": {}, "closed": False,
                "expires_at": expires, "last_seen": time.monotonic(), "sockets": set(), "transports": set(),
                "check_lock": asyncio.Lock(), "requests": asyncio.Semaphore(self.runtime.config.get("web_apps", {}).get("max_requests_per_session", 16))}
            entry["ssl"] = _ssl_context(target) if target["scheme"] == "https" else None
            self.active[key] = entry
            await self.recheck(entry)
            entry["guard"] = asyncio.create_task(self.guard(key))
            response = web.Response(status=303, headers={"Location": "/", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
            response.set_cookie(COOKIE_NAME, cookie, max_age=max(1, int(expires - time.time())), path="/", secure=True, httponly=True, samesite="Lax")
            return response
        except BaseException:
            if "key" in locals() and key in self.active:
                await self.close(key)
                raise
            with contextlib.suppress(Exception):
                await self.call("finish", context, exit_code=1)
            raise

    async def entry(self, request, host_id, origin):
        cookie = _cookie_value(request)
        key = "web_app_session_" + _digest(cookie)
        entry = self.active.get(key)
        if entry is None:
            raise ProtocolError("application owner is unavailable; launch again through the workspace")
        if entry["target"]["public_origin"] != origin or str(entry["context"]["host"]["server_id"]) != host_id:
            raise ProtocolError("application session belongs to another origin")
        await self.recheck(entry)
        entry["last_seen"] = time.monotonic()
        return entry

    async def shutdown(self, app):
        await asyncio.gather(*(self.close(key) for key in tuple(self.active)), return_exceptions=True)


async def _audit(runtime, entry, event, **fields):
    logger = entry["context"].get("_logger")
    if logger:
        await asyncio.to_thread(logger.event_durable, event, connection_id=entry["context"]["connection_id"],
            host_id=entry["context"]["host"]["server_id"], protocol="http", audit_profile="web-application", **fields)


def _application_url(target, path, raw_query):
    from yarl import URL
    if len(raw_query) > 65536 or any(ord(char) < 32 or ord(char) == 127 for char in raw_query) or "#" in raw_query:
        raise ProtocolError("invalid application query")
    base = str(_request_url(target, path))
    return URL(base + ("?" + raw_query if raw_query else ""), encoded=True)


async def proxy_application(request, sessions, host_id, origin):
    import aiohttp
    from aiohttp import web, WSMsgType
    entry = await sessions.entry(request, host_id, origin)
    target = entry["target"]
    path = _path(request.rel_url.path)
    method = request.method.upper()
    if method in ("CONNECT", "TRACE") or method not in target.get("allowed_methods", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]):
        raise ProtocolError("application method is not permitted")
    import fnmatch
    if not any(fnmatch.fnmatchcase(path, pattern) for pattern in target.get("allowed_paths", ["/*"])):
        raise ProtocolError("application path is not permitted")
    websocket = request.headers.get("Upgrade", "").lower() == "websocket"
    if websocket or method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("Origin") != origin:
            raise ProtocolError("application mutation/upgrade requires its own origin")
    elif request.headers.get("Origin") not in (None, origin):
        raise ProtocolError("cross-origin application request is not permitted")
    if method == "OPTIONS" and request.headers.get("Access-Control-Request-Method"):
        raise ProtocolError("cross-origin preflight is not supported")
    request_id = secrets.token_hex(16)
    await _audit(sessions.runtime, entry, "web_request", request_id=request_id, method=method, path=path, websocket=websocket)
    timeout = aiohttp.ClientTimeout(total=target.get("timeout_seconds", 120))
    headers = await asyncio.to_thread(application_request_headers, sessions.runtime.config, request, entry)
    response = None
    received = sent = 0
    maximum = target.get("max_request_bytes", 16777216)
    if request.content_length is not None and request.content_length > maximum:
        raise ProtocolError("application request exceeds its limit")
    async def body():
        nonlocal received
        async for chunk in request.content.iter_chunked(65536):
            if entry["closed"]:
                raise ProtocolError("application session ended")
            received += len(chunk)
            if received > maximum:
                raise ProtocolError("application request exceeds its limit")
            yield chunk
    transport = request.transport
    async with entry["requests"]:
        connector = aiohttp.TCPConnector(resolver=_pinned_resolver(target), use_dns_cache=False, ssl=entry["ssl"])
        if transport:
            entry["transports"].add(transport)
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, auto_decompress=False,
                    trust_env=False, cookie_jar=aiohttp.DummyCookieJar()) as client:
                if websocket:
                    if target.get("websocket", True) is not True:
                        raise ProtocolError("application WebSocket is disabled")
                    protocols = [part.strip() for part in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if part.strip()]
                    if len(protocols) > 16 or any(not _NAME.fullmatch(value) for value in protocols):
                        raise ProtocolError("invalid application WebSocket protocols")
                    async with client.ws_connect(_application_url(target, path, request.rel_url.raw_query_string), headers=headers,
                            protocols=protocols, max_msg_size=target.get("max_websocket_message_bytes", 1048576), heartbeat=20,
                            autoclose=False, autoping=True) as upstream:
                        # The handshake response may set application cookies too.
                        response_headers = application_response_headers(target, upstream._response, entry)
                        for name in ("Content-Length", "Content-Type", "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions"):
                            response_headers.popall(name, None)
                        response = web.WebSocketResponse(protocols=[upstream.protocol] if upstream.protocol else (),
                            max_msg_size=target.get("max_websocket_message_bytes", 1048576), heartbeat=20)
                        response.headers.update(response_headers)
                        await response.prepare(request)
                        entry["sockets"].add(response)
                        sessions.sockets.add(response)
                        async def relay(source, destination):
                            async for message in source:
                                entry["last_seen"] = time.monotonic()
                                if entry["closed"]:
                                    return
                                if message.type == WSMsgType.TEXT:
                                    await destination.send_str(message.data)
                                elif message.type == WSMsgType.BINARY:
                                    await destination.send_bytes(message.data)
                                elif message.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                                    return
                        tasks = [asyncio.create_task(relay(response, upstream)), asyncio.create_task(relay(upstream, response))]
                        try:
                            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                            for task in done:
                                task.result()
                        finally:
                            for task in tasks:
                                task.cancel()
                            await asyncio.gather(*tasks, return_exceptions=True)
                            await response.close()
                            entry["sockets"].discard(response)
                            sessions.sockets.discard(response)
                        await _audit(sessions.runtime, entry, "web_response", request_id=request_id, status=101)
                        return response
                async with client.request(method, _application_url(target, path, request.rel_url.raw_query_string), headers=headers,
                        data=body(), allow_redirects=False) as upstream:
                    response = web.StreamResponse(status=upstream.status, headers=application_response_headers(target, upstream, entry))
                    await response.prepare(request)
                    async for chunk in upstream.content.iter_chunked(65536):
                        if entry["closed"]:
                            raise ProtocolError("application session ended")
                        sent += len(chunk)
                        if sent > target.get("max_response_bytes", 67108864):
                            raise ProtocolError("application response exceeds its limit")
                        await response.write(chunk)
                    await response.write_eof()
                    await _audit(sessions.runtime, entry, "web_response", request_id=request_id, status=upstream.status,
                        request_bytes=received, response_bytes=sent)
                    return response
        except Exception:
            if response is not None and response.prepared and request.transport:
                request.transport.close()
            raise
        finally:
            if transport:
                entry["transports"].discard(transport)
            if not connector.closed:
                await connector.close()


def register_web_app_routes(app, runtime, registry=None):
    """Install before routing: an app Host can never reach control/SSH routes."""
    from aiohttp import web
    configured_applications(runtime.config)
    sessions = ApplicationSessions(runtime, registry)
    app.on_shutdown.append(sessions.shutdown)

    @web.middleware
    async def application_origin(request, handler):
        mapping = configured_applications(runtime.config)
        hosts = request.headers.getall("Host", [])
        if len(hosts) != 1:
            raise web.HTTPBadRequest(text="One explicit Host header is required")
        # An app hostname must never fall through to control routes merely
        # because Host uses a default port, case variant or trailing dot.
        try:
            supplied = urlsplit("https://" + hosts[0])
            hostname = (supplied.hostname or "").lower().rstrip(".")
            candidates = [origin for origin in mapping if urlsplit(origin).hostname == hostname]
        except ValueError:
            raise web.HTTPBadRequest(text="Invalid Host header") from None
        if not candidates:
            return await handler(request)
        try:
            origin = _origin("https://" + hosts[0]) if hosts[0] == hosts[0].lower() and not hosts[0].endswith(".") else None
        except ProtocolError:
            raise web.HTTPBadRequest(text="Use the configured application origin") from None
        host_id = mapping.get(origin)
        if host_id is None:
            raise web.HTTPBadRequest(text="Use the configured application origin")
        if not _secure_ingress(request):
            raise web.HTTPForbidden(text="Application ingress requires TLS")
        try:
            if request.path == RESERVED_PREFIX + "launch":
                return await sessions.launch(request, host_id, origin)
            if request.path == RESERVED_PREFIX + "logout":
                if request.method != "POST" or request.headers.get("Origin") != origin:
                    raise ProtocolError("application logout requires its own origin POST")
                entry = await sessions.entry(request, host_id, origin)
                # Do not close the transport before delivering this response.
                await sessions.close(entry["key"], exit_code=0)
                response = web.Response(status=303, headers={"Location": runtime.config["dashboard"]["public_url"].rstrip("/") + "/workspace", "Cache-Control": "no-store"})
                response.del_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="Lax")
                return response
            if request.path.startswith(RESERVED_PREFIX):
                raise web.HTTPNotFound()
            return await proxy_application(request, sessions, host_id, origin)
        except web.HTTPException:
            raise
        except ProtocolError as exc:
            return web.Response(status=403, text="Application request denied. " + str(exc),
                headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"})
        except (asyncio.TimeoutError, OSError):
            return web.Response(status=502, text="Application upstream is unavailable", headers={"Cache-Control": "no-store"})
        except Exception:
            return web.Response(status=403, text="Application authorization or upstream request failed", headers={"Cache-Control": "no-store"})
    app.middlewares.insert(0, application_origin)
    return sessions
