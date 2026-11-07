"""Protocol-terminating SSH and WebSocket SSH ingress.

Ingress only accepts one-use tickets minted by the authenticated control API.
Human identity, target address and remote Unix identity always come from the
runtime authorization context. No interactive Unix login is needed here.
"""

import asyncio
from contextlib import asynccontextmanager
import ipaddress
import json
import logging
import os
import re
import shlex
import signal
import ssl
import threading
from urllib.parse import urlsplit

import asyncssh
from aiohttp import web


LOG = logging.getLogger(__name__)
CHUNK_SIZE = 32768
MAX_MESSAGE = 65536
RUNTIME_KEY = web.AppKey("isolate_runtime", object)
WEB_CONNECTIONS_KEY = web.AppKey("isolate_web_connections", set)


class GatewayError(ValueError):
    pass


def _options(config):
    return config.get("gateway", {})


def _profile(context, config):
    """Do not turn the restricted command-input profile into a full shell."""
    audit = config.get("command_audit", {})
    if audit.get("enabled") and audit.get("mode") == "managed":
        raise GatewayError("This resource requires the managed command console")
    if context.get("proxy"):
        # Chained gateways require independent authorization of each hop.
        raise GatewayError("Proxy hops are not enabled for gateway SSH")
    if context.get("decision", {}).get("sudo_mode", "none") not in ("none", "sudo-i"):
        raise GatewayError("Unsupported remote privilege profile")


def _terminal(value):
    value = value or "xterm-256color"
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", value):
        raise GatewayError("Invalid terminal type")
    return value


def _size(cols, rows):
    if isinstance(cols, bool) or isinstance(rows, bool):
        raise GatewayError("Invalid terminal size")
    try:
        cols, rows = int(cols), int(rows)
    except (TypeError, ValueError) as exc:
        raise GatewayError("Invalid terminal size") from exc
    if not 1 <= cols <= 1000 or not 1 <= rows <= 1000:
        raise GatewayError("Invalid terminal size")
    return cols, rows


def _command(context, requested):
    if requested is not None:
        if not isinstance(requested, str) or "\x00" in requested or len(requested) > 65536:
            raise GatewayError("Invalid SSH command")
    if context["decision"].get("sudo_mode", "none") == "sudo-i":
        return "sudo -n -i" if not requested else "sudo -n -i -- /bin/sh -c " + shlex.quote(requested)
    return requested


def allowed_origin(request, config):
    """Compare exact configured origins; never trust client forwarding headers."""
    origin = request.headers.get("Origin", "")
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if parsed.scheme not in ("https", "http") or not parsed.netloc or parsed.username or parsed.password:
        return False
    if parsed.path or parsed.query or parsed.fragment:
        return False
    allowed = _options(config).get("allowed_origins") or [config.get("dashboard", {}).get("public_url", "")]
    return origin in allowed


async def _call(runtime, name, *args, **kwargs):
    return await asyncio.to_thread(getattr(runtime, name), *args, **kwargs)


async def _watch(runtime, context, config):
    interval = max(0.2, min(30.0, float(_options(config).get("recheck_interval", 2))))
    while True:
        await asyncio.sleep(interval)
        await _call(runtime, "recheck", context)


async def _cancel(tasks):
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _finish(runtime, context, exit_code):
    try:
        await _call(runtime, "finish", context, exit_code=exit_code)
    except Exception:
        # Cleanup must still close channels if Redis/audit storage is unavailable.
        LOG.error("Could not persist the final gateway session state")


async def _prepare(runtime, context, disconnected):
    """Cancel a blocking approval wait before a disconnected client can connect.

    Runtime's policy recheck observes this event. We wait for the worker thread
    to relinquish its lease before finalizing the ingress context.
    """
    context["_cancel_event"] = threading.Event()
    worker = asyncio.create_task(_call(runtime, "prepare", context))

    def consume_result(task):
        if not task.cancelled():
            task.exception()

    worker.add_done_callback(consume_result)
    closed = asyncio.create_task(disconnected)
    try:
        done, _ = await asyncio.wait([worker, closed], return_when=asyncio.FIRST_COMPLETED)
        if closed in done:
            context["_cancel_event"].set()
            await closed
            raise GatewayError("Client disconnected before session authorization completed")
        await worker
    except BaseException:
        context["_cancel_event"].set()
        # A shutdown may cancel this handler again after the transport already
        # disconnected. Keep waiting for the bounded runtime operation to see
        # cancellation and release its lease; do not abandon its thread/result.
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not worker.cancelled():
            worker.exception()
        raise
    finally:
        await _cancel([closed])


@asynccontextmanager
async def upstream(runtime, context):
    """Keep generated credentials alive until the target SSH connection closes."""
    from isolate_credentials import ssh_credentials

    config = runtime.config
    _profile(context, config)
    host = dict(context["host"], remote_user=context["decision"]["remote_user"])
    credentials = ssh_credentials(config, host, context["identity"], context["connection_id"])
    # Secret fetches/signing and key generation may block, so run off-loop.
    entering = asyncio.create_task(asyncio.to_thread(credentials.__enter__))
    try:
        options = await asyncio.shield(entering)
    except asyncio.CancelledError:
        try:
            await entering
        finally:
            await asyncio.to_thread(credentials.__exit__, None, None, None)
        raise
    connection = None
    try:
        options = dict(options)
        known_hosts = options.get("known_hosts") or _options(config).get("known_hosts")
        if not known_hosts:
            raise GatewayError("A trusted upstream known_hosts configuration is required")
        address = str(ipaddress.ip_address(host["server_ip"]))
        port = int(host.get("server_port") or 22)
        username = context["decision"]["remote_user"]
        # Read only IdentityFile/certificate credentials from the compatibility
        # config. HostName/ProxyCommand/ProxyJump there must not change policy's
        # selected route, and StrictHostKeyChecking cannot disable verification.
        if options.get("config") and "client_keys" not in options:
            parsed = await asyncio.to_thread(
                asyncssh.SSHClientConnectionOptions, config=options["config"],
                host=address, port=port, username=username, known_hosts=known_hosts,
                agent_path=None,
            )
            options["client_keys"] = parsed.client_keys
        options = {name: value for name, value in options.items()
                   if name in ("client_keys", "client_certs", "passphrase")}
        options.update(known_hosts=known_hosts, config=[])
        connection = await asyncssh.connect(
            address, port=port, username=username,
            agent_path=None,
            agent_forwarding=False,
            connect_timeout=max(1, min(60, float(_options(config).get("connect_timeout", 10)))),
            login_timeout=max(1, min(60, float(_options(config).get("connect_timeout", 10)))),
            **options,
        )
        yield connection
    finally:
        try:
            if connection is not None:
                connection.close()
                await asyncio.wait_for(connection.wait_closed(), 5)
        finally:
            await asyncio.to_thread(credentials.__exit__, None, None, None)


async def _copy_output(runtime, context, reader, writer):
    while True:
        data = await reader.read(CHUNK_SIZE)
        if not data:
            return
        await _call(runtime, "record_output", context, data)
        writer.write(data)
        await writer.drain()


async def _copy_native_input(reader, process):
    while True:
        try:
            data = await reader.read(CHUNK_SIZE)
        except asyncssh.TerminalSizeChanged as exc:
            process.change_terminal_size(*exc.term_size)
            continue
        except asyncssh.SignalReceived as exc:
            process.send_signal(exc.signal)
            continue
        except asyncssh.BreakReceived:
            process.send_break(500)
            continue
        if not data:
            process.stdin.write_eof()
            return
        process.stdin.write(data)
        await process.stdin.drain()


class _TicketSSHServer(asyncssh.SSHServer):
    def __init__(self, runtime, state):
        self.runtime = runtime
        self.state = state
        self.connection = None
        self.context = None
        self.channel_started = False
        self.auth_attempts = 0

    def connection_made(self, connection):
        self.connection = connection
        self.state.add(connection)
        connection.set_extra_info(isolate_server=self)
        maximum = max(1, int(_options(self.runtime.config).get("max_connections", 100)))
        if len(self.state) > maximum:
            connection.close()

    def connection_lost(self, exc):
        self.state.discard(self.connection)
        if self.context is not None and not self.channel_started:
            asyncio.create_task(_finish(self.runtime, self.context, 255))

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return False

    def kbdint_auth_supported(self):
        return False

    async def validate_password(self, username, password):
        self.auth_attempts += 1
        if self.auth_attempts > 3:
            self.connection.close()
            return False
        if self.context is not None or not isinstance(password, str) or len(password) > 512:
            return False
        try:
            peer = self.connection.get_extra_info("peername")
            context = await _call(self.runtime, "consume_ticket", password, protocol="ssh", source_ip=peer[0])
            self.context = context
            if str(context["host"]["server_id"]) != username:
                raise GatewayError("SSH username must be the authorized resource ID")
            _profile(context, self.runtime.config)
            return True
        except Exception:
            # Never disclose or log credentials, tokens, or a detailed auth error.
            return False

    def connection_requested(self, *args):
        return False

    def server_requested(self, *args):
        return False

    def unix_connection_requested(self, *args):
        return False

    def unix_server_requested(self, *args):
        return False


async def native_process(process, runtime):
    server = process.get_extra_info("isolate_server")
    if server is None or server.context is None or server.channel_started or process.subsystem:
        process.stderr.write(b"Session refused\r\n")
        process.exit(126)
        return
    server.channel_started = True
    context = server.context
    exit_code = 255
    tasks = []
    remote = None
    try:
        _profile(context, runtime.config)
        await _prepare(runtime, context, process.wait_closed())
        await _call(runtime, "start", context)
        async with upstream(runtime, context) as connection:
            term_type = process.term_type
            term_size = process.term_size[:2] if term_type else (80, 24)
            if term_type:
                term_type = _terminal(term_type)
                term_size = _size(*term_size)
            remote = await connection.create_process(
                _command(context, process.command), term_type=term_type,
                term_size=term_size, encoding=None, env={},
            )
            input_task = asyncio.create_task(_copy_native_input(process.stdin, remote))
            tasks.append(input_task)

            async def transfer():
                await asyncio.gather(
                    _copy_output(runtime, context, remote.stdout, process.stdout),
                    _copy_output(runtime, context, remote.stderr, process.stderr),
                )
                result = await remote.wait()
                return result.exit_status if result.exit_status is not None else 255

            output = asyncio.create_task(transfer())
            watch = asyncio.create_task(_watch(runtime, context, runtime.config))
            closed = asyncio.create_task(process.wait_closed())
            tasks.extend([output, watch, closed])
            done, _ = await asyncio.wait([output, watch, closed], return_when=asyncio.FIRST_COMPLETED)
            for item in done:
                result = await item
                if item is output:
                    exit_code = result
    except asyncio.CancelledError:
        raise
    except Exception:
        try:
            process.stderr.write(b"Isolate session closed: authorization or upstream connection failed\r\n")
        except (OSError, asyncssh.Error):
            pass
    finally:
        await _cancel(tasks)
        if remote:
            remote.close()
        try:
            await _finish(runtime, context, exit_code)
        finally:
            process.exit(exit_code)


async def create_native_listener(runtime, host=None, port=None):
    options = _options(runtime.config)
    key = options.get("host_key_file")
    if not key or not os.path.isfile(key):
        raise GatewayError("gateway.host_key_file must name a provisioned SSH host key")
    state = set()
    handlers = set()

    async def handle(process):
        task = asyncio.current_task()
        handlers.add(task)
        try:
            await native_process(process, runtime)
        finally:
            handlers.discard(task)

    listener = await asyncssh.create_server(
        lambda: _TicketSSHServer(runtime, state),
        host if host is not None else options.get("listen_host", "127.0.0.1"),
        port if port is not None else int(options.get("ssh_port", 2222)),
        server_host_keys=[key], process_factory=handle,
        encoding=None, login_timeout=15, config=[], line_editor=False, line_echo=False,
        allow_pty=True, agent_forwarding=False, x11_forwarding=False,
        allow_scp=False, window=262144, max_pktsize=CHUNK_SIZE,
    )
    listener.isolate_connections = state
    listener.isolate_tasks = handlers
    return listener


async def websocket_ssh(request):
    from aiohttp import WSMsgType, web

    runtime = request.app[RUNTIME_KEY]
    if not allowed_origin(request, runtime.config):
        raise web.HTTPForbidden(text="Origin is not permitted")
    active = request.app[WEB_CONNECTIONS_KEY]
    maximum = max(1, int(_options(runtime.config).get("max_connections", 100)))
    if len(active) >= maximum:
        raise web.HTTPServiceUnavailable(text="Gateway connection limit reached")
    ws = web.WebSocketResponse(max_msg_size=MAX_MESSAGE, heartbeat=30, compress=False)
    active.add(ws)
    context, remote = None, None
    tasks = []
    exit_code = 255
    try:
        await ws.prepare(request)
        hello = await ws.receive_json(timeout=10)
        if not isinstance(hello, dict) or set(hello) - {"ticket", "cols", "rows", "term"}:
            raise GatewayError("Invalid Web SSH handshake")
        ticket = hello.get("ticket")
        if not isinstance(ticket, str) or not ticket or len(ticket) > 512:
            raise GatewayError("A connection ticket is required")
        term = _terminal(hello.get("term"))
        cols, rows = _size(hello.get("cols", 80), hello.get("rows", 24))
        context = await _call(runtime, "consume_ticket", ticket, protocol="webssh", source_ip=request.remote)
        _profile(context, runtime.config)
        await ws.send_json({"type": "status", "state": "waiting"})

        async def before_ready():
            message = await ws.receive()
            if message.type not in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                raise GatewayError("Terminal input is not accepted before authorization")

        await _prepare(runtime, context, before_ready())
        await _call(runtime, "start", context)
        async with upstream(runtime, context) as connection:
            remote = await connection.create_process(
                _command(context, None), term_type=term, term_size=(cols, rows), encoding=None, env={},
            )
            await ws.send_json({"type": "status", "state": "connected"})

            async def incoming():
                async for message in ws:
                    if message.type != WSMsgType.TEXT:
                        break
                    try:
                        value = json.loads(message.data)
                    except (ValueError, TypeError) as exc:
                        raise GatewayError("Invalid terminal message") from exc
                    if not isinstance(value, dict):
                        raise GatewayError("Invalid terminal message")
                    if value.get("type") == "input" and set(value) == {"type", "data"}:
                        data = value["data"]
                        if not isinstance(data, str) or len(data.encode("utf-8")) > MAX_MESSAGE:
                            raise GatewayError("Invalid terminal input")
                        remote.stdin.write(data.encode("utf-8"))
                        await remote.stdin.drain()
                    elif value.get("type") == "resize" and set(value) == {"type", "cols", "rows"}:
                        remote.change_terminal_size(*_size(value["cols"], value["rows"]))
                    else:
                        raise GatewayError("Invalid terminal message")
                remote.close()

            async def outgoing(reader):
                while True:
                    data = await reader.read(CHUNK_SIZE)
                    if not data:
                        return
                    await _call(runtime, "record_output", context, data)
                    await ws.send_bytes(data)

            async def transfer():
                await asyncio.gather(outgoing(remote.stdout), outgoing(remote.stderr))
                result = await remote.wait()
                return result.exit_status if result.exit_status is not None else 255

            sender = asyncio.create_task(transfer())
            receiver = asyncio.create_task(incoming())
            watch = asyncio.create_task(_watch(runtime, context, runtime.config))
            tasks.extend([sender, receiver, watch])
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                result = await task
                if task is sender:
                    exit_code = result
            if not ws.closed:
                await ws.send_json({"type": "exit", "code": exit_code})
    except asyncio.CancelledError:
        raise
    except Exception:
        if not ws.closed and ws.prepared:
            await ws.send_json({"type": "error", "message": "Authorization or upstream SSH connection failed"})
    finally:
        await _cancel(tasks)
        if remote:
            remote.close()
        if context:
            await _finish(runtime, context, exit_code)
        await ws.close()
        active.discard(ws)
    return ws


def create_web_app(runtime):
    from aiohttp import web

    app = web.Application(client_max_size=MAX_MESSAGE)
    app[RUNTIME_KEY] = runtime
    app[WEB_CONNECTIONS_KEY] = set()
    app.router.add_get("/ssh", websocket_ssh)

    async def health(request):
        ready = not runtime.config.get("cluster", {}).get("draining", False)
        redis = getattr(runtime, "redis", None)
        if redis is not None:
            from isolate_cluster import node_ready
            try:
                ready = ready and bool(await asyncio.to_thread(redis.ping))
                ready = ready and bool(await asyncio.to_thread(node_ready, redis, runtime.config))
            except Exception:
                ready = False
        return web.json_response({"service": "isolate-gateway", "status": "ready" if ready else "unavailable"},
                                 status=200 if ready else 503)

    async def shutdown(application):
        await asyncio.gather(*[ws.close(code=1001, message=b"Service restarting")
                               for ws in tuple(application[WEB_CONNECTIONS_KEY])])

    app.router.add_get("/healthz", health)
    app.on_shutdown.append(shutdown)
    if runtime.config.get("protocols", {}).get("enabled"):
        from isolate_protocols import register_protocol_routes
        register_protocol_routes(app, runtime)
    return app


def web_ssl_context(config):
    options = _options(config)
    cert, key = options.get("tls_cert_file"), options.get("tls_key_file")
    if bool(cert) != bool(key):
        raise GatewayError("Both Web gateway TLS certificate and key are required")
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        return context
    host = options.get("web_host", "127.0.0.1")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        raise GatewayError("An externally bound Web gateway requires TLS")
    return None


async def serve(runtime):
    """Run enabled ingress listeners and drain resources on service shutdown."""
    from aiohttp import web

    options = _options(runtime.config)
    if not options.get("enabled"):
        raise GatewayError("Gateway is disabled")
    listener, runner = None, None
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    handlers = []
    try:
        if options.get("ssh_enabled", True):
            listener = await create_native_listener(runtime)
        if options.get("web_enabled", True):
            runner = web.AppRunner(create_web_app(runtime), access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, options.get("web_host", "127.0.0.1"),
                               int(options.get("web_port", 8092)), ssl_context=web_ssl_context(runtime.config))
            await site.start()
        if listener is None and runner is None:
            raise GatewayError("At least one gateway ingress must be enabled")
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(signum, stopped.set)
                handlers.append(signum)
            except (NotImplementedError, RuntimeError):
                pass
        await stopped.wait()
    finally:
        for signum in handlers:
            loop.remove_signal_handler(signum)
        if listener:
            listener.close()
            connections = tuple(listener.isolate_connections)
            for connection in connections:
                connection.close()
            await asyncio.gather(*[connection.wait_closed() for connection in connections], return_exceptions=True)
            handlers = tuple(listener.isolate_tasks)
            if handlers:
                try:
                    await asyncio.wait_for(asyncio.gather(*handlers, return_exceptions=True), 15)
                except asyncio.TimeoutError:
                    await _cancel(handlers)
            await listener.wait_closed()
        if runner:
            await runner.cleanup()
