"""Protocol-terminating SSH and WebSocket SSH ingress.

Ingress only accepts one-use tickets minted by the authenticated control API.
Human identity, target address and remote Unix identity always come from the
runtime authorization context. No interactive Unix login is needed here.
"""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
import ipaddress
import json
import logging
import os
import re
import shlex
import signal
import ssl
import threading
import time
import uuid
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
    if context.get("proxy") and not context.get("proxy_chain"):
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
async def _upstream_hop(runtime, context, tunnel=None):
    """Keep credentials alive until this strictly pinned SSH hop closes."""
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
            tunnel=tunnel,
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


@asynccontextmanager
async def upstream(runtime, context):
    """Open only the independently authorized, revision-bound inventory hops."""
    _profile(context, runtime.config)
    chain = list(context.get("proxy_chain") or [])
    if len(chain) > 8:
        raise GatewayError("SSH proxy chain exceeds the supported limit")
    async with AsyncExitStack() as stack:
        connection = None
        for hop in chain + [context]:
            connection = await stack.enter_async_context(_upstream_hop(runtime, hop, tunnel=connection))
        yield connection


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


def _ssh_features(config):
    return _options(config).get("ssh_features") or {}


class _NativeProcess(asyncssh.SSHServerProcess):
    """Reserve channels before shell/subsystem negotiation, including idle ones."""

    def __init__(self, owner, token):
        self.owner = owner
        self.token = token
        self.active_handler = False
        features = _ssh_features(owner.runtime.config)
        factory = self._sftp if features.get("sftp") or features.get("scp") else None
        super().__init__(owner.handle_process, factory, 3, features.get("scp") is True)

    async def _sftp(self, channel):
        from isolate_sftp_proxy import ProxySFTPServer
        self.active_handler = True
        try:
            if self.owner.context["decision"].get("sudo_mode", "none") != "none":
                raise GatewayError("File transfer requires a no-sudo target policy")
            await self.owner.activate(self.token, "sftp")
            connection = await self.owner.ensure_started()
            client = await connection.start_sftp_client(path_encoding=None, sftp_version=3)
            await self.owner.event("sftp_channel_start", channel_id=self.token,
                                   transfer="scp" if self.command else "sftp")
            return ProxySFTPServer(channel, self.owner, self.token, client)
        except BaseException:
            await self.owner.release(self.token)
            raise

    def subsystem_requested(self, subsystem):
        return subsystem == "sftp" and _ssh_features(self.owner.runtime.config).get("sftp") is True

    def exec_requested(self, command):
        if command.startswith("scp ") and _ssh_features(self.owner.runtime.config).get("scp") is not True:
            return False
        return super().exec_requested(command)

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if not self.active_handler:
            self.owner.spawn(self.owner.release(self.token, 255))


class _ForwardSession(asyncssh.SSHTCPSession):
    """Bounded, backpressured streams through the already-authorized target."""

    def __init__(self, owner, token, reader, writer):
        self.owner, self.token = owner, token
        self.reader, self.writer = reader, writer
        self.channel, self.task = None, None
        self.queue = asyncio.Queue(maxsize=16)
        self.writable = asyncio.Event()
        self.writable.set()
        self.counts = {"sent_bytes": 0, "received_bytes": 0}

    def connection_made(self, channel):
        self.channel = channel
        self.task = self.owner.spawn(self.run())

    def data_received(self, data, datatype):
        self.channel.pause_reading()
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            self.channel.close()

    def eof_received(self):
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            self.channel.close()
        return True

    def pause_writing(self):
        self.writable.clear()

    def resume_writing(self):
        self.writable.set()

    def connection_lost(self, exc):
        self.writer.close()
        if self.task and not self.task.done():
            self.task.cancel()

    async def run(self):
        async def incoming():
            while True:
                data = await self.queue.get()
                if data is None:
                    self.writer.write_eof()
                    return
                self.writer.write(data)
                self.counts["sent_bytes"] += len(data)
                await self.writer.drain()
                self.channel.resume_reading()
        async def outgoing():
            while True:
                data = await self.reader.read(CHUNK_SIZE)
                if not data:
                    self.channel.write_eof()
                    return
                self.channel.write(data)
                self.counts["received_bytes"] += len(data)
                await self.writable.wait()
        tasks = [asyncio.create_task(incoming()), asyncio.create_task(outgoing())]
        try:
            await asyncio.gather(*tasks)
        finally:
            await _cancel(tasks)
            self.writer.close()
            self.channel.close()
            try:
                await self.owner.event("ssh_forward_end", channel_id=self.token, **self.counts)
            finally:
                await self.owner.release(self.token)


class _TicketSSHServer(asyncssh.SSHServer):
    def __init__(self, runtime, state, handlers=None):
        self.runtime = runtime
        self.state = state
        self.handlers = handlers if handlers is not None else set()
        self.connection = None
        self.context = None
        self.channel_started = False
        self.auth_attempts = 0
        self.channels = {}
        self._channels_empty = asyncio.Event()
        self._channels_empty.set()
        self._start_lock = asyncio.Lock()
        self._upstream_manager = None
        self._upstream = None
        self._watcher = None
        self._auth_expiry = None
        self._shutdown_task = None
        self._finalized = False
        self._startup_failed = False
        self.exit_code = 0

    def spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.handlers.add(task)
        def finished(item):
            self.handlers.discard(item)
            if not item.cancelled():
                item.exception()
        task.add_done_callback(finished)
        return task

    def connection_made(self, connection):
        self.connection = connection
        self.state.add(connection)
        connection.set_extra_info(isolate_server=self)
        maximum = max(1, int(_options(self.runtime.config).get("max_connections", 100)))
        if len(self.state) > maximum:
            connection.close()

    def connection_lost(self, exc):
        self.state.discard(self.connection)
        if exc is not None or self.channels:
            self.exit_code = 255
        if self._shutdown_task is None:
            self._shutdown_task = self.spawn(self.shutdown())

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return False

    def kbdint_auth_supported(self):
        return _options(self.runtime.config).get("browser_auth", {}).get("enabled") is True

    async def get_kbdint_challenge(self, username, lang, submethods):
        from isolate_ssh_browser import ssh_challenge
        return await ssh_challenge(self, username)

    async def validate_kbdint_response(self, username, responses):
        from isolate_ssh_browser import ssh_response
        return await ssh_response(self, username, responses)

    async def set_context(self, context, username):
        if self.context is not None or str(context["host"]["server_id"]) != username:
            raise GatewayError("SSH username must be the authorized resource ID")
        _profile(context, self.runtime.config)
        self.context = context
        if type(context.get("deadline")) in (int, float):
            self._auth_expiry = self.spawn(self.expire_authentication())
        return True

    async def expire_authentication(self):
        # An authenticated ControlMaster/-N transport may not open a channel at
        # all. Bound its lifetime even before prepare starts the active watch.
        await asyncio.sleep(max(0, self.context["deadline"] - time.time()))
        self.exit_code = 255
        self.connection.close()

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
            return await self.set_context(context, username)
        except Exception:
            # Never disclose or log credentials, tokens, or a detailed auth error.
            return False

    def reserve(self):
        features = _ssh_features(self.runtime.config)
        if self.context is None or self._finalized or self.connection.is_closed():
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED, "Session is unavailable")
        if features.get("multiple_channels") is not True and self.channel_started:
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED, "Additional channels are disabled")
        maximum = max(1, min(32, int(features.get("max_channels", 8))))
        if len(self.channels) >= maximum:
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_RESOURCE_SHORTAGE, "Channel limit reached")
        token = uuid.uuid4().hex
        self.channels[token] = {"action": "pending"}
        self._channels_empty.clear()
        self.channel_started = True
        return token

    def session_requested(self):
        return _NativeProcess(self, self.reserve())

    async def authorize(self, action, destination=None):
        if self.context is None or self._finalized:
            raise GatewayError("Session is unavailable")
        if hasattr(self.runtime, "authorize_channel"):
            return await _call(self.runtime, "authorize_channel", self.context, action, destination=destination)
        if action != "ssh":
            raise GatewayError("Channel authorization is unavailable")
        await _call(self.runtime, "recheck", self.context)
        return None

    async def activate(self, token, action, destination=None):
        if token not in self.channels:
            raise GatewayError("Channel is no longer available")
        pinned = await self.authorize(action, destination)
        self.channels[token].update(action=action, destination=destination, pinned=pinned)
        return pinned

    async def event(self, event, **fields):
        if hasattr(self.runtime, "channel_event"):
            await _call(self.runtime, "channel_event", self.context, event, **fields)
        elif any(value.get("action") in ("sftp", "forward") for value in self.channels.values()):
            raise GatewayError("Channel auditing is unavailable")

    async def ensure_started(self):
        async with self._start_lock:
            if self._finalized or self._startup_failed:
                raise GatewayError("Session is unavailable")
            if self._upstream is None:
                try:
                    await _prepare(self.runtime, self.context, self.connection.wait_closed())
                    await _call(self.runtime, "start", self.context)
                    self._watcher = self.spawn(self.watch_channels())
                    self._upstream_manager = upstream(self.runtime, self.context)
                    self._upstream = await self._upstream_manager.__aenter__()
                except BaseException:
                    self.exit_code = 255
                    self._startup_failed = True
                    raise
            return self._upstream

    async def watch_channels(self):
        interval = max(0.2, min(30.0, float(_options(self.runtime.config).get("recheck_interval", 2))))
        try:
            while True:
                await asyncio.sleep(interval)
                if hasattr(self.runtime, "recheck_channels"):
                    snapshot = {key: dict(value) for key, value in self.channels.items()}
                    checked = await _call(self.runtime, "recheck_channels", self.context, snapshot)
                    if any(checked[key] != snapshot[key].get("pinned") for key in checked):
                        raise GatewayError("Channel route or authorization changed")
                    continue
                await _call(self.runtime, "recheck", self.context)
                for channel in tuple(self.channels.values()):
                    if channel["action"] in ("sftp", "forward"):
                        fresh = await self.authorize(channel["action"], channel.get("destination"))
                        if fresh != channel.get("pinned"):
                            raise GatewayError("Channel route or authorization changed")
        except asyncio.CancelledError:
            raise
        except Exception:
            self.exit_code = 255
            self.connection.close()

    async def release(self, token, exit_code=None):
        removed = self.channels.pop(token, None)
        if removed is None:
            return
        if exit_code:
            self.exit_code = exit_code
        if not self.channels:
            self._channels_empty.set()
        if _ssh_features(self.runtime.config).get("multiple_channels") is not True:
            await self.shutdown()

    async def shutdown(self):
        if self._finalized:
            return
        self._finalized = True
        if self.context is not None:
            self.context.setdefault("_cancel_event", threading.Event()).set()
        if self._watcher and self._watcher is not asyncio.current_task():
            await _cancel([self._watcher])
        if self._auth_expiry and self._auth_expiry is not asyncio.current_task():
            await _cancel([self._auth_expiry])
        async with self._start_lock:
            if self._upstream_manager and self._upstream is not None:
                try:
                    await self._upstream_manager.__aexit__(None, None, None)
                except Exception:
                    LOG.error("Could not close the upstream SSH context")
            self._upstream = None
            if self.channels:
                try:
                    await asyncio.wait_for(self._channels_empty.wait(), 5)
                except asyncio.TimeoutError:
                    self.exit_code = 255
            if self.context is not None:
                await _finish(self.runtime, self.context, self.exit_code)

    async def handle_process(self, process):
        process.active_handler = True
        task = asyncio.current_task()
        self.handlers.add(task)
        try:
            await native_process(process, self.runtime)
        finally:
            self.handlers.discard(task)

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        if _ssh_features(self.runtime.config).get("forwarding") is not True:
            return False
        return self.open_forward(dest_host, dest_port)

    async def open_forward(self, dest_host, dest_port):
        token, writer = self.reserve(), None
        try:
            destination = {"host": dest_host, "port": dest_port}
            pinned = await self.activate(token, "forward", destination)
            if (not isinstance(pinned, dict) or type(pinned.get("port")) is not int
                    or not 1 <= pinned["port"] <= 65535):
                raise GatewayError("Forwarding requires a pinned target")
            address = str(ipaddress.ip_address(pinned["host"]))
            connection = await self.ensure_started()
            await self.event("ssh_forward_start", channel_id=token, destination_host=address, destination_port=pinned["port"])
            reader, writer = await connection.open_connection(address, pinned["port"], encoding=None)
        except BaseException:
            if writer:
                writer.close()
            await self.release(token)
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED, "Forwarding is not permitted") from None

        return _ForwardSession(self, token, reader, writer)

    def server_requested(self, *args):
        return False

    def unix_connection_requested(self, *args):
        return False

    def unix_server_requested(self, *args):
        return False


async def native_process(process, runtime):
    server = process.get_extra_info("isolate_server")
    token = getattr(process, "token", None)
    if server is None or server.context is None or token not in server.channels or process.subsystem:
        process.stderr.write(b"Session refused\r\n")
        process.exit(126)
        return
    context, exit_code, tasks, remote = server.context, 255, [], None
    try:
        _profile(context, runtime.config)
        await server.activate(token, "ssh")
        connection = await server.ensure_started()
        await server.event("ssh_channel_start", channel_id=token, channel_type="exec" if process.command else "shell")
        term_type = process.term_type
        term_size = process.term_size[:2] if term_type else (80, 24)
        if term_type:
            term_type = _terminal(term_type)
            term_size = _size(*term_size)
        remote = await connection.create_process(
            _command(context, process.command), term_type=term_type,
            term_size=term_size, encoding=None, env={},
        )
        tasks.append(asyncio.create_task(_copy_native_input(process.stdin, remote)))

        async def transfer():
            await asyncio.gather(
                _copy_output(runtime, context, remote.stdout, process.stdout),
                _copy_output(runtime, context, remote.stderr, process.stderr),
            )
            result = await remote.wait()
            return result.exit_status if result.exit_status is not None else 255

        output = asyncio.create_task(transfer())
        closed = asyncio.create_task(process.wait_closed())
        tasks.extend([output, closed])
        done, _ = await asyncio.wait([output, closed], return_when=asyncio.FIRST_COMPLETED)
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
            await server.event("ssh_channel_end", channel_id=token, exit_code=exit_code)
        finally:
            await server.release(token, exit_code)
            process.exit(exit_code)


async def create_native_listener(runtime, host=None, port=None):
    options = _options(runtime.config)
    key = options.get("host_key_file")
    if not key or not os.path.isfile(key):
        raise GatewayError("gateway.host_key_file must name a provisioned SSH host key")
    state = set()
    handlers = set()

    browser = options.get("browser_auth") or {}
    login_timeout = max(15, min(610, int(browser.get("timeout_seconds", 120)) + 10)) if browser.get("enabled") else 15
    listener = await asyncssh.create_server(
        lambda: _TicketSSHServer(runtime, state, handlers),
        host if host is not None else options.get("listen_host", "127.0.0.1"),
        port if port is not None else int(options.get("ssh_port", 2222)),
        server_host_keys=[key],
        encoding=None, login_timeout=login_timeout, config=[], line_editor=False, line_echo=False,
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
    except Exception as exc:
        LOG.warning("Web SSH connection failed: %s", type(exc).__name__)
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
