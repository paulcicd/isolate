#!/usr/bin/env python3
"""Local database tunnel and kubectl credential helper for Isolate.

Secrets are read from the existing private login cache, never command-line
arguments. Every accepted local TCP connection obtains a fresh one-time ticket.
"""

import argparse
import asyncio
import contextlib
import datetime
import ipaddress
import json
import os
import ssl
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shared")))
from isolate_identity import IdentityError, _load_token_cache


def identity_token(path=None):
    cache = _load_token_cache(path)
    token = cache.get("id_token")
    if not isinstance(token, str) or not token:
        raise IdentityError("run isolate login before using a protocol proxy")
    return token, cache


def _safe_endpoint(value, scheme, insecure_loopback=False):
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("endpoint must not contain credentials, query or fragment")
    if parsed.scheme != scheme:
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        if not (insecure_loopback and loopback and parsed.scheme == {"https": "http", "wss": "ws"}[scheme]):
            raise ValueError("{} endpoint is required".format(scheme))
    return value.rstrip("/")


async def database_tunnel(args):
    import aiohttp
    api_url = _safe_endpoint(args.api_url, "https", args.allow_loopback_http)
    gateway_url = _safe_endpoint(args.gateway_url, "wss", args.allow_loopback_http)
    tls = ssl.create_default_context(cafile=args.ca_file)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    active = set()

    async def connection(reader, writer):
        current = asyncio.current_task()
        active.add(current)
        try:
            token, _ = identity_token(args.identity_file)
            timeout = aiohttp.ClientTimeout(total=None, connect=10, sock_connect=10)
            async with aiohttp.ClientSession(timeout=timeout, connector=aiohttp.TCPConnector(ssl=tls),
                    trust_env=False, cookie_jar=aiohttp.DummyCookieJar()) as client:
                async with client.post(api_url + "/api/v1/connections", headers={"Authorization": "Bearer " + token},
                        json={"host_id": args.host_id, "protocol": args.protocol}, timeout=30,
                        allow_redirects=False) as response:
                    if response.status != 200 and response.status != 201:
                        raise RuntimeError("Isolate did not authorize a database connection")
                    issued = await response.json()
                # Gateway URL is operator-supplied: don't trust a URL from a response
                # to send a one-time credential to an unexpected origin.
                async with client.ws_connect(gateway_url + "/protocols/database", max_msg_size=65536,
                        heartbeat=20) as websocket:
                    await websocket.send_json({"ticket": issued["ticket"], "protocol": args.protocol})
                    first = await websocket.receive_json(timeout=300)
                    if first.get("type") != "ready" or first.get("audit_profile") != "connection":
                        raise RuntimeError("database transport was denied")

                    async def upstream():
                        while True:
                            data = await reader.read(65536)
                            if not data:
                                return
                            await websocket.send_bytes(data)

                    async def downstream():
                        async for message in websocket:
                            if message.type == aiohttp.WSMsgType.BINARY:
                                writer.write(message.data)
                                await writer.drain()
                            elif message.type == aiohttp.WSMsgType.TEXT:
                                raise RuntimeError("database transport was closed")
                    tasks = (asyncio.create_task(upstream()), asyncio.create_task(downstream()))
                    try:
                        finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                        for task in finished:
                            task.result()
                    finally:
                        for task in tasks:
                            if not task.done():
                                task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
        except (Exception, asyncio.CancelledError):
            # Never print responses, ticket strings, bearer tokens or DB bytes.
            print("Isolate database connection ended or was denied", file=sys.stderr)
        finally:
            active.discard(current)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    server = await asyncio.start_server(connection, "127.0.0.1", args.listen_port)
    port = server.sockets[0].getsockname()[1]
    print("Isolate {} tunnel listening on 127.0.0.1:{}".format(args.protocol, port), flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        for task in list(active):
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)


def credential(args):
    token, cache = identity_token(args.identity_file)
    status = {"token": token}
    if cache.get("expires_at"):
        expiration = datetime.datetime.fromtimestamp(int(cache["expires_at"]), datetime.timezone.utc)
        status["expirationTimestamp"] = expiration.isoformat().replace("+00:00", "Z")
    print(json.dumps({"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential", "status": status}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    db = commands.add_parser("database", help="Expose one authorized database resource on loopback")
    db.add_argument("--api-url", required=True)
    db.add_argument("--gateway-url", required=True)
    db.add_argument("--host-id", required=True)
    db.add_argument("--protocol", choices=("postgresql", "mysql"), required=True)
    db.add_argument("--listen-port", type=int, default=0)
    db.add_argument("--identity-file")
    db.add_argument("--ca-file")
    db.add_argument("--allow-loopback-http", action="store_true", help="Only for a loopback development endpoint")
    kube = commands.add_parser("credential", help="Print an ExecCredential for kubectl's exec plugin")
    kube.add_argument("--identity-file")
    args = parser.parse_args()
    try:
        if args.command == "credential":
            credential(args)
        else:
            asyncio.run(database_tunnel(args))
    except KeyboardInterrupt:
        pass
    except (IdentityError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
