"""API transport for the existing console; no Redis credentials on clients."""

import argparse
import asyncio
import ipaddress
import json
import os
import shlex
import ssl
import sys
from urllib import error, parse, request

from isolate_identity import IdentityError, _load_token_cache


class ClientError(ValueError):
    pass


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class APIClient:
    def __init__(self, config):
        self.config = config
        self.base = str(config.get("api", {}).get("client_url") or "").rstrip("/")
        parsed = parse.urlsplit(self.base)
        loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback)
                or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ClientError("an HTTPS control API URL is required")
        self.opener = request.build_opener(request.HTTPSHandler(context=ssl.create_default_context(
            cafile=config.get("api", {}).get("ca_file"))), _NoRedirect())

    def call(self, path, body=None):
        token = _load_token_cache().get(self.config.get("keycloak", {}).get("token_kind", "id_token"))
        if not token:
            raise IdentityError("run isolate login before using the API")
        payload = json.dumps(body).encode() if body is not None else None
        req = request.Request(self.base + path, data=payload,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(req, timeout=10) as response:
                data = response.read(8 * 1024 * 1024 + 1)
                if len(data) > 8 * 1024 * 1024:
                    raise ClientError("API response is too large")
                return json.loads(data)
        except error.HTTPError as exc:
            if exc.code == 401:
                raise IdentityError("API identity expired or missing; run isolate login") from None
            if exc.code == 403:
                raise ClientError("API access denied; privileged access may require isolate login --step-up") from None
            raise ClientError("API request failed with HTTP {}".format(exc.code)) from None
        except (error.URLError, OSError) as exc:
            raise ClientError("control API is unavailable") from exc

    def resources(self):
        rows, offset = [], 0
        for _ in range(200):
            page = self.call("/api/v1/resources?limit=500&offset={}".format(offset))
            rows.extend(page["resources"])
            if page.get("next_offset") is None:
                return rows
            offset = int(page["next_offset"])
        raise ClientError("inventory exceeds client pagination limit")


async def connect(config, host_id, command=None):
    import asyncssh
    ticket = await asyncio.to_thread(APIClient(config).call, "/api/v1/connections", {"host_id": str(host_id), "protocol": "ssh"})
    host = ticket.get("gateway_host")
    if not host:
        raise ClientError("gateway public SSH host is not configured")
    known_hosts = config.get("api", {}).get("gateway_known_hosts")
    if not known_hosts:
        raise ClientError("api.gateway_known_hosts is required to verify the gateway")
    state = None
    try:
        async with asyncssh.connect(host, port=int(ticket["gateway_port"]), username=str(host_id),
                password=ticket["ticket"], known_hosts=known_hosts, client_keys=[], agent_path=None,
                config=None, connect_timeout=10, login_timeout=10) as connection:
            ticket.clear()
            if command:
                result = await connection.run(command, check=False)
                sys.stdout.write(result.stdout)
                sys.stderr.write(result.stderr)
                return result.exit_status if result.exit_status is not None else 255
            interactive = sys.stdin.isatty() and sys.stdout.isatty()
            if interactive and os.name == "posix":
                import termios
                import tty
                state = termios.tcgetattr(sys.stdin.fileno())
                tty.setraw(sys.stdin.fileno())
            size = os.get_terminal_size() if interactive else os.terminal_size((80, 24))
            process = await connection.create_process(term_type=os.environ.get("TERM", "xterm-256color") if interactive else None,
                term_size=(size.columns, size.lines), stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            result = await process.wait()
            return result.exit_status if result.exit_status is not None else 255
    except asyncssh.Error:
        raise ClientError("gateway SSH authentication, host verification or connection failed") from None
    finally:
        ticket.clear()
        if state is not None:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, state)


def console(args, unknown_args, config):
    """Keep s/g/p parsing and rendering, replacing only the storage transport."""
    if unknown_args:
        raise ClientError("gateway connection options are controlled by server policy")
    client = APIClient(config)
    rows = client.resources()
    # Reuse established rendering methods without creating AuthHelper or Redis.
    from helper import AuthHelper
    display = AuthHelper.__new__(AuthHelper)
    display.args = args
    display._init_env_vars()
    display.projects = sorted(set(row["project_name"].lower() for row in rows))
    action = args.action[0]
    if action == "projects":
        display.print_projects({project: sum(row["project_name"].lower() == project for row in rows) for project in display.projects})
        return 0
    selectors = args.sargs or []
    if action == "search":
        text = " ".join(selectors).lower()
        from isolate_inventory import host_matches_query
        display.print_hosts([row for row in rows if host_matches_query(row, text)])
        return 0
    if action != "go" or not 1 <= len(selectors) <= 2:
        raise ClientError("use g <project|host> [server_name]")
    candidates = rows
    if len(selectors) == 2:
        candidates = [row for row in rows if row["project_name"].lower() == selectors[0].lower()]
    query = selectors[-1].lower()
    exact = [row for row in candidates if query in [str(row.get(key) or "").lower() for key in
             ("server_id", "server_name", "server_ip")]]
    if not exact and len(selectors) == 1 and query in display.projects:
        exact = [row for row in rows if row["project_name"].lower() == query]
    if len(exact) != 1:
        display.print_hosts(exact or candidates, ambiguous=True)
        return 2
    host_id = exact[0]["server_id"]
    session_file = os.getenv("ISOLATE_SESSION")
    if session_file:
        callback = [sys.executable, os.path.abspath(__file__), "connect", str(host_id)]
        with open(session_file, "w", encoding="utf-8") as output:
            output.write("ISOLATE_CALLBACK={}\nISOLATE_CALLBACK_CMD=({})\n".format(
                shlex.quote(session_file), " ".join(shlex.quote(arg) for arg in callback)))
        return 0
    return asyncio.run(connect(config, host_id))


def completion(config, project=None):
    if config.get("api", {}).get("client_url"):
        rows = APIClient(config).resources()
    else:
        from isolate import load_grants, load_project_sets
        from isolate_identity import load_verified_identity
        from isolate_inventory import list_hosts
        from isolate_policy import filter_allowed_hosts
        from isolate_redis import create_redis_client
        redis = create_redis_client(config)
        rows = filter_allowed_hosts(load_verified_identity(config), list_hosts(redis), grants=load_grants(redis),
            project_sets=load_project_sets(redis), defaults={**config.get("policy", {}), **config.get("ssh", {})})
    if project:
        return sorted({str(row["server_name"]) for row in rows if row["project_name"].lower() == project.lower()})
    return sorted({row["project_name"].lower() for row in rows})


def main():
    from isolate_config import load_config
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    go = commands.add_parser("connect")
    go.add_argument("host_id")
    go.add_argument("--command")
    complete = commands.add_parser("complete")
    complete.add_argument("--project")
    args = parser.parse_args()
    try:
        config = load_config()
        if args.action == "connect":
            return asyncio.run(connect(config, args.host_id, args.command))
        for value in completion(config, args.project):
            print(value)
        return 0
    except (ClientError, IdentityError, OSError, ValueError) as exc:
        print("Isolate: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
