"""Authorization at the service-user SSH execution boundary.

No claims, target addresses, remote users or proxy parameters supplied by the
interactive helper are authoritative. All are checked against trusted config,
the signed identity token and current inventory/policy.
"""

import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import time

from isolate_config import load_config
from isolate_identity import IdentityError, _load_token_cache, normalize_claims, verify_jwt_claims
from isolate_inventory import get_host, is_host_in_maintenance
from isolate_policy import PolicyDenied, resolve_grant


class ConnectionDenied(ValueError):
    pass


def invoking_user():
    import pwd
    if not os.environ.get("SUDO_UID", "").isdigit():
        raise ConnectionDenied("the SSH wrapper must be invoked through sudo")
    uid = int(os.environ["SUDO_UID"])
    if uid == 0 or uid == os.geteuid():
        raise ConnectionDenied("a separate personal invoking account is required")
    user = pwd.getpwuid(uid)
    return uid, user.pw_name


def trusted_config():
    """Never honor caller-controlled configuration/environment in the wrapper."""
    import pwd
    trusted_owners = {0, pwd.getpwnam("auth").pw_uid}
    for path in ("/etc/isolate/isolate.yml", "/opt/auth/configs/isolate.yml"):
        if not os.path.exists(path):
            continue
        current = path
        while current != "/":
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or info.st_uid not in trusted_owners or info.st_mode & 0o022:
                raise ConnectionDenied("unsafe wrapper configuration ownership or permissions")
            current = os.path.dirname(current)
        return load_config(path=path, use_env=False)
    raise ConnectionDenied("trusted wrapper configuration is missing")


def prepare_authorization_file():
    """Pass bearer tokens without exposing them in argv or relaxing home permissions.

    The sudo wrapper reads the caller-owned file through a service-UID ACL. Shell
    callback cleanup removes it; tmpfiles provides crash cleanup on Linux.
    """
    import pwd
    cache = _load_token_cache()
    if not cache.get("id_token"):
        raise IdentityError("run isolate login before connecting")
    fd, path = tempfile.mkstemp(prefix="isolate-authorization-{}-".format(os.getuid()), dir="/tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            fd = None
            json.dump({"id_token": cache["id_token"]}, output)
        # Grant only the service UID read access, not every member of group auth.
        subprocess.run(["/usr/bin/setfacl", "-m", "u:{}:r--".format(pwd.getpwnam("auth").pw_uid), path],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       timeout=5, check=True)
        return path
    except Exception:
        if fd is not None:
            os.close(fd)
        os.unlink(path)
        raise


def read_authorization_file(path, uid):
    if not path or os.path.dirname(path) != "/tmp" or not re.fullmatch(
        r"isolate-authorization-{}-[A-Za-z0-9_-]+".format(uid), os.path.basename(path)
    ):
        raise ConnectionDenied("a caller-owned authorization file is required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o027 or info.st_nlink != 1:
            raise ConnectionDenied("unsafe authorization file")
        data = source.read(65537)
        if len(data) > 65536:
            raise ConnectionDenied("authorization file is too large")
        decoded = json.loads(data)
        if not isinstance(decoded, dict):
            raise ConnectionDenied("invalid authorization file")
        token = decoded.get("id_token")
    if not isinstance(token, str) or not token:
        raise ConnectionDenied("an identity token is required")
    return token


def bind_identity(token, config, username):
    keycloak = config.get("keycloak", {})
    if not keycloak.get("issuer") or not keycloak.get("verify_tokens", True) or not keycloak.get("tls_verify", True):
        raise ConnectionDenied("verified Keycloak identity and TLS are required")
    claims = verify_jwt_claims(token, keycloak)
    audiences = claims.get("aud") if isinstance(claims.get("aud"), list) else [claims.get("aud")]
    if (keycloak.get("expected_audience") or keycloak.get("client_id")) not in audiences:
        raise ConnectionDenied("identity token has the wrong audience")
    identity = normalize_claims(claims)
    if not identity.get("keycloak_sub") or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", str(identity.get("username") or "")) or identity["username"] in (".", ".."):
        raise ConnectionDenied("invalid identity subject or username")
    options = config.get("connection_authorization", {})
    mapping = (options.get("unix_users") or {}).get(username)
    if mapping is not None:
        if not isinstance(mapping, dict) or mapping.get("sub") != identity["keycloak_sub"]:
            raise ConnectionDenied("Keycloak subject is not assigned to this Unix account")
    elif options.get("require_explicit_mapping") or identity["username"] != username:
        raise ConnectionDenied("Keycloak identity is not assigned to this Unix account")
    return identity


def policy_for_host(redis, config, identity, host):
    # Import lazily: the CLI also imports inventory and connection helpers.
    from isolate import load_grants, load_project_sets
    if is_host_in_maintenance(host) and not set(identity.get("groups") or []).intersection(config.get("maintenance", {}).get("bypass_groups") or []):
        raise ConnectionDenied("target is in maintenance")
    return resolve_grant(identity, project=host["project_name"], host=host,
                         grants=load_grants(redis), project_sets=load_project_sets(redis),
                         defaults={**config.get("policy", {}), **config.get("ssh", {})})


def authorize_connection(args, token, config, redis, username, now=None):
    now = int(time.time() if now is None else now)
    options = config.get("connection_authorization", {})
    if options.get("connections_enabled", True) is not True:
        raise ConnectionDenied("new SSH connections are disabled")
    identity = bind_identity(token, config, username)
    if not args.host_id or not str(args.host_id).isdigit():
        raise ConnectionDenied("an inventory host ID is required")
    host = get_host(redis, args.host_id)
    if host is None:
        raise ConnectionDenied("target is not in inventory")
    address = str(host["server_ip"])
    # Pin the actual connection to an inventory IP, never caller-controlled DNS.
    ipaddress.ip_address(address)
    port = int(host.get("server_port") or 22)
    ports = options.get("allowed_target_ports") or []
    if ports and port not in ports:
        raise ConnectionDenied("target port is not permitted")
    decision = policy_for_host(redis, config, identity, host)
    sudo_mode = decision.get("sudo_mode") or "none"
    if sudo_mode not in ("none", "sudo-i"):
        raise ConnectionDenied("unsupported sudo mode")
    supplied_user = args.user[0] if args.user else decision["remote_user"]
    if args.hostname[0] != address or (args.port is not None and args.port != port) or supplied_user != decision["remote_user"]:
        raise ConnectionDenied("target address, port or user differs from the authorized inventory/policy")
    if bool(args.nosudo) != (sudo_mode == "none"):
        raise ConnectionDenied("sudo mode differs from the authorized policy")
    if args.project and args.project != host["project_name"]:
        raise ConnectionDenied("project differs from inventory")
    if ((args.human_user and args.human_user != identity["username"])
            or (args.keycloak_sub and args.keycloak_sub != identity["keycloak_sub"])):
        raise ConnectionDenied("caller-supplied identity differs from the signed token")
    proxy = None
    if host.get("proxy_id"):
        if not options.get("allow_proxy", False):
            raise ConnectionDenied("proxy hosts are disabled")
        proxy_host = get_host(redis, host["proxy_id"])
        if not proxy_host:
            raise ConnectionDenied("proxy host is missing")
        proxy_decision = policy_for_host(redis, config, identity, proxy_host)
        from isolate_session_approvals import session_approval_required
        if session_approval_required(config, proxy_host, proxy_decision):
            raise ConnectionDenied("proxy requires session approval; separate proxy approval is not supported")
        proxy = {"host": str(ipaddress.ip_address(proxy_host["server_ip"])), "port": int(proxy_host.get("server_port") or 22), "user": proxy_decision["remote_user"]}
        if ports and proxy["port"] not in ports:
            raise ConnectionDenied("proxy port is not permitted")
    supplied_proxy = {"host": args.proxy_host[0] if args.proxy_host else None, "port": args.proxy_port, "user": args.proxy_user[0] if args.proxy_user else None}
    if any(value is not None for value in supplied_proxy.values()) and supplied_proxy != proxy:
        raise ConnectionDenied("proxy differs from authorized inventory")
    expires = int(identity["exp"])
    if decision["matched_rule"].get("expires_at"):
        expires = min(expires, int(decision["matched_rule"]["expires_at"]))
    expires = min(expires, now + int(options.get("max_session_seconds", 28800)))
    if expires <= now:
        raise ConnectionDenied("connection authorization expired")
    return {"identity": identity, "host": host, "decision": decision, "proxy": proxy,
            "deadline": expires, "username": username, "token": token, "args": args}


def recheck_connection(context, config, redis):
    if time.time() >= context["deadline"]:
        raise ConnectionDenied("session authorization expired")
    current = authorize_connection(context["args"], context["token"], config, redis, context["username"])
    if current["proxy"] != context["proxy"]:
        raise ConnectionDenied("proxy authorization changed")
    from isolate_session_approvals import SessionApprovalDenied, session_approval_required, validate_session_approval
    approval_id = context.get("session_approval_id")
    if approval_id:
        try:
            approval = validate_session_approval(redis, config, approval_id, current["identity"], current["host"],
                current["decision"], context["connection_id"], source_ip=context.get("source_ip"))
        except SessionApprovalDenied as exc:
            raise ConnectionDenied(str(exc)) from exc
        current["deadline"] = min(current["deadline"], int(approval["session_expires_at"]))
        if time.time() >= current["deadline"]:
            raise ConnectionDenied("session approval expired")
    elif session_approval_required(config, current["host"], current["decision"]):
        raise ConnectionDenied("this session now requires administrator approval")
    return current


def wait_for_connection_approval(context, config, redis, connection_id, source_ip=None, on_event=None,
                                 refresh_config=None, sleeper=None):
    """Wait before starting SSH, then atomically consume one connection's approval.

    Identity and current policy are re-evaluated while waiting. A pending request
    never acts as a grant, and a consumed record cannot start another connection.
    """
    from isolate_session_approvals import (
        SessionApprovalDenied, cancel_session_approval, close_session_approval, consume_session_approval,
        get_session_approval, request_session_approval,
    )
    if context.get("session_approval_id"):
        raise ConnectionDenied("session approval has already been consumed")
    record = request_session_approval(redis, config, context["identity"], context["host"], context["decision"],
                                      connection_id, source_ip=source_ip)
    if record is None:
        return context
    request_id = record["id"]
    sleep = sleeper or time.sleep
    consumed = False
    try:
        if on_event:
            on_event("session_approval_requested", record)
        while True:
            current_config = refresh_config() if refresh_config else config
            current = authorize_connection(context["args"], context["token"], current_config, redis, context["username"])
            if current["proxy"] != context["proxy"]:
                raise ConnectionDenied("proxy authorization changed while awaiting approval")
            latest = get_session_approval(redis, request_id, config=current_config)
            if latest is None:
                raise ConnectionDenied("session approval request disappeared")
            if latest["status"] == "approved":
                approved = consume_session_approval(redis, current_config, request_id, current["identity"], current["host"],
                    current["decision"], connection_id, source_ip=source_ip)
                consumed = True
                current.update(session_approval_id=request_id, connection_id=connection_id, source_ip=source_ip)
                current["deadline"] = min(context["deadline"], current["deadline"], approved["session_expires_at"])
                if on_event:
                    on_event("session_approval_consumed", approved)
                return current
            if latest["status"] != "pending":
                raise ConnectionDenied("session approval is {}".format(latest["status"]))
            if time.time() >= min(context["deadline"], current["deadline"]):
                raise ConnectionDenied("connection authorization expired while awaiting approval")
            interval = max(1, min(30, int(current_config.get("session_approval", {}).get("poll_interval_seconds", 2))))
            sleep(min(interval, max(0, latest["request_expires_at"] - time.time())))
    except BaseException:
        try:
            if consumed:
                close_session_approval(redis, request_id)
            else:
                cancel_session_approval(redis, config, request_id, context["identity"])
        except Exception:
            pass
        raise
