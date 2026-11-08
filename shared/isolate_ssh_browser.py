"""One-use browser approval for standard SSH keyboard-interactive clients.

The public user code is a confirmation URL, never a bearer credential. Only the
waiting SSH transport has the independent proof needed to consume its result.
"""

import asyncio
import hashlib
import html
import ipaddress
import json
import re
import secrets
import time
from urllib.parse import urlsplit, urlencode

from redis.exceptions import WatchError
from isolate_runtime import Runtime, RuntimeDenied
from isolate_identity import IdentityError
from isolate_policy import PolicyDenied
from redis.exceptions import RedisError


def _options(config):
    return config.get("gateway", {}).get("browser_auth", {})


def _code(value):
    normalized = str(value or "").replace("-", "").upper()
    if not re.fullmatch(r"[A-Z2-7]{12}", normalized):
        raise RuntimeDenied("invalid SSH confirmation code")
    return normalized


def _key(code):
    return "ssh_browser_login_" + hashlib.sha256(_code(code).encode()).hexdigest()


def _read(runtime, code):
    raw = runtime.redis.get(_key(code))
    record = json.loads(raw) if raw else None
    if not record or record["expires_at"] <= time.time() or record.get("epoch") != runtime._epoch():
        raise RuntimeDenied("SSH confirmation expired; start a new connection")
    return record


def begin(runtime, host_id, source_ip):
    if not _options(runtime.config).get("enabled") or not runtime.config.get("api", {}).get("enabled"):
        raise RuntimeDenied("browser SSH sign-in is disabled")
    if not isinstance(host_id, str) or not re.fullmatch(r"[0-9]{1,20}", host_id):
        raise RuntimeDenied("SSH username must be an inventory resource ID")
    source_ip = str(ipaddress.ip_address(source_ip))
    base = str(runtime.config.get("dashboard", {}).get("public_url") or "").rstrip("/")
    parsed = urlsplit(base)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise RuntimeDenied("browser SSH sign-in requires the public HTTPS dashboard URL")
    from isolate_admission import check_admission
    check_admission(runtime.redis, {"admission": dict(runtime.config.get("admission", {}), enabled=True)},
        peer=source_ip, kind="ssh-browser")
    import base64
    code = base64.b32encode(secrets.token_bytes(8)).decode()[:12]
    display = "-".join(code[i:i + 4] for i in range(0, 12, 4))
    proof = secrets.token_urlsafe(32)
    ttl = max(30, min(300, int(_options(runtime.config).get("timeout_seconds", 120))))
    record = {"host_id": host_id, "source_ip": source_ip, "epoch": runtime._epoch(),
        "proof_hash": hashlib.sha256(proof.encode()).hexdigest(), "expires_at": int(time.time()) + ttl, "status": "pending"}
    if not runtime.redis.set(_key(code), json.dumps(record), nx=True, ex=ttl):
        raise RuntimeDenied("could not allocate SSH confirmation; retry")
    return {"code": display, "proof": proof, "expires_at": record["expires_at"],
        "verification_uri": base + "/ssh/authorize?" + urlencode({"code": display})}


def approve(runtime, code, token):
    key = _key(code)
    original = _read(runtime, code)
    if original["status"] != "pending":
        raise RuntimeDenied("SSH confirmation is already resolved")
    # Re-authorize every route, membership, step-up and epoch after browser login.
    ticket = runtime.create_ticket(token, original["host_id"], "ssh", original["source_ip"])
    try:
        if original["epoch"] != runtime._epoch():
            raise RuntimeDenied("SSH confirmation crossed the recovery boundary")
        with runtime.redis.pipeline() as pipe:
            pipe.watch(key)
            record = json.loads(pipe.get(key) or "null")
            if record != original or record["expires_at"] <= time.time():
                raise RuntimeDenied("SSH confirmation changed or expired")
            record.update(status="approved", ticket=ticket["ticket"])
            pipe.multi()
            pipe.set(key, json.dumps(record), ex=max(1, record["expires_at"] - int(time.time())))
            pipe.execute()
    except BaseException:
        runtime.redis.delete("isolate_ticket_" + hashlib.sha256(ticket["ticket"].encode()).hexdigest())
        raise
    return {"host_id": original["host_id"], "expires_at": original["expires_at"]}


def poll(runtime, code, proof):
    key = _key(code)
    record = _read(runtime, code)
    if not isinstance(proof, str) or not secrets.compare_digest(record["proof_hash"], hashlib.sha256(proof.encode()).hexdigest()):
        raise RuntimeDenied("SSH transport proof differs")
    if record["status"] == "pending":
        return None
    if record["status"] != "approved":
        raise RuntimeDenied("SSH confirmation was denied")
    with runtime.redis.pipeline() as pipe:
        pipe.watch(key)
        current = pipe.get(key)
        if current is None or json.loads(current) != record:
            raise RuntimeDenied("SSH confirmation was already consumed")
        pipe.multi()
        pipe.delete(key)
        pipe.execute()
    return runtime.consume_ticket(record["ticket"], "ssh", record["source_ip"])


async def ssh_challenge(server, username):
    if server.context is not None or getattr(server, "browser_challenge", None):
        return False
    server.auth_attempts += 1
    if server.auth_attempts > 3:
        return False
    try:
        peer = server.connection.get_extra_info("peername")
        challenge = await asyncio.to_thread(begin, server.runtime, username, peer[0])
        server.browser_challenge = challenge
        return ("Isolate browser sign-in", "Open this trusted dashboard URL and verify the target and SSH source:\n" +
            challenge["verification_uri"] + "\nConfirmation code: " + challenge["code"], "", [(
                "Approve at " + challenge["verification_uri"] + " then press Enter: ", False)])
    except Exception:
        return False


async def ssh_response(server, username, responses):
    challenge = getattr(server, "browser_challenge", None)
    if not challenge or server.context is not None or len(responses) != 1:
        return False
    try:
        while time.time() < challenge["expires_at"] and not server.connection.is_closed():
            context = await asyncio.to_thread(poll, server.runtime, challenge["code"], challenge["proof"])
            if context:
                result = server.set_context(context, username)
                if hasattr(result, "__await__"):
                    result = await result
                return result is not False
            await asyncio.sleep(0.5)
    except Exception:
        return False
    return False


def register_ssh_browser_routes(app, config, redis_factory, current_identity, csrf_token, browser_token):
    from flask import request, redirect, session, abort
    from isolate_identity_security import StepUpRequired

    @app.route("/ssh/authorize", methods=["GET", "POST"])
    def ssh_authorize():
        if not _options(config).get("enabled") or not config.get("api", {}).get("enabled"):
            abort(404)
        try:
            code = _code(request.values.get("code"))
        except RuntimeDenied:
            abort(400)
        identity = current_identity()
        if not identity:
            session["return_to"] = "/ssh/authorize?" + urlencode({"code": code})
            return redirect("/login")
        runtime = Runtime(config, redis_factory(config))
        try:
            record = _read(runtime, code)
            token = browser_token()
            if not token:
                abort(401)
            context = runtime.authorize(token, record["host_id"], "ssh", record["source_ip"])
            if request.method == "POST":
                if not secrets.compare_digest(request.form.get("csrf_token", ""), csrf_token()):
                    abort(403)
                if request.form.get("confirm") != "yes":
                    abort(400)
                approve(runtime, code, token)
                body = '<h1>SSH connection approved</h1><p>Return to your SSH client and press Enter.</p>'
            else:
                body = '<h1>Confirm your SSH connection</h1><p>Approve only a connection you started. Verify the code, target and source.</p>'
                body += '<dl><dt>Code</dt><dd>{}</dd><dt>Resource</dt><dd>{} · {} · #{}</dd><dt>SSH source</dt><dd>{}</dd></dl>'.format(
                    html.escape(code), html.escape(context["host"]["server_name"]), html.escape(context["host"]["project_name"]),
                    html.escape(record["host_id"]), html.escape(record["source_ip"]))
                body += '<form method="post"><input type="hidden" name="code" value="{}"><input type="hidden" name="csrf_token" value="{}"><button name="confirm" value="yes">Approve this SSH connection</button></form>'.format(code, html.escape(csrf_token(), quote=True))
        except StepUpRequired:
            session["return_to"] = "/ssh/authorize?" + urlencode({"code": code})
            return redirect("/login?step_up=true")
        except RedisError:
            return "SSH sign-in temporarily unavailable", 503
        except (ValueError, RuntimeDenied, IdentityError, PolicyDenied):
            abort(403, description="SSH confirmation could not be authorized")
        from isolate_web import _html
        return _html("SSH sign-in", body, config=config)
