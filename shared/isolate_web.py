#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight Isolate admin dashboard."""

import html
import json
import os
import secrets

from isolate import list_grant_records, load_project_sets, redis_client
from isolate_access import approve_access_request, deny_access_request, is_access_admin, list_access_requests, parse_duration, repeat_access_request, set_notification_status
from isolate_config import load_config
from isolate_history import read_history
from isolate_health import run_health_checks
from isolate_identity import decode_jwt_payload, normalize_claims
from isolate_inventory import list_hosts
from isolate_notifications import NotificationError, notify_access_event
from isolate_replay import find_session, parse_raw_replay
from isolate_sessions import list_active_sessions


def is_dashboard_admin(identity, config):
    groups = config.get("dashboard", {}).get("admin_groups") or config.get("history", {}).get("admin_groups") or []
    return is_access_admin(identity, groups)


def _secret_key(config):
    path = config.get("dashboard", {}).get("secret_key_file")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as secret_f:
            return secret_f.read().strip()
    return os.environ.get("ISOLATE_DASHBOARD_SECRET", "dev-only-change-me")


def _html(title, body, config=None, notice=None):
    refresh = ""
    refresh_seconds = int((config or {}).get("dashboard", {}).get("refresh_seconds") or 0)
    if refresh_seconds > 0:
        refresh = '<meta http-equiv="refresh" content="{}">'.format(refresh_seconds)
    notice_html = ""
    if notice:
        notice_html = '<div class="notice {}">{}</div>'.format(
            html.escape(notice.get("level", "info")),
            html.escape(notice.get("text", "")),
        )
    return """<!doctype html>
<html><head><meta charset="utf-8">{refresh}<title>{title}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; color: #182026; }}
nav a {{ margin-right: 14px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
th, td {{ border-bottom: 1px solid #d7dde2; padding: 7px 8px; text-align: left; font-size: 14px; }}
th {{ background: #f4f6f8; }}
input, select, button {{ padding: 6px 8px; margin: 2px; }}
form.inline {{ display: inline-flex; flex-wrap: wrap; gap: 4px; align-items: center; }}
.muted {{ color: #66717b; }}
.grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
.metric {{ border: 1px solid #d7dde2; padding: 12px; border-radius: 6px; }}
.notice {{ border: 1px solid #b7d5f5; background: #eef7ff; padding: 10px 12px; margin: 14px 0; border-radius: 6px; }}
.notice.error {{ border-color: #efb4b4; background: #fff1f1; }}
.notice.warning {{ border-color: #e4c46d; background: #fff8df; }}
</style></head><body>
<nav><a href="/">Summary</a><a href="/sessions/active">Active</a><a href="/history">History</a><a href="/inventory">Inventory</a><a href="/access">Access</a><a href="/grants">Grants</a><a href="/logout">Logout</a></nav>
{notice}
{body}
</body></html>""".format(refresh=refresh, title=title, notice=notice_html, body=body)


def _table(rows, columns):
    header = "".join("<th>{}</th>".format(label) for key, label in columns)
    body = ""
    for row in rows:
        cells = []
        for key, _ in columns:
            value = row.get(key) or ""
            if key not in ("raw", "project_link", "history", "details", "replay"):
                value = html.escape(str(value))
            cells.append("<td>{}</td>".format(value))
        body += "<tr>{}</tr>".format("".join(cells))
    return "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>".format(header, body)


def create_app(config=None):
    from authlib.integrations.flask_client import OAuth
    from flask import Flask, abort, jsonify, redirect, render_template_string, request, send_file, session, url_for

    config = config or load_config()
    app = Flask(__name__)
    app.secret_key = _secret_key(config)
    oauth = OAuth(app)

    issuer = (config.get("keycloak", {}).get("issuer") or "").rstrip("/")
    oauth.register(
        name="keycloak",
        client_id=config.get("keycloak", {}).get("client_id"),
        client_secret=config.get("keycloak", {}).get("client_secret"),
        server_metadata_url=issuer + "/.well-known/openid-configuration",
        client_kwargs={"scope": " ".join(config.get("keycloak", {}).get("scopes") or ["openid", "profile", "email"])},
    )

    def current_identity():
        identity = session.get("identity")
        if not identity:
            return None
        return identity

    def require_admin():
        identity = current_identity()
        if identity is None:
            return redirect(url_for("login"))
        if not is_dashboard_admin(identity, config):
            abort(403)
        return identity

    def csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def validate_csrf():
        if request.form.get("csrf_token") != session.get("csrf_token"):
            abort(403)

    def notify_dashboard(redis, event_name, record, admin, extra=None):
        try:
            result = notify_access_event(config, event_name, record, actor=admin, extra=extra)
        except NotificationError as exc:
            set_notification_status(redis, record.get("id"), {"ok": False, "errors": [str(exc)], "sent": []})
            return {"level": "error", "text": "Action completed, but notification failed: {}".format(exc)}
        set_notification_status(redis, record.get("id"), {"ok": not bool(result.get("errors")), "errors": result.get("errors") or [], "sent": result.get("sent") or []})
        if result.get("errors"):
            return {"level": "warning", "text": "Action completed with notification warning: {}".format("; ".join(result["errors"]))}
        return None

    @app.route("/health")
    def health():
        result = run_health_checks(config)
        public_result = {
            "ok": result["ok"],
            "status": result["status"],
            "checks": {name: {"ok": bool(check.get("ok"))} for name, check in result["checks"].items()},
        }
        response = jsonify(public_result)
        response.status_code = 200 if result["ok"] else 503
        return response

    def status_filter_links(current):
        statuses = [("all", None), ("pending", "pending"), ("approved", "approved"), ("denied", "denied")]
        links = []
        for label, value in statuses:
            href = "/access" if value is None else "/access?status={}".format(value)
            text = "<strong>{}</strong>".format(label) if current == value else html.escape(label)
            links.append('<a href="{}">{}</a>'.format(href, text))
        return " ".join(links)

    def access_table(rows, token, access_cfg):
        default_ttl = html.escape(str(access_cfg.get("default_ttl", "2h")))
        header = (
            "<th>id</th><th>status</th><th>user</th><th>project</th><th>host</th><th>ticket</th>"
            "<th>remote_user</th><th>sudo</th><th>reason</th><th>decision</th><th>expires</th><th>grant</th><th>comments</th><th>notify</th><th>actions</th>"
        )
        body = ""
        for row in rows:
            cells = [
                html.escape(str(row.get("id") or "")),
                html.escape(str(row.get("status") or "")),
                html.escape(str(row.get("requester") or "")),
                html.escape(str(row.get("project") or "")),
                html.escape(str(row.get("host") or "")),
                html.escape(str(row.get("ticket") or "")),
                html.escape(str(row.get("remote_user") or "")),
                html.escape(str(row.get("sudo_mode") or "")),
                html.escape(str(row.get("reason") or "")),
                html.escape(str(row.get("decision_reason") or "")),
                html.escape(str(row.get("expires_at") or "")),
                html.escape(str(row.get("grant_id") or "")),
                html.escape("; ".join("{}: {}".format(c.get("username") or "", c.get("text") or "") for c in row.get("comments") or [])),
                html.escape(str((row.get("notification_status") or {}).get("ok", ""))),
            ]
            actions = ""
            if row.get("status") == "pending":
                request_id = html.escape(str(row.get("id") or ""))
                remote_user = html.escape(str(row.get("remote_user") or ""))
                sudo_mode = html.escape(str(row.get("sudo_mode") or ""))
                actions = """
<form class="inline" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="id" value="{request_id}">
  <input type="hidden" name="action" value="approve">
  <input name="ttl" value="{default_ttl}" size="5" title="TTL">
  <input name="remote_user" value="{remote_user}" placeholder="remote_user" size="10">
  <input name="sudo_mode" value="{sudo_mode}" placeholder="sudo_mode" size="8">
  <input name="comment" placeholder="comment" size="12">
  <button type="submit">Approve</button>
</form>
<form class="inline" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="id" value="{request_id}">
  <input type="hidden" name="action" value="deny">
  <input name="reason" placeholder="reason" size="12">
  <input name="comment" placeholder="comment" size="12">
  <button type="submit">Deny</button>
</form>""".format(
                    token=html.escape(token),
                    request_id=request_id,
                    default_ttl=default_ttl,
                    remote_user=remote_user,
                    sudo_mode=sudo_mode,
                )
            else:
                request_id = html.escape(str(row.get("id") or ""))
                actions = """
<form class="inline" method="post">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="id" value="{request_id}">
  <input type="hidden" name="action" value="repeat">
  <input name="reason" placeholder="reason" size="14">
  <input name="ticket" placeholder="ticket" size="10">
  <button type="submit">Request again</button>
</form>""".format(token=html.escape(token), request_id=request_id)
            body += "<tr>{}<td>{}</td></tr>".format("".join("<td>{}</td>".format(cell) for cell in cells), actions)
        return "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>".format(header, body)

    @app.route("/login")
    def login():
        redirect_uri = config.get("dashboard", {}).get("public_url", "").rstrip("/") + url_for("callback")
        return oauth.keycloak.authorize_redirect(redirect_uri)

    @app.route("/auth/callback")
    def callback():
        token = oauth.keycloak.authorize_access_token()
        claims = token.get("userinfo") or {}
        if not claims and token.get("id_token"):
            claims = decode_jwt_payload(token["id_token"])
        identity = normalize_claims(claims)
        if not is_dashboard_admin(identity, config):
            abort(403)
        session["identity"] = identity
        return redirect(url_for("index"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    def index():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        active = list_active_sessions(redis)
        pending = list_access_requests(redis, status="pending")
        recent = read_history(config["logging"]["base_path"], admin, limit=10, admin_groups=config.get("dashboard", {}).get("admin_groups") or [])
        body = """
<h1>Isolate Dashboard</h1>
<div class="grid">
<div class="metric"><strong>{}</strong><br><span class="muted">active sessions</span></div>
<div class="metric"><strong>{}</strong><br><span class="muted">pending access requests</span></div>
<div class="metric"><strong>{}</strong><br><span class="muted">recent connections</span></div>
</div>
""".format(len(active), len(pending), len(recent))
        return _html("Isolate Dashboard", body, config=config)

    @app.route("/sessions/active")
    def active_sessions():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        rows = list_active_sessions(redis_client(config))
        return _html("Active Sessions", "<h1>Active Sessions</h1>" + _table(rows, [
            ("started_at", "started"), ("username", "user"), ("project", "project"), ("host_id", "host"),
            ("target_host", "target"), ("remote_user", "remote_user"), ("connection_id", "connection_id")
        ]), config=config)

    @app.route("/history")
    def history():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        rows = read_history(
            config["logging"]["base_path"],
            admin,
            query=request.args.get("q"),
            user=request.args.get("user"),
            project=request.args.get("project"),
            host=request.args.get("host"),
            limit=int(request.args.get("limit", 50)),
            admin_groups=config.get("dashboard", {}).get("admin_groups") or [],
        )
        for row in rows:
            connection_id = row.get("connection_id") or row.get("session_id")
            if connection_id:
                row["details"] = '<a href="/session/{}">details</a>'.format(html.escape(str(connection_id)))
            if row.get("raw_log_path"):
                row["raw"] = '<a href="/raw/{}/{}">raw</a>'.format(row.get("username"), row.get("connection_id") or row.get("session_id"))
        return _html("History", "<h1>History</h1>" + _table(rows, [
            ("time", "time"), ("username", "user"), ("project", "project"), ("host_id", "host"),
            ("target", "target"), ("remote_user", "remote_user"), ("result", "result"), ("details", "details"), ("raw", "raw")
        ]))

    @app.route("/access", methods=["GET", "POST"])
    def access():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            request_id = request.form.get("id")
            try:
                if action == "approve":
                    ttl = parse_duration(request.form.get("ttl"), default=config.get("access", {}).get("default_ttl", "2h"))
                    max_ttl = parse_duration(config.get("access", {}).get("max_ttl", "24h"))
                    remote_user = request.form.get("remote_user") or None
                    sudo_mode = request.form.get("sudo_mode") or None
                    record, grant = approve_access_request(
                        redis,
                        request_id,
                        admin,
                        ttl,
                        remote_user=remote_user,
                        sudo_mode=sudo_mode,
                        max_ttl=max_ttl,
                        comment=request.form.get("comment") or None,
                    )
                    notice = notify_dashboard(redis, "access_request_approved", record, admin, extra={"grant": grant})
                    notice = notice or {"level": "info", "text": "Access request approved"}
                elif action == "deny":
                    record = deny_access_request(redis, request_id, admin, reason=request.form.get("reason"), comment=request.form.get("comment") or None)
                    notice = notify_dashboard(redis, "access_request_denied", record, admin)
                    notice = notice or {"level": "info", "text": "Access request denied"}
                elif action == "repeat":
                    record = repeat_access_request(redis, request_id, admin, reason=request.form.get("reason") or None, ticket=request.form.get("ticket") or None, config=config)
                    notice = notify_dashboard(redis, "access_request_created", record, admin)
                    notice = notice or {"level": "info", "text": "Access request repeated"}
            except Exception as exc:
                notice = {"level": "error", "text": str(exc)}
        status = request.args.get("status")
        if status == "all":
            status = None
        rows = list_access_requests(
            redis,
            status=status,
            user=request.args.get("user") or None,
            project=request.args.get("project") or None,
            ticket=request.args.get("ticket") or None,
        )
        body = """
<h1>Access Requests</h1>
<form method="get">
  <input name="user" value="{user}" placeholder="user">
  <input name="project" value="{project}" placeholder="project">
  <input name="ticket" value="{ticket}" placeholder="ticket">
  <button type="submit">Filter</button>
</form>
<p>{links}</p>{table}
""".format(
            user=html.escape(request.args.get("user") or ""),
            project=html.escape(request.args.get("project") or ""),
            ticket=html.escape(request.args.get("ticket") or ""),
            links=status_filter_links(status),
            table=access_table(rows, csrf_token(), config.get("access", {})),
        )
        return _html("Access Requests", body, config=config, notice=notice)

    @app.route("/inventory")
    def inventory():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        project = request.args.get("project") or None
        query = request.args.get("q") or None
        rows = list_hosts(redis_client(config), project=project, query=query)
        for row in rows:
            row["project_link"] = '<a href="/history?project={}">{}</a>'.format(
                html.escape(str(row.get("project_name") or "")),
                html.escape(str(row.get("project_name") or "")),
            )
            row["history"] = '<a href="/history?host={}">history</a>'.format(html.escape(str(row.get("server_id") or "")))
        body = """
<h1>Inventory</h1>
<form method="get">
  <input name="project" value="{project}" placeholder="project">
  <input name="q" value="{query}" placeholder="search">
  <button type="submit">Search</button>
</form>
""".format(
            project=html.escape(project or ""),
            query=html.escape(query or ""),
        )
        body += _table(rows, [
            ("project_link", "project"), ("server_id", "id"), ("server_ip", "ip"), ("server_name", "name"),
            ("server_vip_marker", "vip"), ("server_user", "user"), ("server_services", "services"),
            ("server_note", "note"), ("privileged_access_provider", "privileged"), ("privileged_access_hint", "hint"),
            ("history", "history")
        ])
        return _html("Inventory", body)

    @app.route("/session/<connection_id>")
    def session_details(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        summary = details.get("summary") or {}
        raw_link = ""
        replay_link = ""
        replay_json_link = ""
        if summary.get("raw_log_path"):
            raw_link = '<a href="/raw/{}/{}">raw transcript</a>'.format(
                html.escape(str(summary.get("username") or "")),
                html.escape(str(connection_id)),
            )
            replay_link = '<a href="/replay/{}">replay</a>'.format(html.escape(str(connection_id)))
            replay_json_link = '<a href="/replay/{}.json">replay.json</a>'.format(html.escape(str(connection_id)))
        summary_rows = [
            {"key": key, "value": summary.get(key)}
            for key in ("time", "username", "project", "host_id", "target", "remote_user", "result", "connection_id", "session_id")
        ]
        event_rows = []
        command_rows = []
        for event in details.get("events") or []:
            if event.get("event") == "command":
                command_rows.append(
                    {
                        "ts": event.get("ts"),
                        "cwd": event.get("cwd"),
                        "command": event.get("command"),
                        "exit_code": event.get("exit_code"),
                        "shell": event.get("shell"),
                    }
                )
                continue
            event_rows.append(
                {
                    "ts": event.get("ts"),
                    "event": event.get("event"),
                    "project": event.get("project"),
                    "host_id": event.get("host_id"),
                    "remote_user": event.get("remote_user"),
                    "exit_code": event.get("exit_code"),
                }
            )
        body = "<h1>Session Details</h1>"
        body += "<p>{} {} {} <a href=\"/session/{}/events.json\">events.json</a></p>".format(raw_link, replay_link, replay_json_link, html.escape(str(connection_id)))
        body += "<h2>Summary</h2>" + _table(summary_rows, [("key", "field"), ("value", "value")])
        if command_rows:
            body += "<h2>Commands</h2>" + _table(command_rows, [
                ("ts", "ts"), ("cwd", "cwd"), ("command", "command"), ("exit_code", "exit"), ("shell", "shell")
            ])
        body += "<h2>Timeline</h2>" + _table(event_rows, [
            ("ts", "ts"), ("event", "event"), ("project", "project"), ("host_id", "host"),
            ("remote_user", "remote_user"), ("exit_code", "exit")
        ])
        return _html("Session Details", body)

    @app.route("/session/<connection_id>/events.json")
    def session_events_json(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        return app.response_class(
            response=json.dumps(details.get("events") or [], indent=2, sort_keys=True),
            status=200,
            mimetype="application/json",
        )

    @app.route("/replay/<connection_id>.json")
    def replay_json(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        replay = parse_raw_replay(details.get("raw_log_path"), max_bytes=int(config.get("replay", {}).get("max_bytes", 10485760)))
        return app.response_class(
            response=json.dumps(replay, indent=2, sort_keys=True),
            status=200,
            mimetype="application/json",
        )

    @app.route("/replay/<connection_id>")
    def replay(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None:
            abort(404)
        replay_data = parse_raw_replay(details.get("raw_log_path"), max_bytes=int(config.get("replay", {}).get("max_bytes", 10485760)))
        plain = html.escape(replay_data.get("plain") or "")
        error = replay_data.get("error")
        default_speed = html.escape(str(config.get("replay", {}).get("default_speed", 1)))
        body = """
<h1>Session Replay</h1>
<p><a href="/session/{connection_id}">details</a> <a href="/replay/{connection_id}.json" download>replay.json</a></p>
<p>
  <button id="play">Play</button>
  <button id="pause">Pause</button>
  <button id="reset">Reset</button>
  <select id="speed"><option value="0.5">0.5x</option><option value="1">1x</option><option value="2">2x</option><option value="5">5x</option></select>
  <label><input type="checkbox" id="plainToggle"> Plain transcript</label>
  <span id="clock">0.00 / 0.00</span>
</p>
<input id="scrubber" type="range" min="0" max="0" step="0.01" value="0" style="width:100%;">
<pre id="terminal" style="background:#111;color:#eee;padding:12px;min-height:360px;white-space:pre-wrap;"></pre>
<pre id="fallback" style="display:none;">{plain}</pre>
<script>
let chunks = [];
let timers = [];
let speed = {default_speed};
let cursor = 0;
let duration = 0;
const terminal = document.getElementById("terminal");
const scrubber = document.getElementById("scrubber");
const clock = document.getElementById("clock");
document.getElementById("speed").value = String(speed);
function clearTimers() {{ timers.forEach(clearTimeout); timers = []; }}
function renderUntil(index) {{
  cursor = Math.max(0, Math.min(index, chunks.length));
  terminal.textContent = chunks.slice(0, cursor).map(c => c.data).join("");
  const t = chunks[cursor - 1] ? chunks[cursor - 1].t : 0;
  scrubber.value = t;
  clock.textContent = t.toFixed(2) + " / " + duration.toFixed(2);
}}
function play() {{
  clearTimers();
  speed = parseFloat(document.getElementById("speed").value || "1");
  const base = chunks[cursor] ? chunks[cursor].t : 0;
  for (let i = cursor; i < chunks.length; i++) {{
    timers.push(setTimeout(() => {{
      terminal.textContent += chunks[i].data;
      cursor = i + 1;
      scrubber.value = chunks[i].t;
      clock.textContent = chunks[i].t.toFixed(2) + " / " + duration.toFixed(2);
    }}, Math.max(0, (chunks[i].t - base) * 1000 / speed)));
  }}
}}
document.getElementById("play").onclick = play;
document.getElementById("pause").onclick = clearTimers;
document.getElementById("reset").onclick = () => {{ clearTimers(); renderUntil(0); }};
document.getElementById("plainToggle").onchange = (event) => {{
  clearTimers();
  terminal.textContent = event.target.checked ? document.getElementById("fallback").textContent : chunks.slice(0, cursor).map(c => c.data).join("");
}};
scrubber.oninput = () => {{
  clearTimers();
  const t = parseFloat(scrubber.value || "0");
  let index = chunks.findIndex(c => c.t > t);
  if (index < 0) index = chunks.length;
  renderUntil(index);
}};
fetch("/replay/{connection_id}.json").then(r => r.json()).then(data => {{
  chunks = data.chunks || [];
  duration = data.duration || (chunks.length ? chunks[chunks.length - 1].t : 0);
  scrubber.max = duration;
  clock.textContent = "0.00 / " + duration.toFixed(2);
  if (!chunks.length) {{ terminal.textContent = document.getElementById("fallback").textContent; }}
}});
</script>
""".format(connection_id=html.escape(str(connection_id)), plain=plain, default_speed=default_speed)
        if error:
            body = '<div class="notice warning">{}</div>'.format(html.escape(str(error))) + body
        return _html("Session Replay", body)

    @app.route("/grants")
    def grants():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        grant_rows = list_grant_records(redis)
        sets = list(load_project_sets(redis).values())
        body = "<h1>Grants</h1>" + _table(grant_rows, [
            ("id", "id"), ("subject", "subject"), ("name", "name"), ("project", "project"),
            ("project_set", "project_set"), ("project_glob", "project_glob"), ("remote_user", "remote_user"),
            ("sudo_mode", "sudo")
        ])
        body += "<h1>Project Sets</h1>" + _table(sets, [("name", "name"), ("projects", "projects"), ("project_globs", "globs")])
        return _html("Grants", body)

    @app.route("/raw/<user>/<connection_id>")
    def raw(user, connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        rows = read_history(
            config["logging"]["base_path"],
            admin,
            user=user,
            limit=200,
            admin_groups=config.get("dashboard", {}).get("admin_groups") or [],
        )
        for row in rows:
            if connection_id in (row.get("connection_id"), row.get("session_id")) and row.get("raw_log_path"):
                return send_file(row["raw_log_path"], mimetype="text/plain")
        abort(404)

    return app


def main():
    config = load_config()
    app = create_app(config)
    dashboard = config.get("dashboard", {})
    app.run(host=dashboard.get("listen_host", "127.0.0.1"), port=int(dashboard.get("listen_port", 8080)))


if __name__ == "__main__":
    main()
