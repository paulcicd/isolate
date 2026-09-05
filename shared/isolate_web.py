#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight Isolate admin dashboard."""

import html
import json
import os
import secrets
import time
import urllib.parse

from isolate import get_grant_record, list_grant_records, load_grants, load_project_sets, redis_client, update_grant_record
from isolate_audit import prepare_and_dispatch
from isolate_access import approve_access_request, deny_access_request, is_access_admin, list_access_requests, parse_duration, repeat_access_request, set_notification_status
from isolate_config import load_config
from isolate_history import list_user_profiles, read_history
from isolate_health import run_health_checks
from isolate_identity import normalize_claims
from isolate_inventory import HostValidationError, bulk_update_hosts, create_host, get_host, list_hosts, update_host
from isolate_notifications import NotificationError, notify_access_event
from isolate_replay import find_session, parse_raw_replay
from isolate_policy import PolicyDenied, resolve_grant
from isolate_policy_bundle import PolicyBundleError, apply_bundle, blast_radius, export_bundle, plan_bundle, validate_bundle
from isolate_gitops import GitOpsError, git_policy_status, list_policy_snapshots, rollback_policy, save_policy_snapshot, sync_git_policy
from isolate_sessions import SessionControlError, get_session, list_active_sessions, list_session_records, request_session_termination


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
<nav><a href="/">Summary</a><a href="/sessions/active">Active</a><a href="/history">History</a><a href="/inventory">Inventory</a><a href="/access">Access</a><a href="/grants">Grants</a><a href="/policy/simulate">Simulator</a><a href="/policy/gitops">GitOps</a><a href="/users">Users</a><a href="/notifications">Notifications</a><a href="/logout">Logout</a></nav>
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
            if key not in ("raw", "project_link", "history", "details", "replay", "live", "control", "user_link", "edit"):
                value = html.escape(str(value))
            cells.append("<td>{}</td>".format(value))
        body += "<tr>{}</tr>".format("".join(cells))
    return "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>".format(header, body)


def _split_values(value):
    return [item.strip() for item in str(value or "").replace("\n", ",").split(",") if item.strip()]


def _optional_bool(value):
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ValueError("boolean field must be true or false")


def _host_form_values(form, partial=False):
    mapping = {
        "project": "project_name",
        "name": "server_name",
        "ip": "server_ip",
        "port": "server_port",
        "user": "server_user",
        "services": "server_services",
        "note": "server_note",
        "privileged_provider": "privileged_access_provider",
        "privileged_url": "privileged_access_url",
        "privileged_hint": "privileged_access_hint",
        "proxy_id": "proxy_id",
    }
    result = {}
    for source, target in mapping.items():
        value = form.get(source)
        if value not in (None, "") or (not partial and source in form):
            result[target] = value
    for source, target in (("vip", "server_vip"), ("nosudo", "server_nosudo")):
        value = _optional_bool(form.get(source))
        if value is not None:
            result[target] = value
    return result


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
        if identity.get("exp") and int(identity["exp"]) <= int(time.time()):
            session.clear()
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

    def require_mutation_confirmation():
        if config.get("dashboard", {}).get("require_mutation_confirmation", True):
            if request.form.get("confirm") != "true":
                raise ValueError("explicit confirmation is required")

    def require_manual_policy_edit():
        if config.get("policy_as_code", {}).get("enforce_git", False):
            raise ValueError("manual policy editing is disabled because enforced GitOps is active")

    def audit_admin(action, admin, outcome, details=None):
        record = {
            "event": "dashboard_admin_action",
            "action": action,
            "username": admin.get("username"),
            "keycloak_sub": admin.get("keycloak_sub"),
            "outcome": outcome,
            "source": "isolate-dashboard",
        }
        record.update(details or {})
        prepare_and_dispatch(record, config.get("logging", {}))

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
        if not isinstance(claims, dict) or not claims:
            abort(401, description="Keycloak did not return verified OIDC claims")
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
        token = csrf_token()
        termination_enabled = config.get("session_control", {}).get("terminate_enabled", False)
        for row in rows:
            connection_id = html.escape(str(row.get("connection_id") or ""))
            username = str(row.get("username") or "")
            row["user_link"] = '<a href="/user/{}">{}</a>'.format(urllib.parse.quote(username, safe=""), html.escape(username))
            row["live"] = '<a href="/session/{}/live">live</a>'.format(connection_id)
            if termination_enabled:
                row["control"] = """
<form class="inline" method="post" action="/sessions/{connection_id}/terminate">
  <input type="hidden" name="csrf_token" value="{token}">
  <input type="hidden" name="confirm" value="true">
  <input name="reason" placeholder="reason" size="12">
  <button type="submit">Terminate</button>
</form>""".format(connection_id=connection_id, token=html.escape(token))
        return _html("Active Sessions", "<h1>Active Sessions</h1>" + _table(rows, [
            ("started_at", "started"), ("duration_seconds", "duration_s"), ("user_link", "user"),
            ("project", "project"), ("host_id", "host"), ("target_host", "target"),
            ("remote_user", "remote_user"), ("connection_id", "connection_id"), ("live", "view"), ("control", "control")
        ]), config=config)

    @app.route("/sessions/<connection_id>/terminate", methods=["POST"])
    def terminate_session(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        validate_csrf()
        if not config.get("session_control", {}).get("terminate_enabled", False):
            abort(403)
        try:
            require_mutation_confirmation()
            record = request_session_termination(
                redis_client(config), connection_id, admin, reason=request.form.get("reason") or None
            )
            audit_admin("session_terminate", admin, "requested", {"connection_id": connection_id})
        except (SessionControlError, ValueError) as exc:
            audit_admin("session_terminate", admin, "denied", {"connection_id": connection_id})
            return _html("Session Control", "<h1>Session Control</h1>", config=config, notice={"level": "error", "text": str(exc)}), 409
        return redirect(url_for("active_sessions"))

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
            username = str(row.get("username") or "")
            row["user_link"] = '<a href="/user/{}">{}</a>'.format(urllib.parse.quote(username, safe=""), html.escape(username))
            if connection_id:
                row["details"] = '<a href="/session/{}">details</a>'.format(html.escape(str(connection_id)))
            if row.get("raw_log_path"):
                row["raw"] = '<a href="/raw/{}/{}">raw</a>'.format(
                    urllib.parse.quote(str(row.get("username") or ""), safe=""),
                    urllib.parse.quote(str(row.get("connection_id") or row.get("session_id") or ""), safe=""),
                )
        return _html("History", "<h1>History</h1>" + _table(rows, [
            ("time", "time"), ("user_link", "user"), ("project", "project"), ("host_id", "host"),
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

    @app.route("/inventory", methods=["GET", "POST"])
    def inventory():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            try:
                require_mutation_confirmation()
                if action == "add":
                    host = create_host(redis, _host_form_values(request.form), updated_by=admin.get("username"))
                    notice = {"level": "info", "text": "Host {} added".format(host.get("server_id"))}
                    audit_admin("host_add", admin, "applied", {"host_id": host.get("server_id")})
                elif action == "bulk_update":
                    host_ids = _split_values(request.form.get("host_ids"))
                    if not host_ids or len(host_ids) > 200:
                        raise ValueError("between 1 and 200 host ids are required")
                    updates = _host_form_values(request.form, partial=True)
                    if not updates:
                        raise ValueError("at least one bulk update field is required")
                    bulk_update_hosts(redis, host_ids, updates, updated_by=admin.get("username"))
                    changed = [str(host_id) for host_id in host_ids]
                    notice = {"level": "info", "text": "Updated hosts: {}".format(", ".join(changed))}
                    audit_admin("host_bulk_update", admin, "applied", {"host_ids": changed, "count": len(changed)})
                else:
                    raise ValueError("unknown inventory action")
            except (HostValidationError, ValueError) as exc:
                audit_admin("inventory_mutation", admin, "denied", {"action": action})
                notice = {"level": "error", "text": str(exc)}
        project = request.args.get("project") or None
        query = request.args.get("q") or None
        rows = list_hosts(redis, project=project, query=query)
        for row in rows:
            row["project_link"] = '<a href="/history?project={}">{}</a>'.format(
                html.escape(str(row.get("project_name") or "")),
                html.escape(str(row.get("project_name") or "")),
            )
            row["history"] = '<a href="/history?host={}">history</a>'.format(html.escape(str(row.get("server_id") or "")))
            row["details"] = '<a href="/inventory/{}/edit">edit</a>'.format(html.escape(str(row.get("server_id") or "")))
        body = """
<h1>Inventory</h1>
<form method="get">
  <input name="project" value="{project}" placeholder="project">
  <input name="q" value="{query}" placeholder="search">
  <button type="submit">Search</button>
</form>
<h2>Add host</h2>
<form method="post" class="inline">
  <input type="hidden" name="csrf_token" value="{csrf}"><input type="hidden" name="action" value="add">
  <input name="project" placeholder="project" required><input name="name" placeholder="name" required>
  <input name="ip" placeholder="IP" required><input name="port" value="22" size="5">
  <input name="user" placeholder="remote user" required><input name="services" placeholder="services">
  <select name="vip"><option value="false">standard</option><option value="true">VIP</option></select>
  <label><input type="checkbox" name="confirm" value="true" required> confirm</label><button type="submit">Add</button>
</form>
<h2>Bulk update</h2>
<form method="post" class="inline">
  <input type="hidden" name="csrf_token" value="{csrf}"><input type="hidden" name="action" value="bulk_update">
  <input name="host_ids" placeholder="10001,10002" required><input name="project" placeholder="new project">
  <input name="user" placeholder="new remote user"><input name="services" placeholder="new services">
  <select name="vip"><option value="">keep VIP</option><option value="true">VIP</option><option value="false">not VIP</option></select>
  <label><input type="checkbox" name="confirm" value="true" required> confirm</label><button type="submit">Apply</button>
</form>
""".format(
            project=html.escape(project or ""),
            query=html.escape(query or ""),
            csrf=html.escape(csrf_token()),
        )
        body += _table(rows, [
            ("project_link", "project"), ("server_id", "id"), ("server_ip", "ip"), ("server_name", "name"),
            ("server_vip_marker", "vip"), ("server_user", "user"), ("server_services", "services"),
            ("server_note", "note"), ("privileged_access_provider", "privileged"), ("privileged_access_hint", "hint"),
            ("history", "history"), ("details", "edit")
        ])
        return _html("Inventory", body, config=config, notice=notice)

    @app.route("/inventory/<server_id>/edit", methods=["GET", "POST"])
    def inventory_edit(server_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            try:
                require_mutation_confirmation()
                host = update_host(
                    redis,
                    server_id,
                    _host_form_values(request.form),
                    updated_by=admin.get("username"),
                    expected_revision=request.form.get("revision") or None,
                )
                if host is None:
                    abort(404)
                audit_admin("host_update", admin, "applied", {"host_id": server_id})
                notice = {"level": "info", "text": "Host updated"}
            except (HostValidationError, ValueError) as exc:
                audit_admin("host_update", admin, "denied", {"host_id": server_id})
                notice = {"level": "error", "text": str(exc)}
        host = get_host(redis, server_id)
        if host is None:
            abort(404)
        body = """
<h1>Edit Host {server_id}</h1>
<form method="post">
<input type="hidden" name="csrf_token" value="{csrf}">
<input type="hidden" name="revision" value="{revision}">
<p>Project <input name="project" value="{project}" required> Name <input name="name" value="{name}" required></p>
<p>IP <input name="ip" value="{ip}" required> Port <input name="port" value="{port}" required> User <input name="user" value="{user}" required></p>
<p>Services <input name="services" value="{services}" size="60"></p>
<p>Note <input name="note" value="{note}" size="80"></p>
<p>VIP <select name="vip"><option value="false">false</option><option value="true" {vip_selected}>true</option></select>
No sudo <select name="nosudo"><option value="false">false</option><option value="true" {nosudo_selected}>true</option></select></p>
<p>Provider <input name="privileged_provider" value="{provider}"> URL <input name="privileged_url" value="{provider_url}" size="45"></p>
<p>Privileged hint <input name="privileged_hint" value="{provider_hint}" size="80"> Proxy ID <input name="proxy_id" value="{proxy_id}"></p>
<label><input type="checkbox" name="confirm" value="true" required> confirm update</label>
<button type="submit">Save</button>
</form>
""".format(
            server_id=html.escape(str(server_id)), csrf=html.escape(csrf_token()), revision=html.escape(str(host.get("_revision") or "")),
            project=html.escape(str(host.get("project_name") or "")), name=html.escape(str(host.get("server_name") or "")),
            ip=html.escape(str(host.get("server_ip") or "")), port=html.escape(str(host.get("server_port") or 22)),
            user=html.escape(str(host.get("server_user") or "")), services=html.escape(str(host.get("server_services") or "")),
            note=html.escape(str(host.get("server_note") or "")), vip_selected="selected" if host.get("server_vip") else "",
            nosudo_selected="selected" if host.get("server_nosudo") else "", provider=html.escape(str(host.get("privileged_access_provider") or "")),
            provider_url=html.escape(str(host.get("privileged_access_url") or "")), provider_hint=html.escape(str(host.get("privileged_access_hint") or "")),
            proxy_id=html.escape(str(host.get("proxy_id") or "")),
        )
        return _html("Edit Host", body, config=config, notice=notice)

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
        live_link = ""
        try:
            active_record = get_session(redis_client(config), connection_id)
        except Exception:
            active_record = None
        if active_record and active_record.get("status") == "active":
            live_link = '<a href="/session/{}/live">live</a>'.format(html.escape(str(connection_id)))
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
        body += "<p>{} {} {} {} <a href=\"/session/{}/events.json\">events.json</a></p>".format(raw_link, replay_link, replay_json_link, live_link, html.escape(str(connection_id)))
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

    @app.route("/session/<connection_id>/live.json")
    def session_live_json(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        active = get_session(redis, connection_id)
        details = find_session(config["logging"]["base_path"], connection_id)
        if details is None and active is None:
            abort(404)
        raw_path = (details or {}).get("raw_log_path")
        replay_data = parse_raw_replay(
            raw_path,
            max_bytes=int(config.get("session_control", {}).get("live_tail_bytes", 262144)),
            tail=True,
        )
        return jsonify({
            "active": bool(active and active.get("status") == "active"),
            "session": active or {},
            "duration": replay_data.get("duration"),
            "chunks": replay_data.get("chunks") or [],
            "plain": replay_data.get("plain") or "",
            "error": replay_data.get("error"),
        })

    @app.route("/session/<connection_id>/live")
    def session_live(connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        connection_id_safe = html.escape(str(connection_id))
        body = """
<h1>Live Session</h1>
<p><a href="/session/{connection_id}">details</a> <span id="state">loading</span></p>
<link rel="stylesheet" href="/static/vendor/xterm/xterm.css">
<div id="terminal" style="background:#111;padding:12px;height:70vh;"></div>
<script type="module">
import {{ Terminal }} from "/static/vendor/xterm/xterm.mjs";
const terminal = new Terminal({{rows: 50, cols: 180, scrollback: 5000, disableStdin: true, convertEol: false, theme: {{background: "#111111"}}}});
terminal.open(document.getElementById("terminal"));
async function refreshLive() {{
  const response = await fetch("/session/{connection_id}/live.json", {{cache: "no-store"}});
  if (!response.ok) {{ document.getElementById("state").textContent = "unavailable"; return; }}
  const data = await response.json();
  terminal.reset();
  terminal.write((data.chunks || []).map(chunk => chunk.data).join("") || data.plain || "");
  document.getElementById("state").textContent = data.active ? "active" : "completed";
  if (data.active) setTimeout(refreshLive, 2000);
}}
refreshLive();
</script>
""".format(connection_id=connection_id_safe)
        return _html("Live Session", body)

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
<link rel="stylesheet" href="/static/vendor/xterm/xterm.css">
<div id="terminal" class="terminal" style="background:#111;padding:12px;height:62vh;"></div>
<pre id="fallback" style="display:none;">{plain}</pre>
<script type="module">
import {{ Terminal }} from "/static/vendor/xterm/xterm.mjs";
let chunks = [];
let timers = [];
let speed = {default_speed};
let cursor = 0;
let duration = 0;
const terminalElement = document.getElementById("terminal");
const fallback = document.getElementById("fallback");
const emulator = new Terminal({{rows: 40, cols: 160, scrollback: 10000, disableStdin: true, convertEol: false, theme: {{background: "#111111"}}}});
emulator.open(terminalElement);
const scrubber = document.getElementById("scrubber");
const clock = document.getElementById("clock");
document.getElementById("speed").value = String(speed);
function clearTimers() {{ timers.forEach(clearTimeout); timers = []; }}
function renderUntil(index) {{
  cursor = Math.max(0, Math.min(index, chunks.length));
  emulator.reset();
  emulator.write(chunks.slice(0, cursor).map(c => c.data).join(""));
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
      emulator.write(chunks[i].data);
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
  terminalElement.style.display = event.target.checked ? "none" : "block";
  fallback.style.display = event.target.checked ? "block" : "none";
  if (!event.target.checked) renderUntil(cursor);
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
  if (!chunks.length) {{ terminalElement.style.display = "none"; fallback.style.display = "block"; }}
}});
</script>
""".format(connection_id=html.escape(str(connection_id)), plain=plain, default_speed=default_speed)
        if error:
            body = '<div class="notice warning">{}</div>'.format(html.escape(str(error))) + body
        return _html("Session Replay", body)

    @app.route("/policy/simulate", methods=["GET", "POST"])
    def policy_simulate():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        result = None
        values = request.form if request.method == "POST" else request.args
        if values.get("project") or values.get("host"):
            redis = redis_client(config)
            host_id = str(values.get("host") or "").strip() or None
            host = get_host(redis, host_id) if host_id else None
            project = str(values.get("project") or "").strip() or (host or {}).get("project_name")
            identity = {
                "username": str(values.get("user") or "policy-preview").strip(),
                "groups": _split_values(values.get("groups")),
                "roles": _split_values(values.get("roles")),
            }
            action = str(values.get("policy_action") or "ssh").strip()
            try:
                decision = resolve_grant(
                    identity, project=project, host=host, grants=load_grants(redis),
                    project_sets=load_project_sets(redis),
                    defaults={**config.get("policy", {}), **config.get("ssh", {})}, action=action,
                )
                result = {"allowed": True, "identity": identity, "project": project, "host": host, "action": action, "decision": decision}
            except PolicyDenied as exc:
                result = {"allowed": False, "identity": identity, "project": project, "host_id": host_id, "action": action, "reason": str(exc)}
        body = """
<h1>Policy Simulator</h1>
<form method="post" class="inline">
<input name="user" value="{user}" placeholder="username"><input name="groups" value="{groups}" placeholder="Group-A,Group-B">
<input name="roles" value="{roles}" placeholder="roles"><input name="project" value="{project}" placeholder="project">
<input name="host" value="{host}" placeholder="host id"><select name="policy_action"><option>ssh</option><option>runbook</option><option>operate</option><option>command</option></select>
<button type="submit">Simulate</button>
</form>
""".format(**{name: html.escape(str(values.get(name) or "")) for name in ("user", "groups", "roles", "project", "host")})
        if result is not None:
            decision = result.get("decision") or {}
            matched = decision.get("matched_rule") or {}
            summary = {
                "result": "ALLOWED" if result.get("allowed") else "DENIED",
                "reason": result.get("reason"),
                "grant_id": matched.get("id"),
                "remote_user": decision.get("remote_user"),
                "sudo_mode": decision.get("sudo_mode"),
                "allowed_actions": decision.get("allowed_actions"),
            }
            level = "info" if result.get("allowed") else "error"
            body += '<div class="notice {}"><strong>{}</strong></div>'.format(level, summary["result"])
            body += "<h2>Decision</h2><pre>{}</pre>".format(html.escape(json.dumps(summary, indent=2, sort_keys=True)))
            body += "<details><summary>Full evaluation</summary><pre>{}</pre></details>".format(html.escape(json.dumps(result, indent=2, sort_keys=True)))
        return _html("Policy Simulator", body, config=config)

    @app.route("/policy/gitops", methods=["GET", "POST"])
    def policy_gitops():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        cfg = config.get("policy_as_code", {}) or {}
        notice = None
        status = None
        if request.method == "POST":
            validate_csrf()
            try:
                require_mutation_confirmation()
                action = request.form.get("action")
                if action == "sync":
                    status = sync_git_policy(config, redis, dry_run=False, confirmed=True)
                    audit_admin("policy_git_sync", admin, "applied", {"commit": status.get("commit")})
                    notice = {"level": "info", "text": "Approved Git policy synchronized"}
                elif action == "rollback":
                    revision = request.form.get("revision")
                    status = rollback_policy(config, redis, revision, confirmed=True)
                    audit_admin("policy_rollback", admin, "applied", {"revision": revision})
                    notice = {"level": "warning", "text": "Policy rolled back; pause the sync timer if Git still contains the newer revision"}
                else:
                    raise ValueError("unknown GitOps action")
            except (GitOpsError, PolicyBundleError, OSError, ValueError) as exc:
                notice = {"level": "error", "text": str(exc)}
        elif cfg.get("enabled") and request.args.get("refresh") == "1":
            try:
                status = git_policy_status(config, redis)
            except (GitOpsError, PolicyBundleError, OSError, ValueError) as exc:
                notice = {"level": "error", "text": str(exc)}
        revisions = list_policy_snapshots(config)
        body = "<h1>Policy GitOps</h1><pre>{}</pre>".format(html.escape(json.dumps({
            "enabled": bool(cfg.get("enabled")), "enforce_git": bool(cfg.get("enforce_git")),
            "repository": cfg.get("repository"), "branch": cfg.get("branch"),
            "bundle": cfg.get("git_bundle_path"), "approval_required": True,
        }, indent=2, sort_keys=True)))
        body += '<p><a href="/policy/gitops?refresh=1">Fetch status, drift and blast radius</a></p>'
        if status is not None:
            body += "<h2>Result</h2><pre>{}</pre>".format(html.escape(json.dumps(status, indent=2, sort_keys=True)))
        token = html.escape(csrf_token())
        if cfg.get("enabled"):
            body += '<form method="post" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="action" value="sync"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Sync approved revision</button></form>'.format(token)
        body += "<h2>Rollback revisions</h2>" + _table(revisions, [("revision_id", "revision"), ("created_at", "created"), ("source", "source")])
        body += '<form method="post" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="action" value="rollback"><input name="revision" placeholder="revision id" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Rollback</button></form>'.format(token)
        return _html("Policy GitOps", body, config=config, notice=notice)

    @app.route("/users")
    def users():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        profiles = list_user_profiles(config["logging"]["base_path"])
        active_users = {row.get("username") for row in list_active_sessions(redis_client(config))}
        for profile in profiles:
            username = str(profile.get("username") or "")
            profile["user_link"] = '<a href="/user/{}">{}</a>'.format(urllib.parse.quote(username, safe=""), html.escape(username))
            profile["active"] = "yes" if username in active_users else ""
            profile["groups_display"] = ", ".join(profile.get("groups") or [])
        return _html("Users", "<h1>Users</h1>" + _table(profiles, [
            ("user_link", "user"), ("groups_display", "groups"), ("last_seen", "last_seen"),
            ("connection_count", "connections"), ("active", "active"),
        ]), config=config)

    @app.route("/user/<username>")
    def user_details(username):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        profiles = {row["username"]: row for row in list_user_profiles(config["logging"]["base_path"])}
        profile = profiles.get(username, {"username": username, "groups": [], "roles": []})
        redis = redis_client(config)
        active = [row for row in list_active_sessions(redis) if row.get("username") == username]
        history_rows = read_history(
            config["logging"]["base_path"], admin, user=username, limit=200,
            admin_groups=config.get("dashboard", {}).get("admin_groups") or [],
        )
        subjects = {("user", username)}
        subjects.update(("group", group) for group in profile.get("groups") or [])
        subjects.update(("role", role) for role in profile.get("roles") or [])
        grants = [row for row in list_grant_records(redis) if (row.get("subject"), row.get("name")) in subjects]
        body = "<h1>User {}</h1><pre>{}</pre>".format(html.escape(username), html.escape(json.dumps(profile, indent=2, sort_keys=True)))
        body += "<h2>Effective grant candidates</h2>" + _table(grants, [
            ("id", "id"), ("subject", "subject"), ("name", "name"), ("project", "project"),
            ("project_set", "project_set"), ("project_glob", "glob"), ("host", "host"),
            ("remote_user", "remote_user"), ("sudo_mode", "sudo"), ("allowed_actions", "actions"),
        ])
        body += "<h2>Active sessions</h2>" + _table(active, [
            ("started_at", "started"), ("project", "project"), ("host_id", "host"), ("remote_user", "remote_user"),
        ])
        body += "<h2>Recent sessions</h2>" + _table(history_rows, [
            ("time", "time"), ("project", "project"), ("host_id", "host"), ("target", "target"),
            ("remote_user", "remote_user"), ("result", "result"),
        ])
        return _html("User Details", body, config=config)

    @app.route("/notifications")
    def notification_status():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        sinks = []
        for index, sink in enumerate(config.get("notifications", {}).get("sinks") or []):
            sinks.append({"index": index, "type": sink.get("type"), "configured": "yes"})
        deliveries = []
        for record in list_access_requests(redis_client(config)):
            status = record.get("notification_status") or {}
            deliveries.append({
                "request_id": record.get("id"), "status": record.get("status"), "requester": record.get("requester"),
                "ok": status.get("ok"), "sent": ", ".join(str(item.get("type")) for item in status.get("sent") or []),
                "errors": "; ".join(status.get("errors") or []), "updated_at": status.get("updated_at"),
            })
        session_deliveries = []
        for record in list_session_records(redis_client(config)):
            for delivery in record.get("alert_deliveries") or []:
                session_deliveries.append({
                    "connection_id": record.get("connection_id"), "alert": delivery.get("alert"),
                    "user": record.get("username"), "ok": delivery.get("ok"),
                    "sent": ", ".join(str(item.get("type")) for item in delivery.get("sent") or []),
                    "errors": "; ".join(delivery.get("errors") or []), "updated_at": delivery.get("ts"),
                })
        body = "<h1>Notification Delivery</h1><h2>Configured sinks</h2>" + _table(sinks, [("index", "#"), ("type", "type"), ("configured", "configured")])
        body += "<h2>Access request delivery status</h2>" + _table(deliveries, [
            ("request_id", "request"), ("status", "status"), ("requester", "requester"),
            ("ok", "ok"), ("sent", "sent"), ("errors", "errors"), ("updated_at", "updated"),
        ])
        body += "<h2>Session alert delivery status</h2>" + _table(session_deliveries, [
            ("connection_id", "connection"), ("alert", "alert"), ("user", "user"),
            ("ok", "ok"), ("sent", "sent"), ("errors", "errors"), ("updated_at", "updated"),
        ])
        return _html("Notifications", body, config=config)

    @app.route("/grants", methods=["GET", "POST"])
    def grants():
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        redis = redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            try:
                require_mutation_confirmation()
                require_manual_policy_edit()
                bundle = export_bundle(redis)
                if action == "grant_save":
                    grant_id = str(request.form.get("id") or "").strip() or None
                    selector_type = request.form.get("selector_type")
                    selector_value = str(request.form.get("selector_value") or "").strip()
                    if selector_type not in ("project", "project_glob", "project_set") or not selector_value:
                        raise ValueError("one project selector is required")
                    grant = {
                        "schema_version": 2,
                        "subject": request.form.get("subject"),
                        "name": str(request.form.get("name") or "").strip(),
                        selector_type: selector_value,
                        "host": str(request.form.get("host") or "").strip() or None,
                        "remote_user": str(request.form.get("remote_user") or "").strip(),
                        "sudo_mode": request.form.get("sudo_mode") or "none",
                        "allowed_actions": _split_values(request.form.get("allowed_actions")) or ["ssh"],
                    }
                    if grant_id:
                        grant["id"] = grant_id
                        replaced = False
                        for index, current in enumerate(bundle["grants"]):
                            if str(current.get("id")) == grant_id:
                                bundle["grants"][index] = grant
                                replaced = True
                                break
                        if not replaced:
                            raise ValueError("grant not found: {}".format(grant_id))
                    else:
                        bundle["grants"].append(grant)
                elif action == "grant_remove":
                    grant_id = str(request.form.get("id") or "").strip()
                    before = len(bundle["grants"])
                    bundle["grants"] = [row for row in bundle["grants"] if str(row.get("id")) != grant_id]
                    if len(bundle["grants"]) == before:
                        raise ValueError("grant not found: {}".format(grant_id))
                elif action == "grant_bulk_action":
                    grant_ids = set(_split_values(request.form.get("ids")))
                    selected_action = str(request.form.get("allowed_action") or "").strip()
                    mode = request.form.get("mode")
                    if not grant_ids or not selected_action or mode not in ("add", "remove"):
                        raise ValueError("grant ids, action, and mode are required")
                    matched = set()
                    for grant in bundle["grants"]:
                        if str(grant.get("id")) not in grant_ids:
                            continue
                        matched.add(str(grant.get("id")))
                        actions = set(grant.get("allowed_actions") or ["ssh"])
                        if mode == "add":
                            actions.add(selected_action)
                        else:
                            actions.discard(selected_action)
                        grant["allowed_actions"] = sorted(actions)
                    if matched != grant_ids:
                        raise ValueError("one or more grant ids were not found")
                elif action == "project_set_save":
                    name = str(request.form.get("name") or "").strip()
                    if not name:
                        raise ValueError("project set name is required")
                    record = {
                        "schema_version": 2,
                        "name": name,
                        "projects": sorted(set(_split_values(request.form.get("projects")))),
                        "project_globs": sorted(set(_split_values(request.form.get("project_globs")))),
                    }
                    bundle["project_sets"] = [row for row in bundle["project_sets"] if row.get("name") != name]
                    bundle["project_sets"].append(record)
                elif action == "project_set_remove":
                    name = str(request.form.get("name") or "").strip()
                    bundle["project_sets"] = [row for row in bundle["project_sets"] if row.get("name") != name]
                elif action == "project_set_bulk_members":
                    names = set(_split_values(request.form.get("names")))
                    values = set(_split_values(request.form.get("values")))
                    member_type = request.form.get("member_type")
                    mode = request.form.get("mode")
                    if not names or not values or member_type not in ("projects", "project_globs") or mode not in ("add", "remove"):
                        raise ValueError("set names, values, member type, and mode are required")
                    matched = set()
                    for project_set in bundle["project_sets"]:
                        if project_set.get("name") not in names:
                            continue
                        matched.add(project_set["name"])
                        members = set(project_set.get(member_type) or [])
                        members = members | values if mode == "add" else members - values
                        project_set[member_type] = sorted(members)
                    if matched != names:
                        raise ValueError("one or more project sets were not found")
                else:
                    raise ValueError("unknown policy action")
                validation = validate_bundle(bundle)
                if not validation["valid"]:
                    raise PolicyBundleError("; ".join(validation["errors"]))
                changes = plan_bundle(redis, bundle, prune=True)
                save_policy_snapshot(config, redis, source="dashboard:{}".format(action))
                apply_bundle(redis, bundle, prune=True)
                audit_admin(action, admin, "applied", {"change_count": sum(len(rows) for rows in changes.values())})
                notice = {"level": "info", "text": "Policy updated"}
            except (ValueError, PolicyBundleError, OSError) as exc:
                audit_admin(action or "policy_mutation", admin, "denied")
                notice = {"level": "error", "text": str(exc)}
        grant_rows = list_grant_records(redis)
        sets = list(load_project_sets(redis).values())
        edit_grant = get_grant_record(redis, request.args.get("edit_grant")) if request.args.get("edit_grant") else None
        edit_set = next((row for row in sets if row.get("name") == request.args.get("edit_set")), None)
        for row in grant_rows:
            row["edit"] = '<a href="/grants?edit_grant={}">edit</a>'.format(urllib.parse.quote(str(row.get("id") or ""), safe=""))
        for row in sets:
            row["edit"] = '<a href="/grants?edit_set={}">edit</a>'.format(urllib.parse.quote(str(row.get("name") or ""), safe=""))
        token = html.escape(csrf_token())
        edit_grant = edit_grant or {}
        edit_selector = next((name for name in ("project", "project_set", "project_glob") if edit_grant.get(name) is not None), "project")
        grant_form = {
            "id": html.escape(str(edit_grant.get("id") or "")),
            "name": html.escape(str(edit_grant.get("name") or "")),
            "selector": html.escape(str(edit_grant.get(edit_selector) or "")),
            "host": html.escape(str(edit_grant.get("host") or "")),
            "remote_user": html.escape(str(edit_grant.get("remote_user") or "")),
            "actions": html.escape(", ".join(edit_grant.get("allowed_actions") or ["ssh"])),
        }
        def selected(value, expected):
            return " selected" if value == expected else ""
        git_notice = "<p><strong>Enforced GitOps:</strong> policy is read-only here.</p>" if config.get("policy_as_code", {}).get("enforce_git", False) else ""
        body = "<h1>Grants</h1>" + git_notice + _table(grant_rows, [
            ("id", "id"), ("subject", "subject"), ("name", "name"), ("project", "project"),
            ("project_set", "project_set"), ("project_glob", "project_glob"), ("remote_user", "remote_user"),
            ("sudo_mode", "sudo"), ("allowed_actions", "actions"), ("edit", "edit")
        ])
        body += """
<h2>Add or replace grant</h2>
<form method="post" class="inline">
<input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="grant_save">
<input name="id" value="{id}" placeholder="id for update" size="8"><select name="subject"><option{subject_group}>group</option><option{subject_user}>user</option><option{subject_role}>role</option></select>
<input name="name" value="{name}" placeholder="subject name" required><select name="selector_type"><option{selector_project}>project</option><option{selector_set}>project_set</option><option{selector_glob}>project_glob</option></select>
<input name="selector_value" value="{selector}" placeholder="selector" required><input name="host" value="{host}" placeholder="optional host" size="10">
<input name="remote_user" value="{remote_user}" placeholder="remote user" required><select name="sudo_mode"><option{sudo_none}>none</option><option{sudo_i}>sudo-i</option></select>
<input name="allowed_actions" value="{actions}" placeholder="ssh,runbook"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Save</button>
</form>
<h2>Remove grant</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="grant_remove"><input name="id" placeholder="grant id" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Remove</button></form>
<h2>Bulk grant action</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="grant_bulk_action"><input name="ids" placeholder="1,2,3" required><select name="mode"><option>add</option><option>remove</option></select><input name="allowed_action" placeholder="runbook" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Apply</button></form>
""".format(
            token=token, **grant_form,
            subject_group=selected(edit_grant.get("subject") or "group", "group"),
            subject_user=selected(edit_grant.get("subject"), "user"), subject_role=selected(edit_grant.get("subject"), "role"),
            selector_project=selected(edit_selector, "project"), selector_set=selected(edit_selector, "project_set"),
            selector_glob=selected(edit_selector, "project_glob"), sudo_none=selected(edit_grant.get("sudo_mode") or "none", "none"),
            sudo_i=selected(edit_grant.get("sudo_mode"), "sudo-i"),
        )
        body += "<h1>Project Sets</h1>" + _table(sets, [("name", "name"), ("projects", "projects"), ("project_globs", "globs"), ("edit", "edit")])
        edit_set = edit_set or {}
        body += """
<h2>Add or replace project set</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="project_set_save"><input name="name" value="{set_name}" placeholder="name" required><input name="projects" value="{projects}" placeholder="prod-a,prod-b"><input name="project_globs" value="{globs}" placeholder="*-prod"><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Save</button></form>
<h2>Remove project set</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="project_set_remove"><input name="name" placeholder="name" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Remove</button></form>
<h2>Bulk project-set members</h2><form method="post" class="inline"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="project_set_bulk_members"><input name="names" placeholder="set-a,set-b" required><select name="member_type"><option>projects</option><option>project_globs</option></select><select name="mode"><option>add</option><option>remove</option></select><input name="values" placeholder="project-a,*-prod" required><label><input type="checkbox" name="confirm" value="true" required> confirm</label><button>Apply</button></form>
""".format(
            token=token, set_name=html.escape(str(edit_set.get("name") or "")),
            projects=html.escape(", ".join(edit_set.get("projects") or [])),
            globs=html.escape(", ".join(edit_set.get("project_globs") or [])),
        )
        return _html("Grants", body, config=config, notice=notice)

    @app.route("/raw/<user>/<connection_id>")
    def raw(user, connection_id):
        admin = require_admin()
        if not isinstance(admin, dict):
            return admin
        details = find_session(config["logging"]["base_path"], connection_id)
        summary = (details or {}).get("summary") or {}
        if details and str(summary.get("username") or "") == str(user) and details.get("raw_log_path"):
            return send_file(details["raw_log_path"], mimetype="text/plain")
        abort(404)

    return app


def main():
    config = load_config()
    app = create_app(config)
    dashboard = config.get("dashboard", {})
    app.run(host=dashboard.get("listen_host", "127.0.0.1"), port=int(dashboard.get("listen_port", 8080)))


if __name__ == "__main__":
    main()
