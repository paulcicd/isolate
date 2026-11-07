"""Owner-scoped dashboard routes for verified Keycloak users."""

import html
import re
import time
import urllib.parse

from isolate_access import (
    AccessDenied, cancel_access_request, comment_access_request, create_access_request,
    get_access_request, list_access_requests, owns_access_request, renew_access_request,
)
from isolate_exports import ExportError, render_export
from isolate_history import read_history
from isolate_inventory import HostValidationError, get_host, list_hosts
from isolate_connectivity import get_last_check
from isolate_permissions import has_permission
from isolate_policy import PolicyDenied, resolve_grant
from isolate_sessions import list_active_sessions


_WORDS = {
    "en": {
        "my_servers": "My servers", "my_sessions": "My sessions", "my_history": "My history",
        "my_requests": "My requests", "search": "Search", "project": "Project", "host": "Host",
        "user": "User", "tags": "Tags", "filter": "Filter", "server": "Server", "address": "Address",
        "services": "Services", "state": "State", "connect": "Connect", "connection": "Connection",
        "remote_user": "Remote user", "duration": "Duration (s)", "status": "Status", "result": "Result",
        "limit": "Limit", "all_results": "All results", "success": "Success", "failure": "Failure",
        "started": "Started", "selected": "Selected", "from": "From (UTC date / ISO with timezone)",
        "until": "To (UTC date / ISO with timezone)", "time": "Time (server timezone)",
        "servers_help": "Servers available to your current identity. Connect from the bastion using the command shown.",
        "request_temporary_access": "Request temporary access", "request_access": "Request access",
        "request_updated": "Request updated", "confirm": "Confirm", "host_optional": "Host ID (optional)",
        "reason": "Reason", "ticket": "Ticket", "start": "Start", "end": "End",
        "start_utc": "Start (UTC)", "end_utc": "End (UTC)",
        "window_help": "Optional window: ISO 8601 with a timezone, or Unix timestamps. Empty start means immediate access after approval.",
        "comment": "Comment", "cancel": "Cancel", "renew": "Request renewal", "renews": "Renews",
        "comments": "Comments", "actions": "Actions", "start_placeholder": "start with timezone",
        "end_placeholder": "end with timezone", "empty": "No records",
        "owner": "Owner", "environment": "Environment", "details": "Details", "availability": "Availability",
        "unknown": "Unknown", "reachable": "Reachable (cached)", "unreachable": "Unreachable (cached)",
        "stale": "Check expired", "checked": "Last check (UTC)", "ssh_access": "SSH access",
        "allowed": "Allowed", "not_allowed": "No SSH permission", "expires": "Current authorization until (UTC)",
        "permanent": "No grant expiration", "copy_command": "Copy command", "copied": "Copied",
        "connection_help": "Log in to the bastion, run isolate login, then use this command. Current policy and session approval requirements are checked when connecting.",
        "maintenance": "Maintenance", "ready": "Available", "port": "SSH port", "note": "Notes",
        "catalogue_help": "Browse your resources, check their owners and access windows, and copy connection instructions.",
        "inventory_only": "This project role allows inventory viewing. SSH access requires a separate grant.",
        "discovery_checked": "Services scanned (UTC)", "discovery_failed": "The latest service scan failed; the last successful snapshot is shown.",
        "back_catalogue": "Back to resources", "request_for_resource": "Request access to this resource",
    },
    "ru": {
        "my_servers": "Мои серверы", "my_sessions": "Мои сессии", "my_history": "Моя история",
        "my_requests": "Мои заявки", "search": "Поиск", "project": "Проект", "host": "Сервер",
        "user": "Пользователь", "tags": "Теги", "filter": "Применить", "server": "Имя сервера", "address": "Адрес",
        "services": "Сервисы", "state": "Состояние", "connect": "Подключение", "connection": "Подключение",
        "remote_user": "Учётная запись SSH", "duration": "Длительность (с)", "status": "Статус", "result": "Результат",
        "limit": "Лимит", "all_results": "Все результаты", "success": "Успешно", "failure": "Ошибка",
        "started": "Запущено", "selected": "Выбрано", "from": "С (дата UTC / ISO с часовым поясом)",
        "until": "По (дата UTC / ISO с часовым поясом)", "time": "Время (часовой пояс сервера)",
        "servers_help": "Серверы, доступные вашей учётной записи. Для подключения выполните указанную команду на бастионе.",
        "request_temporary_access": "Запросить временный доступ", "request_access": "Запросить доступ",
        "request_updated": "Заявка сохранена", "confirm": "Подтвердить", "host_optional": "ID сервера (необязательно)",
        "reason": "Причина", "ticket": "Тикет", "start": "Начало", "end": "Окончание",
        "start_utc": "Начало (UTC)", "end_utc": "Окончание (UTC)",
        "window_help": "Необязательное окно: ISO 8601 с часовым поясом или Unix timestamp. Пустое начало означает доступ сразу после одобрения.",
        "comment": "Комментарий", "cancel": "Отменить", "renew": "Запросить продление", "renews": "Продлевает",
        "comments": "Комментарии", "actions": "Действия", "start_placeholder": "начало с часовым поясом",
        "end_placeholder": "окончание с часовым поясом", "empty": "Нет записей",
        "owner": "Владелец", "environment": "Окружение", "details": "Подробнее", "availability": "Доступность",
        "unknown": "Неизвестно", "reachable": "Доступен (кэш)", "unreachable": "Недоступен (кэш)",
        "stale": "Проверка устарела", "checked": "Последняя проверка (UTC)", "ssh_access": "SSH-доступ",
        "allowed": "Разрешён", "not_allowed": "Нет разрешения SSH", "expires": "Текущая авторизация до (UTC)",
        "permanent": "Грант без срока окончания", "copy_command": "Копировать команду", "copied": "Скопировано",
        "connection_help": "Войдите на бастион, выполните isolate login и используйте эту команду. При подключении проверяются текущие права и требования согласования сессии.",
        "maintenance": "Обслуживание", "ready": "Доступен", "port": "SSH-порт", "note": "Примечания",
        "catalogue_help": "Просматривайте ресурсы, их владельцев и сроки доступа; копируйте команды подключения.",
        "inventory_only": "Проектная роль разрешает просмотр инвентаря. Для SSH требуется отдельный грант.",
        "discovery_checked": "Сервисы просканированы (UTC)", "discovery_failed": "Последнее сканирование сервисов завершилось ошибкой; показан последний успешный снимок.",
        "back_catalogue": "Назад к ресурсам", "request_for_resource": "Запросить доступ к ресурсу",
    },
}


_CATALOGUE_STYLE = """<style>
.resource-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 340px), 1fr)); gap: 16px; margin: 18px 0; }
.resource-card { padding: 20px; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); min-width: 0; }
.resource-card h2 { margin: 0 0 4px; font-size: 18px; overflow-wrap: anywhere; }
.resource-card .resource-project { color: var(--muted); font-size: 12px; margin-bottom: 14px; }
.resource-metadata { display: grid; grid-template-columns: minmax(110px, 36%) minmax(0, 1fr); gap: 6px 12px; margin: 12px 0; }
.resource-metadata dt { color: var(--muted); }.resource-metadata dd { margin: 0; overflow-wrap: anywhere; }
.resource-tags { display: flex; gap: 5px; flex-wrap: wrap; margin: 12px 0; }.resource-tags span { padding: 3px 7px; font-size: 11px; background: var(--surface-muted); border-radius: 4px; overflow-wrap: anywhere; }
.resource-command { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 12px 0; }.resource-command code { padding: 8px 10px; background: var(--surface-muted); border-radius: 4px; }
.resource-actions { display: flex; flex-wrap: wrap; gap: 14px; align-items: center; margin-top: 14px; }
.resource-status { font-size: 12px; color: var(--muted); }.resource-status[data-available="true"] { color: var(--positive); }
</style>"""


def _words(locale):
    return _WORDS.get(locale, _WORDS["en"])


def history_filters(args, include_user=True):
    """Share exactly the same validated filters between tables and downloads."""
    result = {key: args.get(key) or None for key in ("project", "host", "since", "until", "result")}
    result["query"] = args.get("q") or None
    result["limit"] = min(max(int(args.get("limit", 50)), 1), 1000)
    if include_user:
        result["user"] = args.get("user") or None
    return result


def history_form(args, include_user=True, locale="en"):
    words = _words(locale)
    fields = [("q", words["search"]), ("project", words["project"]), ("host", words["host"])]
    if include_user:
        fields.insert(1, ("user", words["user"]))
    fields += [("since", words["from"]), ("until", words["until"])]
    inputs = "".join('<label>{label} <input name="{name}" value="{value}"></label>'.format(
        label=label, name=name, value=html.escape(args.get(name) or "", quote=True)) for name, label in fields)
    options = "".join('<option value="{0}"{1}>{2}</option>'.format(
        value, ' selected' if args.get("result", "") == value else "", label
    ) for value, label in (("", words["all_results"]), ("success", words["success"]), ("failure", words["failure"]), ("started", words["started"]), ("selected", words["selected"])))
    return '<form method="get" class="inline">{inputs}<label>{result} <select name="result">{options}</select></label><label>{limit} <input type="number" min="1" max="1000" name="limit" value="{value}"></label><button>{filter}</button></form>'.format(
        inputs=inputs, options=options, value=html.escape(str(args.get("limit", 50)), quote=True), **words)


def register_self_service(app, config, current_identity, csrf_token, validate_csrf, notify, audit):
    from flask import Response, abort, redirect, request
    import isolate_web as web

    def words():
        return _words(web._dashboard_locale(config))

    def table(rows, columns):
        return web._table(rows, columns) if rows else '<div class="empty-state">{empty}</div>'.format(**words())

    def require_user():
        identity = current_identity()
        if identity is None:
            return redirect("/login")
        if not (web.is_dashboard_admin(identity, config) or web.is_self_service_user(identity, config)
                or has_permission(identity, config, "inventory.read")):
            abort(403)
        return identity

    def page(title, body, notice=None):
        # Form pages must not reload and discard an unfinished request.
        page_config = dict(config, dashboard=dict(config.get("dashboard", {}), refresh_seconds=0))
        return web._html(title, body, config=page_config, notice=notice)

    def owns_session(record, identity):
        if record.get("keycloak_sub"):
            return record.get("keycloak_sub") == identity.get("keycloak_sub")
        return record.get("username") == identity.get("username")

    def resource_access(redis, identity, host, grants=None, project_sets=None):
        try:
            decision = resolve_grant(identity, project=host.get("project_name"), host=host,
                grants=web.load_grants(redis) if grants is None else grants,
                project_sets=web.load_project_sets(redis) if project_sets is None else project_sets,
                defaults={**config.get("policy", {}), **config.get("ssh", {})})
        except PolicyDenied:
            decision = None
        visible = decision is not None or has_permission(identity, config, "inventory.read", project=host.get("project_name"))
        return visible, decision

    def resource_health(redis, host):
        cached = get_last_check(redis, host["server_id"])
        if not cached or cached.get("address") != host.get("server_ip") or int(cached.get("port") or 22) != int(host.get("server_port") or 22):
            return "unknown", None
        if cached.get("project") and cached["project"] != host.get("project_name"):
            return "unknown", None
        checked_at = cached.get("checked_at")
        if not checked_at or int(checked_at) + int(config.get("connectivity", {}).get("result_ttl", 3600)) <= int(time.time()):
            return "stale", checked_at
        return ("reachable" if cached.get("ok") else "unreachable"), checked_at

    def resource_metadata(redis, identity, host, decision, labels):
        health, checked_at = resource_health(redis, host)
        items = [(labels["owner"], host.get("resource_owner") or "—"),
                 (labels["environment"], host.get("environment") or "—"),
                 (labels["availability"], labels[health]),
                 (labels["checked"], web._format_access_time(checked_at) or "—"),
                 (labels["state"], labels["maintenance"] if host.get("maintenance_active") else labels["ready"]),
                 (labels["ssh_access"], labels["allowed"] if decision else labels["not_allowed"])]
        if decision:
            grant = decision.get("matched_rule") or {}
            ends = [int(value) for value in (grant.get("expires_at"), identity.get("exp")) if value]
            items += [(labels["remote_user"], decision.get("remote_user") or "—"),
                      ("Sudo", decision.get("sudo_mode") or "none"),
                      (labels["expires"], web._format_access_time(min(ends)) if ends else labels["permanent"])]
        return '<dl class="resource-metadata">{}</dl>'.format("".join('<dt>{}</dt><dd>{}</dd>'.format(html.escape(str(key)), html.escape(str(value))) for key, value in items))

    def connection_command(host, labels):
        command = "g {}".format(host["server_id"])
        result = '<div class="resource-command"><code>{}</code><button type="button" data-copy-command="{}" data-copied-label="{}">{}</button></div>'.format(
            html.escape(command), html.escape(command, quote=True), html.escape(labels["copied"], quote=True), html.escape(labels["copy_command"]))
        if config.get("api", {}).get("enabled") and config.get("gateway", {}).get("enabled"):
            result += '<a class="button" href="/me/terminal/{}">Web SSH</a>'.format(urllib.parse.quote(str(host["server_id"]), safe=""))
        return result

    def copy_script():
        return """<script>document.querySelectorAll('[data-copy-command]').forEach(function(button) {
button.addEventListener('click', function() { if (navigator.clipboard) navigator.clipboard.writeText(button.dataset.copyCommand).then(function() { button.textContent = button.dataset.copiedLabel; }).catch(function() {}); });
});</script>"""

    @app.route("/me")
    def my_workspace():
        identity = require_user()
        if not isinstance(identity, dict):
            return identity
        redis = web.redis_client(config)
        try:
            candidates = list_hosts(redis, project=request.args.get("project") or None,
                                    query=request.args.get("q") or None, tags=request.args.get("tags") or None)
        except HostValidationError as exc:
            abort(400, description=str(exc))
        grants, project_sets = web.load_grants(redis), web.load_project_sets(redis)
        hosts = []
        for host in candidates:
            visible, decision = resource_access(redis, identity, host, grants, project_sets)
            if visible:
                hosts.append((host, decision))
        labels = words()
        body = _CATALOGUE_STYLE + '<h1>{my_servers}</h1><p>{catalogue_help}</p>'.format(**labels)
        body += '<form class="inline" method="get"><label>{search} <input name="q" value="{query_value}"></label><label>{project} <input name="project" value="{project_value}"></label><label>{tags} <input name="tags" placeholder="env=prod,owner=payments" value="{tags_value}"></label><button>{filter}</button></form>'.format(
            query_value=html.escape(request.args.get("q") or "", quote=True),
            project_value=html.escape(request.args.get("project") or "", quote=True),
            tags_value=html.escape(request.args.get("tags") or "", quote=True), **labels)
        body += '<div class="resource-grid">'
        for host, decision in hosts:
            href = "/me/resources/" + urllib.parse.quote(str(host["server_id"]), safe="")
            body += '<article class="resource-card"><h2><a href="{}">{}</a></h2><div class="resource-project">{} · #{}</div>'.format(
                href, html.escape(host["server_name"]), html.escape(host["project_name"]), html.escape(host["server_id"]))
            body += resource_metadata(redis, identity, host, decision, labels)
            body += '<p><strong>{}</strong>: {}</p>'.format(html.escape(labels["services"]), html.escape(host.get("server_services_display") or "—"))
            body += '<div class="resource-tags">{}</div>'.format("".join('<span>{}={}</span>'.format(html.escape(key), html.escape(value)) for key, value in host.get("tags", {}).items()))
            if decision:
                body += connection_command(host, labels)
            body += '<div class="resource-actions"><a href="{}">{}</a></div></article>'.format(href, html.escape(labels["details"]))
        body += '</div>'
        if not hosts:
            body += '<div class="empty-state">{empty}</div>'.format(**labels)
        body += '<p><a href="/me/access">{request_temporary_access}</a></p>'.format(**labels)
        body += copy_script()
        return page(labels["my_servers"], body)

    @app.route("/me/resources/<server_id>")
    def my_resource(server_id):
        identity = require_user()
        if not isinstance(identity, dict):
            return identity
        if re.fullmatch(r"[0-9]{1,20}", server_id) is None:
            abort(404)
        redis = web.redis_client(config)
        host = get_host(redis, server_id)
        if host is None:
            abort(404)
        visible, decision = resource_access(redis, identity, host)
        if not visible:
            abort(404)
        labels = words()
        body = _CATALOGUE_STYLE + '<p><a href="/me">{}</a></p><h1>{}</h1><p>{} · #{}</p>'.format(
            html.escape(labels["back_catalogue"]), html.escape(host["server_name"]), html.escape(host["project_name"]), html.escape(host["server_id"]))
        body += '<div class="resource-card">' + resource_metadata(redis, identity, host, decision, labels)
        body += '<dl class="resource-metadata">{}</dl>'.format("".join('<dt>{}</dt><dd>{}</dd>'.format(html.escape(str(key)), html.escape(str(value))) for key, value in (
            (labels["address"], host["server_ip"]), (labels["port"], host.get("server_port") or 22),
            (labels["services"], host.get("server_services_display") or "—"), (labels["note"], host.get("server_note") or "—"),
            (labels["tags"], host.get("tags_display") or "—"))))
        snapshot = host.get("service_discovery") or {}
        if snapshot.get("checked_at"):
            body += '<p>{}: {}</p>'.format(html.escape(labels["discovery_checked"]), html.escape(web._format_access_time(snapshot["checked_at"])))
        if snapshot and not snapshot.get("ok"):
            body += '<p class="muted">{}</p>'.format(html.escape(labels["discovery_failed"]))
        if decision:
            body += '<h2>{}</h2><p>{}</p>'.format(html.escape(labels["connect"]), html.escape(labels["connection_help"])) + connection_command(host, labels)
        else:
            body += '<p>{}</p>'.format(html.escape(labels["inventory_only"]))
        prefill = urllib.parse.urlencode({"project": host["project_name"], "host": host["server_id"]})
        body += '<p><a href="/me/access?{}">{}</a></p></div>'.format(html.escape(prefill, quote=True), html.escape(labels["request_for_resource"]))
        body += copy_script()
        return page(host["server_name"], body)

    @app.route("/me/sessions")
    def my_sessions():
        identity = require_user()
        if not isinstance(identity, dict):
            return identity
        rows = [row for row in list_active_sessions(web.redis_client(config)) if owns_session(row, identity)]
        labels = words()
        return page(labels["my_sessions"], '<h1>{my_sessions}</h1>'.format(**labels) + table(rows, [
            ("connection_id", labels["connection"]), ("project", labels["project"]), ("host_id", labels["host"]),
            ("remote_user", labels["remote_user"]), ("duration_seconds", labels["duration"]), ("status", labels["status"])]))

    @app.route("/me/history")
    @app.route("/me/history/export")
    def my_history():
        identity = require_user()
        if not isinstance(identity, dict):
            return identity
        labels = words()
        try:
            filters = history_filters(request.args, include_user=False)
            rows = read_history(config["logging"]["base_path"], identity, user=identity["username"], admin_groups=[], **filters)
            columns = [("time", labels["time"]), ("project", labels["project"]), ("host_id", labels["host"]),
                       ("server_name", labels["server"]), ("remote_user", labels["remote_user"]), ("result", labels["result"])]
            if request.path.endswith("/export"):
                # Internal filesystem paths and other users' objects are never exported.
                public_rows = [{key: row.get(key) for key, _ in columns} for row in rows]
                output_format = request.args.get("format", "csv")
                content, mimetype = render_export(public_rows, output_format)
                return Response(content, mimetype=mimetype, headers={
                    "Content-Disposition": "attachment; filename=my-history.{}".format(output_format)})
        except (ValueError, ExportError) as exc:
            abort(400, description=str(exc))
        query = {key: value for key, value in request.args.items() if key != "format"}
        links = " ".join('<a href="/me/history/export?{}">{}</a>'.format(
            html.escape(urllib.parse.urlencode(dict(query, format=fmt)), quote=True), fmt.upper()) for fmt in ("csv", "json"))
        return page(labels["my_history"], '<h1>{my_history}</h1>'.format(**labels) + history_form(request.args, False, web._dashboard_locale(config)) + links + table(rows, columns))

    @app.route("/me/access", methods=["GET", "POST"])
    def my_access():
        identity = require_user()
        if not isinstance(identity, dict):
            return identity
        labels = words()
        redis = web.redis_client(config)
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            if action not in ("create", "cancel", "renew", "comment"):
                abort(403)
            request_id = request.form.get("id")
            if action != "create":
                record = get_access_request(redis, request_id)
                if not record or not owns_access_request(record, identity):
                    abort(404)
            try:
                if request.form.get("confirm") != "true":
                    raise ValueError("explicit confirmation is required")
                if action == "create":
                    project = (request.form.get("project") or "").strip()
                    host_id = (request.form.get("host") or "").strip() or None
                    if not project or len(project) > 256:
                        raise ValueError("a project is required")
                    if host_id:
                        host = get_host(redis, host_id)
                        if not host or host.get("project_name", "").lower() != project.lower():
                            raise ValueError("host does not belong to the requested project")
                    record = create_access_request(
                        redis, identity, project, host=host_id,
                        remote_user=request.form.get("remote_user") or None,
                        sudo_mode=request.form.get("sudo_mode") or "none",
                        reason=request.form.get("reason"), ticket=request.form.get("ticket") or None,
                        starts_at=request.form.get("starts_at") or None, ends_at=request.form.get("ends_at") or None, config=config)
                    event = "access_request_created"
                elif action == "cancel":
                    record = cancel_access_request(redis, request_id, identity)
                    event = "access_request_cancelled"
                elif action == "renew":
                    record = renew_access_request(redis, request_id, identity, reason=request.form.get("reason") or None,
                        ticket=request.form.get("ticket") or None, starts_at=request.form.get("starts_at") or None,
                        ends_at=request.form.get("ends_at") or None, config=config)
                    event = "access_request_renewed"
                else:
                    record = comment_access_request(redis, request_id, identity, request.form.get("comment"))
                    event = "access_request_commented"
                audit(event, identity, "applied", {"access_request_id": record["id"], "self_service": True})
                notice = notify(redis, event, record, identity) or {"level": "info", "text": labels["request_updated"]}
                # Prevent a refresh from submitting the same mutation again.
                if notice.get("level") == "info":
                    return redirect("/me/access")
            except (AccessDenied, ValueError) as exc:
                audit("access_" + str(action), identity, "denied", {"access_request_id": request_id, "self_service": True})
                notice = {"level": "error", "text": str(exc)}
        token = html.escape(csrf_token(), quote=True)
        prefill_project, prefill_host, prefill_remote_user = "", "", ""
        if request.method == "GET" and re.fullmatch(r"[0-9]{1,20}", request.args.get("host") or ""):
            candidate = get_host(redis, request.args.get("host"))
            if candidate is not None and (not request.args.get("project") or request.args["project"] == candidate["project_name"]):
                visible, decision = resource_access(redis, identity, candidate)
                if visible:
                    prefill_project, prefill_host = candidate["project_name"], candidate["server_id"]
                    prefill_remote_user = (decision or {}).get("remote_user") or ""
        confirmation = '<label><input type="checkbox" name="confirm" value="true" required> {confirm}</label>'.format(**labels)
        body = '''<h1>{my_requests}</h1>
<form method="post"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="create">
<p><label>{project} <input name="project" value="{prefill_project}" required></label> <label>{host_optional} <input name="host" value="{prefill_host}"></label></p>
<p><label>{remote_user} <input name="remote_user" value="{prefill_remote_user}" required></label> <label>Sudo <select name="sudo_mode"><option>none</option><option>sudo-i</option></select></label></p>
<p><label>{reason} <input name="reason" required></label> <label>{ticket} <input name="ticket"></label></p>
<p><label>{start} <input name="starts_at" placeholder="2026-11-07T22:00:00+07:00"></label> <label>{end} <input name="ends_at" placeholder="2026-11-07T23:00:00+07:00"></label></p>
<p>{window_help}</p>
{confirmation}<button>{request_access}</button></form>'''.format(
            token=token, confirmation=confirmation, prefill_project=html.escape(prefill_project, quote=True),
            prefill_host=html.escape(prefill_host, quote=True), prefill_remote_user=html.escape(prefill_remote_user, quote=True), **labels)
        rows = []
        for item in list_access_requests(redis):
            if not owns_access_request(item, identity):
                continue
            row = dict(item)
            row["start"] = web._format_access_time(row.get("starts_at"))
            row["end"] = web._format_access_time(row.get("expires_at") or row.get("ends_at"))
            row["comments_text"] = "; ".join(str(c.get("text") or "") for c in row.get("comments") or [])
            actions = [("comment", labels["comment"])]
            if row.get("status") == "pending":
                actions.append(("cancel", labels["cancel"]))
            if row.get("status") == "approved":
                actions.append(("renew", labels["renew"]))
            row["actions"] = ""
            for action, label in actions:
                extra = '<input name="comment" placeholder="{comment}" required>'.format(**labels) if action == "comment" else ""
                if action == "renew":
                    extra = '<input name="reason" placeholder="{reason}" required><input name="ticket" placeholder="{ticket}"><input name="starts_at" placeholder="{start_placeholder}"><input name="ends_at" placeholder="{end_placeholder}">'.format(**labels)
                row["actions"] += '<form class="inline" method="post"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="id" value="{}"><input type="hidden" name="action" value="{}">{}{}<button>{}</button></form>'.format(
                    token, html.escape(str(row["id"]), quote=True), action, extra, confirmation, label)
            rows.append(row)
        body += table(rows, [("id", "ID"), ("status", labels["status"]), ("project", labels["project"]), ("host", labels["host"]),
                                 ("remote_user", labels["remote_user"]), ("ticket", labels["ticket"]), ("start", labels["start_utc"]), ("end", labels["end_utc"]),
                                 ("renewal_of", labels["renews"]), ("comments_text", labels["comments"]), ("actions", labels["actions"])])
        return page(labels["my_requests"], body, notice)
