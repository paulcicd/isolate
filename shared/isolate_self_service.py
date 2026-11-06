"""Owner-scoped dashboard routes for verified Keycloak users."""

import html
import urllib.parse

from isolate_access import (
    AccessDenied, cancel_access_request, comment_access_request, create_access_request,
    get_access_request, list_access_requests, owns_access_request, renew_access_request,
)
from isolate_exports import ExportError, render_export
from isolate_history import read_history
from isolate_inventory import HostValidationError, get_host, list_hosts
from isolate_policy import filter_allowed_hosts
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
    },
}


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
        if not (web.is_dashboard_admin(identity, config) or web.is_self_service_user(identity, config)):
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
        hosts = filter_allowed_hosts(identity, candidates, grants=web.load_grants(redis),
                                     project_sets=web.load_project_sets(redis),
                                     defaults={**config.get("policy", {}), **config.get("ssh", {})})
        for host in hosts:
            host["connect_command"] = "g {}".format(host["server_id"])
        labels = words()
        body = '<h1>{my_servers}</h1><p>{servers_help}</p>'.format(**labels)
        body += '<form class="inline" method="get"><label>{search} <input name="q" value="{query_value}"></label><label>{project} <input name="project" value="{project_value}"></label><label>{tags} <input name="tags" placeholder="env=prod,owner=payments" value="{tags_value}"></label><button>{filter}</button></form>'.format(
            query_value=html.escape(request.args.get("q") or "", quote=True),
            project_value=html.escape(request.args.get("project") or "", quote=True),
            tags_value=html.escape(request.args.get("tags") or "", quote=True), **labels)
        body += table(hosts, [("server_id", "ID"), ("project_name", labels["project"]), ("server_name", labels["server"]),
                                  ("server_ip", labels["address"]), ("tags_display", labels["tags"]), ("server_services_display", labels["services"]),
                                  ("maintenance_marker", labels["state"]), ("connect_command", labels["connect"])])
        body += '<p><a href="/me/access">{request_temporary_access}</a></p>'.format(**labels)
        return page(labels["my_servers"], body)

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
        confirmation = '<label><input type="checkbox" name="confirm" value="true" required> {confirm}</label>'.format(**labels)
        body = '''<h1>{my_requests}</h1>
<form method="post"><input type="hidden" name="csrf_token" value="{token}"><input type="hidden" name="action" value="create">
<p><label>{project} <input name="project" required></label> <label>{host_optional} <input name="host"></label></p>
<p><label>{remote_user} <input name="remote_user" required></label> <label>Sudo <select name="sudo_mode"><option>none</option><option>sudo-i</option></select></label></p>
<p><label>{reason} <input name="reason" required></label> <label>{ticket} <input name="ticket"></label></p>
<p><label>{start} <input name="starts_at" placeholder="2026-11-07T22:00:00+07:00"></label> <label>{end} <input name="ends_at" placeholder="2026-11-07T23:00:00+07:00"></label></p>
<p>{window_help}</p>
{confirmation}<button>{request_access}</button></form>'''.format(token=token, confirmation=confirmation, **labels)
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
