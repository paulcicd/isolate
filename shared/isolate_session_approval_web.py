"""Scoped review and owner tracking for single-connection SSH approvals."""

import html

from isolate_notifications import NotificationError, notify_session_approval_event
from isolate_permissions import has_permission, role_names
from isolate_session_approvals import (
    SessionApprovalDenied, cancel_session_approval, decide_session_approval,
    get_session_approval, list_session_approvals, revoke_session_approval,
    set_session_approval_notification_status,
)


def register_session_approval_routes(app, config, current_identity, csrf_token, validate_csrf, audit):
    from flask import abort, redirect, request
    import isolate_web as web

    def user(manager=False):
        identity = current_identity()
        if identity is None:
            return redirect("/login")
        if manager:
            if not (has_permission(identity, config, "sessions.approve") or has_permission(identity, config, "sessions.read")):
                abort(403)
        elif not (web.is_dashboard_admin(identity, config) or web.is_self_service_user(identity, config) or role_names(identity, config)):
            abort(403)
        return identity

    def owns(record, identity):
        return bool(identity.get("keycloak_sub")) and record.get("requester_sub") == identity["keycloak_sub"]

    def can_read(record, identity):
        project = record.get("project")
        return bool(project) and (has_permission(identity, config, "sessions.approve", project)
                                  or has_permission(identity, config, "sessions.read", project))

    def render(manager):
        identity = user(manager)
        if not isinstance(identity, dict):
            return identity
        redis = web.redis_client(config)
        russian = web._dashboard_locale(config) == "ru"
        title = ("Согласования сессий" if russian else "Session approvals") if manager else ("Мои согласования" if russian else "My approvals")
        notice = None
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            request_id = request.form.get("id")
            try:
                record = get_session_approval(redis, request_id)
            except SessionApprovalDenied:
                abort(404)
            if record is None or not (can_read(record, identity) if manager else owns(record, identity)):
                abort(404)
            if manager and (not record.get("project") or not has_permission(identity, config, "sessions.approve", record["project"])):
                abort(403)
            if action not in (("approve", "deny", "revoke") if manager else ("cancel",)):
                abort(403)
            try:
                if request.form.get("confirm") != "true":
                    raise SessionApprovalDenied("explicit confirmation is required")
                if action == "cancel":
                    record = cancel_session_approval(redis, config, request_id, identity)
                elif action == "revoke":
                    record = revoke_session_approval(redis, config, request_id, identity, reason=request.form.get("reason"))
                else:
                    record = decide_session_approval(redis, config, request_id, identity,
                                                     approve=action == "approve", reason=request.form.get("reason"))
                event = "session_approval_" + {"approve": "approved", "deny": "denied", "revoke": "revoked", "cancel": "cancelled"}[action]
                audit(event, identity, "applied", {"session_approval_id": request_id, "project": record["project"], "self_service": not manager})
                try:
                    delivery = notify_session_approval_event(config, event, record, actor=identity)
                except NotificationError as exc:
                    delivery = {"sent": [], "errors": [str(exc)]}
                set_session_approval_notification_status(redis, request_id, dict(delivery, ok=not bool(delivery.get("errors"))))
                if delivery.get("errors"):
                    notice = {"level": "warning", "text": "; ".join(delivery["errors"])}
                else:
                    return redirect(request.path)
            except (SessionApprovalDenied, ValueError) as exc:
                audit("session_approval_" + str(action), identity, "denied", {"session_approval_id": request_id, "self_service": not manager})
                notice = {"level": "error", "text": str(exc)}
        rows = list_session_approvals(redis, status=request.args.get("status") or None, project=request.args.get("project") or None)
        rows = [record for record in rows if can_read(record, identity)] if manager else [record for record in rows if owns(record, identity)]
        token = html.escape(csrf_token(), quote=True)
        for row in rows:
            row["quorum"] = "{} / {}".format(len(row.get("approvals") or []), row.get("required_approvals") or 1)
            row["approvers"] = ", ".join(item.get("username") or item.get("keycloak_sub") or "" for item in row.get("approvals") or [])
            row["expires"] = web._format_access_time(row.get("session_expires_at") or row.get("approval_expires_at") or row.get("request_expires_at"))
            row["actions"] = ""
            actions = []
            can_decide = bool(row.get("project")) and has_permission(identity, config, "sessions.approve", row["project"])
            if manager and can_decide and not owns(row, identity):
                if row["status"] == "pending":
                    actions = [("approve", "Одобрить" if russian else "Approve"), ("deny", "Отклонить" if russian else "Deny")]
                elif row["status"] in ("approved", "active"):
                    actions = [("revoke", "Отозвать" if russian else "Revoke")]
            elif not manager and row["status"] in ("pending", "approved"):
                actions = [("cancel", "Отменить" if russian else "Cancel")]
            for action, label in actions:
                row["actions"] += '<form method="post" class="inline"><input type="hidden" name="csrf_token" value="{}"><input type="hidden" name="id" value="{}"><input type="hidden" name="action" value="{}"><input name="reason" placeholder="{}"><label><input type="checkbox" name="confirm" value="true" required> {}</label><button>{}</button></form>'.format(
                    token, html.escape(str(row["id"]), quote=True), action,
                    "Причина" if russian else "Reason", "Подтвердить" if russian else "Confirm", label)
        help_text = ("Подключение ожидает согласования перед запуском SSH. Решение действует только для этой сессии; изменение сервера или прав требует нового решения. Обновите страницу для проверки статуса."
                     if russian else "The connection waits for approval before SSH starts. Approval applies to this connection only; host or policy changes require a new decision. Refresh to check status.")
        body = '<h1>{}</h1><p>{}</p><form method="get" class="inline"><label>{} <input name="project" value="{}"></label><label>{} <select name="status"><option value="">{}</option>{}</select></label><button>{}</button></form>'.format(
            title, help_text, "Проект" if russian else "Project", html.escape(request.args.get("project") or "", quote=True),
            "Статус" if russian else "Status", "Все" if russian else "All", "".join('<option{}>{}</option>'.format(' selected' if request.args.get("status") == value else "", value)
                for value in ("pending", "approved", "active", "denied", "revoked", "cancelled", "expired", "closed")), "Обновить" if russian else "Refresh")
        for row in rows:
            escape = lambda value: html.escape(str(value if value is not None else ""), quote=True)
            body += '<article class="panel"><div class="section-heading"><h2>{} · #{}</h2><span class="badge">{}</span></div><p><strong>{} → {}</strong> · sudo: {} · {}: {}</p><dl class="key-value">'.format(
                escape(row.get("project")), escape(row.get("host_id")), escape(row.get("status")),
                escape(row.get("requester")), escape(row.get("remote_user")), escape(row.get("sudo_mode")),
                "Кворум" if russian else "Quorum", escape(row["quorum"]))
            for label, value in (
                ("ID", row.get("id")),
                ("Подключение" if russian else "Connection", row.get("connection_id")),
                ("Назначение" if russian else "Destination", "{}:{}".format(row.get("target_host") or "", row.get("target_port") or 22)),
                ("Согласующие" if russian else "Approvers", row["approvers"] or "—"),
                ("Срок (UTC)" if russian else "Expires (UTC)", row["expires"]),
                ("Причина" if russian else "Reason", row.get("reason") or "—"),
            ):
                body += '<dt>{}</dt><dd style="overflow-wrap:anywhere">{}</dd>'.format(label, escape(value))
            body += '</dl><div class="approval-actions">{}</div></article>'.format(row["actions"])
        if not rows:
            body += '<div class="empty-state">{}</div>'.format("Согласований нет" if russian else "No session approvals")
        view_config = dict(config, dashboard=dict(config.get("dashboard", {}), refresh_seconds=0))
        return web._html(title, body, config=view_config, notice=notice)

    @app.route("/session-approvals", methods=["GET", "POST"])
    def session_approvals():
        return render(True)

    @app.route("/me/session-approvals", methods=["GET", "POST"])
    def own_session_approvals():
        return render(False)
