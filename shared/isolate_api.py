"""Versioned authenticated control API; it never exposes Redis or SSH keys."""

import html
import json
import secrets
from urllib.parse import urlsplit

from isolate_connection_auth import ConnectionDenied
from isolate_identity import IdentityError
from isolate_permissions import has_permission, is_platform_admin
from isolate_policy import PolicyDenied
from isolate_runtime import Runtime


def register_api_routes(app, config, redis_factory, current_identity, csrf_token, browser_token):
    from flask import abort, jsonify, request
    from redis.exceptions import RedisError

    def runtime():
        return Runtime(config, redis=redis_factory(config))

    def require_enabled():
        if not config.get("api", {}).get("enabled", False):
            abort(404)

    def bearer(allow_browser=False, mutation=False):
        require_enabled()
        authorization = request.headers.get("Authorization", "")
        if authorization:
            if not authorization.startswith("Bearer ") or len(authorization) > 32768:
                abort(401)
            return authorization[7:]
        if allow_browser:
            identity = current_identity()
            if identity:
                if mutation:
                    supplied = request.headers.get("X-CSRF-Token", "")
                    if not secrets.compare_digest(supplied, csrf_token()):
                        abort(403)
                token = browser_token()
                if token:
                    return token
        abort(401, description="verified bearer token is required")

    def failure(exc):
        from isolate_identity_security import StepUpRequired
        if isinstance(exc, StepUpRequired):
            response = jsonify(error="step_up_required", acr_values=exc.acr_values, max_age=exc.max_age,
                               reauthenticate_url="/login?step_up=true")
            response.headers["WWW-Authenticate"] = 'Bearer error="insufficient_user_authentication"'
            return response, 403
        if isinstance(exc, RedisError):
            return jsonify(error="control_store_unavailable"), 503
        return jsonify(error="access_denied", message=str(exc)), 403

    errors = (ConnectionDenied, IdentityError, PolicyDenied, RedisError, ValueError)

    @app.get("/api/v1/me")
    def api_me():
        try:
            identity = runtime().authenticate(bearer())
            return jsonify({key: identity.get(key) for key in ("keycloak_sub", "username", "email", "groups", "roles", "exp")})
        except errors as exc:
            return failure(exc)

    @app.get("/api/v1/resources")
    def api_resources():
        try:
            rows = runtime().resources(bearer(), query=request.args.get("q"), project=request.args.get("project"))
            offset, limit = max(0, int(request.args.get("offset", 0))), min(500, max(1, int(request.args.get("limit", 100))))
            return jsonify(resources=rows[offset:offset + limit], next_offset=offset + limit if offset + limit < len(rows) else None)
        except errors as exc:
            return failure(exc)

    @app.post("/api/v1/connections")
    def api_connection():
        token = bearer(allow_browser=True, mutation=True)
        if request.content_length and request.content_length > 4096:
            abort(413)
        body = request.get_json()
        if not isinstance(body, dict) or set(body) - {"host_id", "protocol"}:
            abort(400, description="only host_id and protocol are accepted")
        try:
            result = runtime().create_ticket(token, body.get("host_id"), body.get("protocol", "ssh"), source_ip=request.remote_addr)
            gateway = config.get("gateway", {})
            result["gateway_host"] = gateway.get("public_ssh_host")
            result["gateway_port"] = gateway.get("ssh_port", 2222)
            result["websocket_url"] = str(gateway.get("public_web_url") or "").rstrip("/") + "/ssh"
            if result["protocol"] in ("postgresql", "mysql"):
                result["websocket_url"] = str(gateway.get("public_web_url") or "").rstrip("/") + "/protocols/database"
                result["audit_profile"] = "connection"
            response = jsonify(result)
            response.headers["Cache-Control"] = "no-store"
            return response, 201
        except errors as exc:
            return failure(exc)

    @app.get("/api/v1/history")
    def api_history():
        try:
            service = runtime()
            identity = service.authenticate(bearer())
            from isolate_history import read_history
            limit = min(100, max(1, int(request.args.get("limit", 30))))
            # The client console's f command is always the caller's own history.
            rows = read_history(config["logging"]["base_path"], identity, limit=limit,
                query=request.args.get("query"), project=request.args.get("project"), host=request.args.get("host"),
                since=request.args.get("since"), until=request.args.get("until"), result=request.args.get("result"))
            return jsonify(history=rows)
        except errors as exc:
            return failure(exc)

    def audit_search(service, identity):
        from isolate_audit_index import AuditIndex
        index = AuditIndex(config.get("audit_index", {}))
        admin = is_platform_admin(identity, config)
        projects = None if admin else [project for project in index.projects() if has_permission(identity, config, "audit.read", project)]
        cursor = json.loads(request.args["before"]) if request.args.get("before") else None
        return index.search(subject=None if admin else identity["keycloak_sub"], projects=projects,
            query=request.args.get("q"), event=request.args.get("event"), host_id=request.args.get("host_id"),
            connection_id=request.args.get("connection_id"), since=request.args.get("since"), until=request.args.get("until"),
            before=cursor, limit=request.args.get("limit", 100))

    @app.get("/api/v1/audit")
    def api_audit():
        token = bearer(allow_browser=True)
        if not config.get("audit_index", {}).get("enabled"):
            abort(404)
        try:
            service = runtime()
            return jsonify(audit_search(service, service.authenticate(token)))
        except errors as exc:
            return failure(exc)

    @app.get("/audit/search")
    def audit_page():
        token = bearer(allow_browser=True)
        if not config.get("audit_index", {}).get("enabled"):
            abort(404)
        try:
            service = runtime()
            result = audit_search(service, service.authenticate(token))
        except errors as exc:
            return failure(exc)
        import isolate_web
        from urllib.parse import urlencode
        filters = ("q", "event", "host_id", "connection_id", "since", "until")
        form = '<h1>Audit search</h1><form class="inline" method="get">'
        for name in filters:
            form += '<label>{}<input name="{}" value="{}"></label>'.format(name, name, html.escape(request.args.get(name, ""), quote=True))
        form += '<button>Search</button></form>'
        rows = []
        for record in result["events"]:
            row = {name: str(record.get(name) or "") for name in
                   ("ts", "event", "username", "project", "host_id", "connection_id")}
            row["details"] = '<details><summary>Event</summary><pre>{}</pre></details>'.format(html.escape(json.dumps(record, indent=2, ensure_ascii=False)))
            rows.append(row)
        form += isolate_web._table(rows, [(key, key) for key in ("ts", "event", "username", "project", "host_id", "connection_id", "details")])
        if result["next"]:
            args = {name: request.args[name] for name in filters if request.args.get(name)}
            args["before"] = json.dumps(result["next"])
            form += '<p><a href="?{}">Next page</a></p>'.format(html.escape(urlencode(args), quote=True))
        return isolate_web._html("Audit search", form, config=config)

    @app.post("/auth/backchannel-logout")
    def backchannel_logout():
        if not config.get("identity_security", {}).get("backchannel_logout", {}).get("enabled"):
            abort(404)
        if request.content_length and request.content_length > 65536:
            abort(413)
        from isolate_identity_security import IdentityStoreUnavailable, process_backchannel_logout
        try:
            process_backchannel_logout(redis_factory(config), config, request.form.get("logout_token"))
        except IdentityStoreUnavailable:
            return "", 503
        except (IdentityError, ValueError):
            return "", 400, {"Cache-Control": "no-store"}
        except RedisError:
            return "", 503
        return "", 200, {"Cache-Control": "no-store"}

    @app.get("/ready")
    def api_ready():
        require_enabled()
        from isolate_cluster import node_ready
        try:
            redis = redis_factory(config)
            ready = bool(redis.ping()) and node_ready(redis, config)
            return jsonify(ready=ready), 200 if ready else 503
        except RedisError:
            return jsonify(ready=False), 503

    @app.get("/me/terminal/<host_id>")
    def browser_terminal(host_id):
        require_enabled()
        if not config.get("gateway", {}).get("enabled"):
            abort(404)
        token = bearer(allow_browser=True)
        try:
            context = runtime().authorize(token, host_id, "webssh", request.remote_addr)
        except errors as exc:
            from isolate_identity_security import StepUpRequired
            if isinstance(exc, StepUpRequired):
                from flask import redirect, session
                session["return_to"] = "/me/terminal/" + str(host_id)
                return redirect("/login?step_up=true")
            return failure(exc)
        import isolate_web
        url = str(config.get("gateway", {}).get("public_web_url") or "").rstrip("/") + "/ssh"
        body = '<h1>Terminal: {}</h1><p id="isolate-terminal-status" role="status"></p>'.format(html.escape(context["host"]["server_name"]))
        body += '<link rel="stylesheet" href="/static/vendor/xterm/xterm.css">'
        body += '<div id="isolate-terminal" style="height:65vh;background:#111722" data-host-id="{}" data-csrf-token="{}" data-ticket-url="/api/v1/connections" data-websocket-url="{}"></div>'.format(
            html.escape(str(host_id), quote=True), html.escape(csrf_token(), quote=True), html.escape(url, quote=True))
        body += '<script type="module" src="/static/isolate-webssh.js"></script>'
        return isolate_web._html("SSH terminal", body, config=config)
