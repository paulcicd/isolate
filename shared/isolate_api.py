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
        from isolate_recordings import RecordingError
        if isinstance(exc, RecordingError):
            return jsonify(error="recording_evidence_unavailable"), 503
        from isolate_admission import AdmissionDenied
        if isinstance(exc, AdmissionDenied):
            response = jsonify(error="rate_limited", retry_after=exc.retry_after)
            response.headers["Retry-After"] = str(exc.retry_after)
            return response, 429
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

    def bounded_json(maximum):
        if not request.is_json:
            abort(415)
        raw = request.stream.read(maximum + 1)
        if len(raw) > maximum:
            abort(413)
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError, OverflowError):
            abort(400, description="a JSON object is required")
        if not isinstance(body, dict):
            abort(400, description="a JSON object is required")
        return body

    from isolate_workspace_api import register_workspace_api
    register_workspace_api(app, config, runtime, bearer, bounded_json, failure, errors)
    from isolate_application_api import register_application_api
    register_application_api(app, config, runtime, bearer, bounded_json, failure, errors, csrf_token)
    from isolate_admin_api import register_admin_api
    register_admin_api(app, config, runtime, bearer, bounded_json, failure, errors)
    from isolate_investigation_api import register_investigation_api
    register_investigation_api(app, config, runtime, bearer, failure, errors)
    from isolate_explain_api import register_explain_api
    register_explain_api(app, config, runtime, bearer, bounded_json, failure, errors)
    from isolate_governance_api import register_governance_api
    register_governance_api(app, config, runtime, bearer, bounded_json, failure, errors, csrf_token)
    from isolate_campaign_api import register_campaign_api
    register_campaign_api(app, config, runtime, bearer, bounded_json, failure, errors, csrf_token)
    from isolate_openapi import register_openapi_routes
    register_openapi_routes(app, config)

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
        body = bounded_json(4096)
        if not isinstance(body, dict) or set(body) - {"host_id", "protocol"}:
            abort(400, description="only host_id and protocol are accepted")
        if (type(body.get("host_id")) not in (str, int) or not str(body["host_id"]).isdigit()
                or not isinstance(body.get("protocol", "ssh"), str)):
            abort(400, description="a numeric host_id and string protocol are required")
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
            rows = read_history(config["logging"]["base_path"], identity, archive_config=config, state_client=service.redis, limit=limit,
                query=request.args.get("query"), project=request.args.get("project"), host=request.args.get("host"),
                since=request.args.get("since"), until=request.args.get("until"), result=request.args.get("result"))
            return jsonify(history=rows)
        except errors as exc:
            return failure(exc)

    @app.post("/api/v1/jobs")
    def api_create_job():
        from isolate_jobs import JobError
        from isolate_mcp import IsolateMCPService, MCPAccessDenied, token_scopes
        import hashlib
        token = bearer(allow_browser=True, mutation=True)
        if request.content_length and request.content_length > 65536:
            abort(413)
        body = bounded_json(65536)
        if not isinstance(body, dict) or set(body) - {"type", "host_id", "command", "runbook_id", "parameters", "timeout", "confirm"}:
            abort(400)
        if body.get("type") not in ("runbook", "command"):
            abort(400, description="job type must be command or runbook")
        key = request.headers.get("Idempotency-Key", "")
        if not 16 <= len(key) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            abort(400, description="Idempotency-Key must contain 16-128 printable non-space characters")
        try:
            control = runtime()
            identity = control.authenticate(token)
            from isolate_admission import check_admission
            # Job submission is a new mutation surface: its shared quota is
            # mandatory even when legacy connection throttling is disabled.
            limits = dict(config.get("admission", {}), enabled=True)
            check_admission(control.redis, {"admission": limits}, identity["keycloak_sub"], request.remote_addr, kind="job")
            service = IsolateMCPService(config, control.redis)
            scopes = token_scopes(identity.get("raw_claims") or {})
            if body.get("confirm") is not True:
                raise MCPAccessDenied("explicit confirm=true is required")
            if body["type"] == "command":
                service._require_command_submitter(identity, scopes)
                from isolate_jobs import validate_command
                validate_command(body.get("command"), config)
                action = "command"
            else:
                from isolate_runbooks import render_runbook
                rendered = render_runbook(config, body.get("runbook_id"), body.get("parameters"))
                service._require_runbook_submitter(identity, scopes, rendered["runbook"]["class"])
                action = rendered["policy_action"]
            from isolate_inventory import get_host
            from isolate import load_grants, load_project_sets
            from isolate_policy import resolve_grant
            host = get_host(control.redis, body.get("host_id")) if str(body.get("host_id")).isdigit() else None
            if host is None:
                raise MCPAccessDenied("host was not found or is not allowed")
            resolve_grant(identity, project=host["project_name"], host=host, grants=load_grants(control.redis),
                project_sets=load_project_sets(control.redis), defaults={**config.get("policy", {}), **config.get("ssh", {})}, action=action)
            digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            record_key = "job_submission_" + hashlib.sha256((identity["keycloak_sub"] + ":" + key).encode()).hexdigest()
            pending = {"digest": digest, "state": "pending", "subject": identity["keycloak_sub"]}
            if not control.redis.set(record_key, json.dumps(pending), nx=True):
                existing = json.loads(control.redis.get(record_key))
                if existing.get("digest") != digest:
                    return jsonify(error="idempotency_conflict"), 409
                if existing.get("state") != "complete":
                    return jsonify(error="submission_outcome_requires_review"), 409
                return jsonify(existing["result"]), 200
            if body.get("type") == "runbook":
                result = service.runbook_execute(identity, scopes, body.get("runbook_id"), body.get("host_id"),
                    parameters=body.get("parameters"), timeout=body.get("timeout"), confirm=body.get("confirm"), token=token)
            elif body.get("type") == "command":
                result = service.command_job_create(identity, scopes, body.get("host_id"), body.get("command"),
                    timeout=body.get("timeout"), confirm=body.get("confirm"), token=token)
            else:
                raise ValueError("job type must be command or runbook")
            control.redis.set(record_key, json.dumps(dict(pending, state="complete", result=result), sort_keys=True))
            return jsonify(result), 201
        except (JobError, MCPAccessDenied) + errors as exc:
            return failure(exc)

    @app.get("/api/v1/jobs/<job_id>")
    def api_job_status(job_id):
        from isolate_jobs import get_job
        if not job_id.isdigit():
            abort(404)
        try:
            control = runtime()
            identity = control.authenticate(bearer())
            record = get_job(control.redis, job_id)
            if record is None or (record.get("keycloak_sub") != identity.get("keycloak_sub") and not is_platform_admin(identity, config)):
                abort(404)
            return jsonify(job=record)
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

    @app.get("/me/terminal")
    @app.get("/me/terminal/<host_id>")
    def browser_terminal(host_id=None):
        require_enabled()
        if not config.get("gateway", {}).get("enabled"):
            abort(404)
        token = bearer(allow_browser=True)
        try:
            control = runtime()
            identity = control.authenticate(token)
            context = control.authorize_identity(identity, host_id, "webssh", token, request.remote_addr) if host_id else None
        except errors as exc:
            from isolate_identity_security import StepUpRequired
            if isinstance(exc, StepUpRequired):
                from flask import redirect, session
                session["return_to"] = "/me/terminal/" + str(host_id) if host_id else "/me/terminal"
                return redirect("/login?step_up=true")
            return failure(exc)
        import isolate_web
        from isolate_terminal_ui import render_terminal_workspace
        from isolate_workspace import preferences
        body = render_terminal_workspace(context["host"] if context else None, csrf_token(),
            language=isolate_web._dashboard_locale(config), preferences=preferences(control.redis, identity))
        return isolate_web._html("SSH terminal", body, config=dict(config,
            dashboard=dict(config.get("dashboard", {}), refresh_seconds=0)))
