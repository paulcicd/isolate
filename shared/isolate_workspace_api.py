"""Authenticated catalogue, subject preferences and scoped replay bookmarks."""

import json
import html
import math
import re
import secrets
import shlex
import time

from redis.exceptions import WatchError

from isolate_permissions import has_permission
from isolate_workspace import preferences, update_preferences, workspace_resources, subject_key


def _recording_metadata(runtime, connection_id):
    from isolate_replay import _find_local_session
    from isolate_recordings import RecordingArchive, RecordingNotFound, capture_root
    config = runtime.config
    if config.get("recordings", {}).get("enabled"):
        private = _find_local_session(capture_root(config), connection_id)
        if private:
            return private["summary"]
        try:
            return RecordingArchive(config, state_client=runtime.redis).describe(connection_id)["metadata"]
        except RecordingNotFound:
            pass
    local = _find_local_session(config["logging"]["base_path"], connection_id)
    return local["summary"] if local else None


def register_workspace_api(app, config, runtime_factory, bearer, bounded_json, failure, errors):
    from flask import abort, jsonify, request

    def authenticated(mutation=False):
        token = bearer(allow_browser=True, mutation=mutation)
        runtime = runtime_factory()
        return runtime, runtime.authenticate(token), token

    @app.route("/api/v1/workspace/preferences", methods=["GET", "PATCH"])
    def workspace_preferences():
        try:
            runtime, identity, _ = authenticated(request.method == "PATCH")
            value = (update_preferences(runtime.redis, identity, bounded_json(16384)) if request.method == "PATCH"
                     else preferences(runtime.redis, identity))
            return jsonify(value)
        except errors as exc:
            return failure(exc)

    @app.get("/api/v1/workspace/resources")
    def workspace_catalogue():
        try:
            runtime, identity, token = authenticated()
            kind, view = request.args.get("protocol"), request.args.get("view", "all")
            if (kind and kind not in ("ssh", "http", "kubernetes", "postgresql", "mysql")) or view not in ("all", "favorites", "recent"):
                abort(400)
            rows = workspace_resources(runtime, identity, token, request.args.get("q"), request.args.get("project"), kind)
            if view != "all":
                order = preferences(runtime.redis, identity)[view]
                selected = set(order)
                rows = [row for row in rows if row["resource_id"] in selected]
                if view == "recent":
                    rank = {item: i for i, item in enumerate(order)}
                    rows.sort(key=lambda row: rank[row["resource_id"]])
            offset, limit = max(0, int(request.args.get("offset", 0))), min(100, max(1, int(request.args.get("limit", 48))))
            return jsonify(resources=rows[offset:offset + limit], total=len(rows),
                next_offset=offset + limit if offset + limit < len(rows) else None)
        except errors as exc:
            return failure(exc)

    @app.get("/workspace/resource/<host_id>/<protocol>")
    def workspace_resource(host_id, protocol):
        try:
            runtime, identity, token = authenticated()
            # A resource detail must pass its own protocol grant, even if a
            # separate management role can see it in the catalogue.
            context = runtime.authorize_identity(identity, host_id, protocol, token, request.remote_addr)
            if protocol == "ssh":
                from flask import redirect
                return redirect("/me/terminal/" + str(host_id))
            public = str(config.get("dashboard", {}).get("public_url") or "").rstrip("/")
            gateway = str(config.get("gateway", {}).get("public_web_url") or "").rstrip("/")
            endpoint = gateway.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
            title = context["host"]["server_name"]
            body = '<h1>{}</h1><p>{} · {}</p>'.format(html.escape(title), html.escape(context["host"]["project_name"]), html.escape(protocol.upper()))
            if protocol in ("postgresql", "mysql"):
                command = shlex.join(['python3', '/opt/auth/scripts/isolate-protocol-proxy.py', 'database',
                    '--api-url', public, '--gateway-url', gateway + '/protocols/database',
                    '--host-id', str(host_id), '--protocol', protocol, '--listen-port', '15432'])
                body += '<p>Start the local Isolate tunnel, then connect your database client to 127.0.0.1:15432 with native TLS and your database identity.</p><pre>{}</pre>'.format(html.escape(command))
            else:
                endpoint += '/protocols/' + protocol + '/' + str(host_id) + '/'
                body += '<p>Use this authenticated API endpoint from your client. Sign in with <code>isolate login</code>; bearer credentials remain in your private client cache.</p><pre>{}</pre>'.format(html.escape(endpoint))
                if protocol == "kubernetes":
                    body += '<p>Configure kubectl with the Isolate ExecCredential helper and the trusted gateway CA. Your verified identity is impersonated upstream.</p>'
            body += '<p><a href="/workspace">Back to resources</a></p>'
            from isolate_web import _html
            return _html(title, body, config=config)
        except errors as exc:
            return failure(exc)

    def bookmarks_context(connection_id, mutation=False):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", connection_id):
            abort(404)
        runtime, identity, _ = authenticated(mutation)
        metadata = _recording_metadata(runtime, connection_id)
        if not metadata:
            abort(404)
        owner = (metadata.get("keycloak_sub") == identity["keycloak_sub"] if metadata.get("keycloak_sub")
                 else metadata.get("username") == identity.get("username"))
        if not owner and not (metadata.get("project") and has_permission(identity, config, "audit.read", metadata["project"])):
            abort(404)
        key = "recording_bookmarks_" + subject_key(identity) + "_" + connection_id
        return runtime, identity, metadata, key

    @app.route("/api/v1/recordings/<connection_id>/bookmarks", methods=["GET", "POST"])
    @app.delete("/api/v1/recordings/<connection_id>/bookmarks/<bookmark_id>")
    def recording_bookmarks(connection_id, bookmark_id=None):
        try:
            runtime, identity, metadata, key = bookmarks_context(connection_id, request.method != "GET")
            if request.method == "GET":
                return jsonify(bookmarks=json.loads(runtime.redis.get(key) or "[]"))
            item = None
            if request.method == "POST":
                body = bounded_json(2048)
                if set(body) != {"seconds", "label"}:
                    abort(400)
                position, label = body["seconds"], body["label"]
                if (type(position) not in (int, float) or not math.isfinite(position) or not 0 <= position <= 604800
                        or not isinstance(label, str) or not 1 <= len(label.strip()) <= 160
                        or any(ord(char) < 32 or ord(char) == 127 for char in label)):
                    abort(400)
                item = {"id": secrets.token_hex(16), "seconds": round(position, 3), "label": label.strip(), "created_at": time.time()}
            elif not re.fullmatch(r"[a-f0-9]{32}", bookmark_id or ""):
                abort(404)
            for _ in range(12):
                with runtime.redis.pipeline() as pipe:
                    try:
                        pipe.watch(key)
                        values = json.loads(pipe.get(key) or "[]")
                        if item:
                            if len(values) >= 100:
                                abort(409, description="recording bookmark limit reached")
                            values.append(item)
                        else:
                            values = [value for value in values if value["id"] != bookmark_id]
                        values.sort(key=lambda value: (value["seconds"], value["id"]))
                        # Persist intent before the mutation. Audit includes no
                        # terminal data and no label text supplied by the user.
                        from isolate_audit import prepare_and_dispatch
                        prepare_and_dispatch({"event": "recording_bookmark_change", "ts": time.time(),
                            "username": identity.get("username"), "keycloak_sub": identity["keycloak_sub"],
                            "connection_id": connection_id, "project": metadata.get("project"),
                            "action": "create" if item else "delete", "result": "requested"},
                            dict(config.get("logging", {}), fail_closed=True))
                        pipe.multi()
                        pipe.set(key, json.dumps(values))
                        pipe.execute()
                        return jsonify(bookmarks=values), 201 if item else 200
                    except WatchError:
                        continue
            abort(409, description="bookmarks changed concurrently; retry")
        except errors as exc:
            return failure(exc)
