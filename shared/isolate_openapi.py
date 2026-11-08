"""Central, deliberately explicit OpenAPI contract for the control listener.

Flask's registered routes are the source of truth for operation coverage.  A new
API route must receive a real contract here; silently manufacturing a generic
operation would hide contract drift.  Browser pages and the separate streaming
protocol listeners are not JSON control API operations.
"""

import copy
import re


HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
PUBLIC_PATHS = frozenset({"/health", "/ready", "/auth/backchannel-logout"})
BEARER = [{"BearerAuth": []}]
BROWSER = [{"BearerAuth": []}, {"BrowserSession": []}]
MUTATION = [{"BearerAuth": []}, {"BrowserSession": [], "CSRFToken": []}]


def ref(name):
    return {"$ref": "#/components/schemas/" + name}


def obj(properties=None, required=(), **extra):
    value = {"type": "object", "properties": properties or {}}
    if required:
        value["required"] = list(required)
    value.update(extra)
    return value


def array(items):
    return {"type": "array", "items": items}


STRING = {"type": "string"}
BOOLEAN = {"type": "boolean"}
INTEGER = {"type": "integer"}
NUMERIC_ID = {"type": "string", "pattern": "^[0-9]{1,20}$"}
REVISION = {"type": "string", "pattern": "^[a-f0-9]{64}$", "readOnly": True}
PROTOCOL = {"type": "string", "enum": ["ssh", "webssh", "http", "kubernetes", "postgresql", "mysql"]}
NEXT_OFFSET = {"type": ["integer", "null"], "minimum": 0}


def schemas():
    terminal = obj({
        "font_size": {"type": "integer", "minimum": 10, "maximum": 24},
        "font_family": {"type": "string", "enum": ["monospace", "ui-monospace", "Menlo", "Consolas"]},
        "theme": {"type": "string", "enum": ["dark", "light"]},
        "scrollback": {"type": "integer", "minimum": 1000, "maximum": 20000},
        "paste_threshold": {"type": "integer", "minimum": 100, "maximum": 10000},
    }, additionalProperties=False)
    host_fields = {
        "project_name": STRING, "server_name": STRING, "server_ip": STRING,
        "server_user": STRING, "server_port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "server_nosudo": BOOLEAN, "server_note": STRING, "server_services": STRING,
        "proxy_id": {"type": ["string", "null"], "description": "Existing inventory jump host ID, or empty/null for none."},
        "resource_owner": STRING, "environment": STRING,
        "tags": {"type": "object", "additionalProperties": STRING},
    }
    grant_fields = {
        "subject": {"type": "string", "enum": ["user", "group", "role", "service"]},
        "name": STRING, "project": STRING, "remote_user": STRING,
        "sudo_mode": {"type": "string", "enum": ["none", "sudo-i"]},
        "allowed_actions": {"type": "array", "items": STRING, "minItems": 1, "uniqueItems": True},
        "host": STRING, "keycloak_sub": {"type": "string", "description": "Compatibility field for an optional stable user subject binding."},
    }
    return {
        "Error": obj({"error": STRING, "message": STRING, "retry_after": {"type": "number"},
            "acr_values": STRING, "max_age": INTEGER, "reauthenticate_url": STRING}, additionalProperties=True),
        "Identity": obj({"keycloak_sub": STRING, "subject": STRING, "issuer": STRING,
            "username": STRING, "email": {"type": ["string", "null"]},
            "groups": array(STRING), "roles": array(STRING), "exp": INTEGER}),
        "HostInput": obj(host_fields, additionalProperties=False),
        "Host": obj(dict(host_fields, server_id=NUMERIC_ID, _revision=REVISION), ["server_id", "_revision"]),
        "GrantInput": obj(grant_fields, additionalProperties=False),
        "Grant": obj(dict(grant_fields, id=NUMERIC_ID, _revision=REVISION), ["id", "_revision"]),
        "Resource": obj({"host_id": NUMERIC_ID, "server_id": NUMERIC_ID, "server_name": STRING,
            "project_name": STRING}, additionalProperties=True),
        "WorkspaceResource": obj({"resource_id": STRING, "host_id": NUMERIC_ID, "name": STRING,
            "project": STRING, "protocol": PROTOCOL, "owner": STRING, "environment": STRING,
            "tags": {"type": "object", "additionalProperties": STRING},
            "access": obj({"state": STRING, "reason": STRING, "next_action": STRING, "url": STRING}),
            "connect_url": {"type": ["string", "null"]}, "details_url": STRING}, additionalProperties=True),
        "ConnectionRequest": obj({"host_id": NUMERIC_ID, "protocol": PROTOCOL}, ["host_id"], additionalProperties=False),
        "Connection": obj({"ticket": {"type": "string", "description": "Secret, short-lived, single-use credential. Never log or persist."},
            "connection_id": STRING, "expires_at": {"type": "number"}, "host_id": NUMERIC_ID,
            "protocol": PROTOCOL, "approval_required": BOOLEAN, "gateway_host": STRING,
            "gateway_port": INTEGER, "websocket_url": STRING, "audit_profile": STRING},
            ["ticket", "connection_id", "expires_at", "host_id", "protocol"]),
        "JobRequest": obj({"type": {"type": "string", "enum": ["command", "runbook"]},
            "host_id": NUMERIC_ID, "command": STRING, "runbook_id": STRING,
            "parameters": obj(additionalProperties=True), "timeout": {"type": "integer", "minimum": 1},
            "confirm": {"const": True}}, ["type", "host_id", "confirm"], additionalProperties=False),
        "Job": obj({"job_id": STRING, "id": STRING, "status": STRING}, additionalProperties=True),
        "TerminalPreferences": terminal,
        "Preferences": obj({"favorites": array(STRING), "recent": array(STRING), "terminal": ref("TerminalPreferences")},
            ["favorites", "recent", "terminal"]),
        "PreferencesPatch": obj({"favorites": array(STRING), "terminal": ref("TerminalPreferences")}, additionalProperties=False),
        "BookmarkInput": obj({"seconds": {"type": "number", "minimum": 0, "maximum": 604800},
            "label": {"type": "string", "minLength": 1, "maxLength": 160}}, ["seconds", "label"], additionalProperties=False),
        "Bookmark": obj({"id": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
            "seconds": {"type": "number"}, "label": STRING, "created_at": {"type": "number"}},
            ["id", "seconds", "label", "created_at"]),
        "Bookmarks": obj({"bookmarks": array(ref("Bookmark"))}, ["bookmarks"]),
        "AuditPage": obj({"events": array(obj(additionalProperties=True)),
            "next": {"description": "Opaque JSON cursor; send its JSON encoding as before.", "type": ["array", "null"], "items": {}}},
            ["events", "next"]),
        "Health": obj({"ok": BOOLEAN, "status": STRING,
            "checks": {"type": "object", "additionalProperties": obj({"ok": BOOLEAN}, ["ok"])}}, ["ok", "checks"]),
        "Ready": obj({"ready": BOOLEAN}, ["ready"]),
        "Version": obj({"schema_version": INTEGER, "version": STRING, "revision": {"type": ["string", "null"]}}, additionalProperties=True),
        "Confirmation": obj({"confirm": {"const": True}}, ["confirm"], additionalProperties=False),
    }


def response(description, schema=None, media="application/json"):
    value = {"description": description}
    if schema is not None:
        value["content"] = {media: {"schema": schema}}
    return value


def query(name, schema=STRING, description=None):
    value = {"name": name, "in": "query", "required": False, "schema": schema}
    if description:
        value["description"] = description
    return value


def body(schema, maximum=None):
    value = {"required": True, "content": {"application/json": {"schema": schema}}}
    if maximum:
        value["description"] = "JSON object; maximum {} bytes.".format(maximum)
        value["x-max-body-bytes"] = maximum
    return value


def operation(name, summary, schema=None, *, security=BEARER, parameters=(), request_body=None,
              success="200", description="", errors=(400, 401, 403, 404, 503)):
    value = {"operationId": name, "summary": summary, "description": description,
        "security": security, "responses": {success: response("Success", schema)}}
    for status in errors:
        value["responses"][str(status)] = {"$ref": "#/components/responses/Error"}
    if parameters:
        value["parameters"] = list(parameters)
    if request_body:
        value["requestBody"] = request_body
    return value


def catalogue():
    paging = [query("q"), query("project"), query("offset", {"type": "integer", "minimum": 0}),
        query("limit", {"type": "integer", "minimum": 1, "maximum": 500, "default": 100})]
    history = [query(name) for name in ("query", "project", "host", "since", "until", "result", "limit")]
    audit = [query(name) for name in ("q", "event", "host_id", "connection_id", "since", "until", "before", "limit")]
    paths = {
        "/api/v1/me": {"get": operation("getIdentity", "Inspect the verified bearer identity", ref("Identity"))},
        "/api/v1/resources": {"get": operation("listResources", "List authorized SSH resources",
            obj({"resources": array(ref("Resource")), "next_offset": NEXT_OFFSET}, ["resources", "next_offset"]), parameters=paging)},
        "/api/v1/connections": {"post": operation("createConnection", "Issue a single-use protocol connection ticket", ref("Connection"),
            security=MUTATION, request_body=body(ref("ConnectionRequest"), 4096), success="201",
            description="Rechecks protocol grants, admission, approval and step-up policy. Browser sessions require X-CSRF-Token. Tickets are credentials; do not put them in Terraform state.",
            errors=(400, 401, 403, 404, 413, 415, 429, 503))},
        "/api/v1/history": {"get": operation("getHistory", "Read the caller's connection history", obj({"history": array(obj(additionalProperties=True))}, ["history"]),
            parameters=history)},
        "/api/v1/jobs": {"post": operation("createJob", "Submit an explicitly confirmed command or runbook", ref("Job"),
            security=MUTATION, request_body=body(ref("JobRequest"), 65536), success="201", parameters=[{"$ref": "#/components/parameters/IdempotencyKey"}],
            description="Requires the configured submitter action and matching OAuth scope. Idempotent replay returns 200; conflicting or uncertain submissions return 409. Does not execute a shell on the API listener.",
            errors=(400, 401, 403, 404, 409, 413, 415, 429, 503))},
        "/api/v1/jobs/{job_id}": {"get": operation("getJob", "Read an owned job or a job visible to a platform administrator",
            obj({"job": ref("Job")}, ["job"]))},
        "/api/v1/audit": {"get": operation("searchAudit", "Search the scoped audit index", ref("AuditPage"), security=BROWSER,
            parameters=audit, description="The SQL index is derived from audit evidence; this API does not expose the control store. Disabled indexes return 404.")},
        "/api/v1/workspace/preferences": {
            "get": operation("getPreferences", "Read preferences bound to the stable verified subject", ref("Preferences"), security=BROWSER),
            "patch": operation("updatePreferences", "Update favorites and terminal preferences", ref("Preferences"), security=MUTATION,
                request_body=body(ref("PreferencesPatch"), 16384), errors=(400, 401, 403, 404, 413, 415, 503))},
        "/api/v1/workspace/resources": {"get": operation("listWorkspaceResources", "List protocol resources and access guidance",
            obj({"resources": array(ref("WorkspaceResource")), "total": INTEGER, "next_offset": NEXT_OFFSET}, ["resources", "total", "next_offset"]),
            security=BROWSER, parameters=paging[:3] + [query("limit", {"type": "integer", "minimum": 1, "maximum": 100, "default": 48}),
                query("protocol", PROTOCOL), query("view", {"type": "string", "enum": ["all", "favorites", "recent"], "default": "all"})])},
        "/api/v1/recordings/{connection_id}/bookmarks": {
            "get": operation("listBookmarks", "Read subject-private recording bookmarks", ref("Bookmarks"), security=BROWSER,
                description="Recording ownership or project-scoped audit permission is checked on every request."),
            "post": operation("createBookmark", "Add a subject-private bookmark", ref("Bookmarks"), security=MUTATION,
                request_body=body(ref("BookmarkInput"), 2048), success="201", errors=(400, 401, 403, 404, 409, 413, 415, 503),
                description="At most 100 bookmarks per subject/recording. The audit intent is persisted before the mutation.")},
        "/api/v1/recordings/{connection_id}/bookmarks/{bookmark_id}": {
            "delete": operation("deleteBookmark", "Delete a subject-private recording bookmark", ref("Bookmarks"), security=MUTATION,
                errors=(400, 401, 403, 404, 409, 503))},
        "/auth/backchannel-logout": {"post": operation("backchannelLogout", "Receive a signed OIDC backchannel logout token", security=[],
            request_body={"required": True, "content": {"application/x-www-form-urlencoded": {"schema":
                obj({"logout_token": STRING}, ["logout_token"], additionalProperties=False)}}},
            description="Authenticates the IdP-signed logout_token, including issuer, audience, event and replay checks. No browser CSRF applies. Enabled only by explicit identity-security configuration; maximum 65536 bytes.",
            errors=(400, 404, 413, 503))},
        "/health": {"get": operation("getHealth", "Read reduced dependency health", ref("Health"), security=[], errors=(503,))},
        "/ready": {"get": operation("getReadiness", "Check control-store and cluster readiness", ref("Ready"), security=[], errors=(404, 503))},
        "/api/v1/version": {"get": operation("getVersion", "Read build and control schema versions", ref("Version"), security=[], errors=(404,))},
        "/api/v1/openapi.json": {"get": operation("getOpenAPIJSON", "Read this OpenAPI contract", obj(additionalProperties=True), security=[], errors=(404,))},
        "/api/v1/openapi.yaml": {"get": operation("getOpenAPIYAML", "Read this OpenAPI contract as YAML", STRING, security=[], errors=(404,))},
    }
    paths["/api/v1/jobs"]["post"]["responses"]["200"] = response("Previously completed submission with the same idempotency key", ref("Job"))
    paths["/api/v1/openapi.yaml"]["get"]["responses"]["200"] = response("OpenAPI YAML", STRING, "application/yaml")
    for kind, plural, scope in (("host", "hosts", "isolate.inventory.write"), ("grant", "grants", "isolate.policy.write")):
        title = kind.title()
        envelope = obj({kind: ref(title)}, [kind])
        input_envelope = obj({kind: ref(title + "Input"), "confirm": {"const": True}}, [kind, "confirm"], additionalProperties=False)
        description = ("Requires an explicitly authorized administrative identity and OAuth scope {}. "
            "Browser administrators require a CSRF header and confirm=true. Workload identities require explicit allowed_actions "
            "and admin_projects configuration; no human groups are inherited. Reads and mutations are constrained to administrative projects. "
            "Returned records omit SSH credentials. Broader grant selectors require explicit global administration.").format(scope)
        collection = "/api/v1/admin/" + plural
        paths[collection] = {
            "get": operation("listAdmin" + plural.title(), "List administratively visible " + plural,
                obj({plural: array(ref(title))}, [plural]), security=BROWSER, description=description),
            "post": operation("createAdmin" + title, "Create a confirmed " + kind, envelope, security=MUTATION, success="201",
                parameters=[{"$ref": "#/components/parameters/IdempotencyKey"}], request_body=body(input_envelope, 65536),
                description=description + " Idempotent replay returns 200; uncertain or conflicting create returns 409.",
                errors=(400, 401, 403, 404, 409, 413, 415, 429, 503)),
        }
        paths[collection]["post"]["responses"]["200"] = response("Previously completed idempotent create", envelope)
        paths[collection + "/{" + kind + "_id}"] = {
            "get": operation("getAdmin" + title, "Read a " + kind + " with its revision", envelope, security=BROWSER, description=description),
            "put": operation("updateAdmin" + title, "Update a confirmed " + kind + " at its current revision", envelope,
                security=MUTATION, parameters=[{"$ref": "#/components/parameters/IfMatch"}], request_body=body(input_envelope, 65536),
                description=description + " PUT accepts a partial record. Terraform sends the complete set of its managed fields. Missing If-Match returns 428; stale revision returns 409.",
                errors=(400, 401, 403, 404, 409, 413, 415, 428, 429, 503)),
            "delete": operation("deleteAdmin" + title, "Delete a confirmed " + kind + " at its current revision",
                security=MUTATION, success="204", parameters=[{"$ref": "#/components/parameters/IfMatch"}],
                request_body=body(ref("Confirmation"), 65536), description=description + " Missing If-Match returns 428; stale revision returns 409.",
                errors=(400, 401, 403, 404, 409, 413, 415, 428, 429, 503)),
        }
        for item in paths[collection].values():
            item["x-required-oauth-scopes"] = [scope]
        for item in paths[collection + "/{" + kind + "_id}"].values():
            item["x-required-oauth-scopes"] = [scope]
    for route, methods in paths.items():
        parameters = []
        for name in re.findall(r"\{([^}]+)\}", route):
            schema = NUMERIC_ID if name in ("host_id", "grant_id", "job_id") else STRING
            parameters.append({"name": name, "in": "path", "required": True, "schema": schema})
        for method in methods.values():
            method.setdefault("parameters", []).extend(parameters)
    return paths


def registered_operations(app):
    """Return only actual HTTP control operations, excluding implicit HEAD/OPTIONS."""
    operations = set()
    for rule in app.url_map.iter_rules():
        if not (rule.rule.startswith("/api/") or rule.rule in PUBLIC_PATHS):
            continue
        path = re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", r"{\1}", rule.rule)
        operations.update((path, method.lower()) for method in rule.methods if method.lower() in HTTP_METHODS)
    return operations


def undocumented_operations(app):
    documented = {(path, method) for path, operations in catalogue().items() for method in operations}
    return sorted(registered_operations(app) - documented)


def build_openapi(app=None):
    paths = catalogue()
    if app is not None:
        missing = undocumented_operations(app)
        if missing:
            raise ValueError("OpenAPI contract missing registered operations: " + repr(missing))
        active = registered_operations(app)
        paths = {path: {method: value for method, value in operations.items() if (path, method) in active}
                 for path, operations in paths.items() if any((path, method) in active for method in operations)}
    document = {
        "openapi": "3.1.1",
        "info": {"title": "Isolate Control API", "version": "1.0.0", "description":
            "Versioned control-plane API. The configured SQL or legacy Redis control store remains private. "
            "Use verified OIDC tokens matching the configured token_kind and audience; Keycloak remains supported. "
            "The browser login redirects and HTML management pages are not control API operations. "
            "SSH/WebSocket/database/HTTP/Kubernetes streaming listeners have separate transport contracts."},
        "servers": [{"url": "/", "description": "Same trusted HTTPS control origin"}],
        "security": BEARER,
        "paths": paths,
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "OIDC JWT", "description":
                    "Verified token from the configured issuer with expected audience and explicit scopes. Use access_token for workload/API clients; legacy id_token configurations remain supported. Session tickets are not bearer tokens."},
                "BrowserSession": {"type": "apiKey", "in": "cookie", "name": "session", "description":
                    "Existing verified browser session. Only operations explicitly listing this alternative accept it."},
                "CSRFToken": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token", "description":
                    "Session-bound CSRF value required together with browser authentication on mutations; not required with a bearer access token."},
            },
            "parameters": {
                "IdempotencyKey": {"name": "Idempotency-Key", "in": "header", "required": True,
                    "schema": {"type": "string", "minLength": 16, "maxLength": 128},
                    "description": "Unique opaque printable key for one create intent; reuse only with the identical request."},
                "IfMatch": {"name": "If-Match", "in": "header", "required": True,
                    "schema": {"type": "string"}, "description": "Current opaque _revision, raw or double-quoted. No wildcard/blind writes."},
            },
            "schemas": schemas(),
            "responses": {"Error": {"description":
                "Request rejected. 401: missing/malformed authentication; 403: policy, scope, CSRF or step-up; "
                "404: disabled/unavailable/not visible; 409: conflict or uncertain outcome; 428: revision missing; "
                "429: admission limit; 503: required dependency or evidence unavailable. "
                "Flask request-validation errors can use HTML rather than JSON.",
                "headers": {"Retry-After": {"schema": STRING}, "WWW-Authenticate": {"schema": STRING}},
                "content": {"application/json": {"schema": ref("Error")}, "text/html": {"schema": STRING}}}},
        },
    }
    return copy.deepcopy(document)


def register_openapi_routes(app, config):
    """Register public read-only contract endpoints, gated by api.enabled."""
    from flask import abort, jsonify, Response

    def enabled():
        if not config.get("api", {}).get("enabled", False):
            abort(404)

    @app.get("/api/v1/version")
    def api_version():
        enabled()
        from isolate_state import SCHEMA_VERSION
        from isolate_build import get_build_info
        build = get_build_info(config)
        return jsonify(version=build.get("version"), revision=build.get("revision"), schema_version=SCHEMA_VERSION)

    @app.get("/api/v1/openapi.json")
    def api_openapi_json():
        enabled()
        return jsonify(build_openapi(app))

    @app.get("/api/v1/openapi.yaml")
    def api_openapi_yaml():
        enabled()
        import yaml
        return Response(yaml.safe_dump(build_openapi(app), sort_keys=False, allow_unicode=True), mimetype="application/yaml")
