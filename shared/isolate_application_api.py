"""Browser-safe launch of an application on its isolated gateway origin."""
import html
import secrets
from urllib.parse import urlsplit


def launch_form(host_id, csrf, *, russian=False):
    action = "/workspace/application/" + str(host_id) + "/launch"
    return ('<form method="post" action="{}"><input type="hidden" name="csrf_token" value="{}">'
            '<input type="hidden" name="confirm" value="true"><button type="submit">{}</button></form>').format(
                html.escape(action, quote=True), html.escape(csrf, quote=True),
                "Открыть приложение" if russian else "Open application")


def register_application_api(app, config, runtime_factory, bearer, bounded_json, failure, errors, csrf_token):
    from flask import abort, jsonify, request, session, Response

    def create(token, host_id):
        if not config.get("web_apps", {}).get("enabled") or not str(host_id).isdigit():
            abort(404)
        from isolate_web_apps import create_launch
        return create_launch(runtime_factory(), token, str(host_id), source_ip=request.remote_addr,
                             browser_session=session.get("runtime_session") if not request.headers.get("Authorization") else None)

    @app.post("/api/v1/web-apps/<host_id>/launch")
    def api_web_application_launch(host_id):
        token = bearer(allow_browser=True, mutation=True)
        payload = bounded_json(1024)
        if set(payload) != {"confirm"} or payload.get("confirm") is not True:
            abort(400, description="explicit confirm=true is required")
        try:
            response = jsonify(create(token, host_id))
            response.headers["Cache-Control"] = "no-store"
            return response, 201
        except errors as exc:
            return failure(exc)

    @app.post("/workspace/application/<host_id>/launch")
    def browser_web_application_launch(host_id):
        if request.content_length and request.content_length > 2048:
            abort(413)
        supplied = request.form.get("csrf_token", "")
        if not supplied or not secrets.compare_digest(supplied, csrf_token()) or request.form.get("confirm") != "true":
            abort(403)
        if request.headers.get("Origin") and request.headers["Origin"] != str(config.get("dashboard", {}).get("public_url") or "").rstrip("/"):
            abort(403)
        try:
            result = create(bearer(allow_browser=True), host_id)
        except errors as exc:
            return failure(exc)
        destination = result["launch_url"]
        parsed = urlsplit(destination)
        origin = "https://" + parsed.netloc
        nonce = secrets.token_urlsafe(24)
        # The credential travels in a form POST body, never in a redirect URL,
        # referrer, access log, or shared browser cookie domain.
        body = ('<!doctype html><html><head><meta charset="utf-8"><title>Opening application</title></head>'
                '<body><p>Opening application…</p><form method="post" action="{}">'
                '<input type="hidden" name="code" value="{}"><button type="submit">Continue</button></form>'
                '<script nonce="{}">document.forms[0].submit()</script></body></html>').format(
                    html.escape(destination, quote=True), html.escape(result["code"], quote=True), nonce)
        response = Response(body, content_type="text/html; charset=utf-8")
        # no-referrer makes browsers send Origin:null on this cross-site form
        # navigation. Keep only the control origin so launch CSRF validation can
        # verify it, without revealing resource paths or any POST credentials.
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "strict-origin",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action " + origin + "; script-src 'nonce-" + nonce + "'"})
        return response
