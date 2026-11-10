"""HTTP and browser presentation for visibility-scoped access explanations."""
import html
import json
import re
import secrets
from urllib.parse import urlencode

from isolate_access_explain import ExplanationError, explain_resource, preview_policy_impact


def explanation_link(host_id, protocol='ssh', action=None, russian=False):
    if not str(host_id).isdigit():
        return ''
    query = urlencode({'protocol': protocol, **({'action': action} if action else {})})
    label = 'Почему такой доступ?' if russian else 'Why this access?'
    return '<a class="access-explanation-link" href="{}">{}</a>'.format(
        html.escape('/workspace/access/' + str(host_id) + '?' + query, quote=True), label)


def explanation_panel(host_id, protocol='ssh', action=None, russian=False):
    if not str(host_id).isdigit():
        return ''
    query = urlencode({'protocol': protocol, **({'action': action} if action else {})})
    endpoint = '/api/v1/access/explain/' + str(host_id) + '?' + query
    return ('<details class="access-explanation" data-access-explanation="{}" data-language="{}">'
        '<summary>{}</summary><div data-explanation-result role="status" aria-live="polite">{}</div></details>'
        '<script src="/static/access-explain.js" defer></script>').format(html.escape(endpoint, quote=True),
            'ru' if russian else 'en', 'Почему такой доступ?' if russian else 'Why this access?',
            'Откройте, чтобы проверить действующие правила.' if russian else 'Open to check the current policy and requirements.')


def register_explain_api(app, config, runtime_factory, bearer, bounded_json, failure, errors, csrf_token=None):
    from flask import abort, jsonify, request, make_response, session

    def form_csrf():
        if csrf_token:
            return csrf_token()
        if not session.get('csrf_token'):
            session['csrf_token'] = secrets.token_urlsafe(32)
        return session['csrf_token']

    def request_explanation(host_id):
        unknown = set(request.args) - {'protocol', 'action', 'lang'}
        if unknown:
            raise ExplanationError(400, 'unsupported_explanation_parameters')
        control = runtime_factory()
        token = bearer(allow_browser=True)
        identity = control.authenticate(token)
        return explain_resource(control, identity, host_id, protocol=request.args.get('protocol', 'ssh'),
            action=request.args.get('action'), token=token, source_ip=request.remote_addr)

    def explanation_failure(exc):
        response = jsonify(error=exc.code)
        response.headers['Cache-Control'] = 'no-store'
        return response, exc.status

    @app.get('/api/v1/access/explain/<host_id>')
    def api_access_explanation(host_id):
        try:
            response = jsonify(request_explanation(host_id))
            response.headers['Cache-Control'] = 'no-store'
            return response
        except ExplanationError as exc:
            return explanation_failure(exc)
        except errors as exc:
            return failure(exc)

    @app.get('/workspace/access/<host_id>')
    def workspace_access_explanation(host_id):
        try:
            result = request_explanation(host_id)
        except ExplanationError as exc:
            abort(exc.status)
        except errors as exc:
            return failure(exc)
        from isolate_web import _html
        russian = request.args.get('lang') == 'ru'
        title = 'Объяснение доступа' if russian else 'Access explanation'
        body = '<h1>{}</h1><p>{} · {}</p>'.format(title, html.escape(str(result['resource']['name'])),
            html.escape(str(result['resource']['project'])))
        body += '<p>{}</p><ul>'.format(html.escape(result['summary']))
        for check in result['checks']:
            body += '<li>{}: {}</li>'.format(html.escape(check['status']), html.escape(check['message']))
        body += '</ul>'
        selected = result['policy'].get('selected_grant')
        if selected:
            body += '<p>{}: <strong>{}</strong></p>'.format('Правило' if russian else 'Selected rule',
                html.escape(str(selected.get('id') or 'policy')))
        body += '<p>{}</p>'.format(html.escape(result['policy']['precedence_note']))
        action = result.get('next_action')
        if action:
            body += '<p><a href="{}">{}</a></p>'.format(html.escape(action['url'], quote=True), html.escape(action['label']))
        body += '<p>{}</p><p><a href="/workspace">{}</a></p>'.format(html.escape(result['notice']),
            'К ресурсам' if russian else 'Back to resources')
        response = make_response(_html(title, body, config=config))
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/api/v1/admin/policy/impact')
    def api_policy_impact():
        token = bearer(allow_browser=True, mutation=True)
        body = bounded_json(32768)
        if set(body) - {'grant', 'replace_grant_id', 'remove', 'project', 'max_entries'}:
            abort(400)
        if body.get('project') is not None and (not isinstance(body['project'], str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', body['project'])):
            abort(400)
        try:
            control = runtime_factory()
            identity = control.authenticate(token)
            # Keep the same explicit bearer scope as actual policy mutations.
            # A browser administrator uses its signed session plus CSRF.
            from isolate_admin_api import _projects, AdminError
            try:
                _projects(config, identity, 'policy.write', browser=not bool(request.headers.get('Authorization')))
            except AdminError as exc:
                raise ExplanationError(exc.status, exc.error) from None
            result = preview_policy_impact(control, identity, body.get('grant'),
                replace_grant_id=body.get('replace_grant_id'), remove=body.get('remove', False),
                project=body.get('project'), max_entries=body.get('max_entries', 500))
            response = jsonify(result)
            response.headers['Cache-Control'] = 'no-store'
            return response
        except ExplanationError as exc:
            return explanation_failure(exc)
        except errors as exc:
            return failure(exc)

    @app.route('/policy/impact', methods=['GET', 'POST'])
    def browser_policy_impact():
        from isolate import load_grants
        from isolate_permissions import is_platform_admin
        from isolate_web import _html, _table
        from isolate_admin_api import _projects, AdminError
        control = runtime_factory()
        try:
            identity = control.authenticate(bearer(allow_browser=True))
            if not is_platform_admin(identity, config) or identity.get('principal_type') == 'service':
                abort(403)
            _projects(config, identity, 'policy.write', browser=not bool(request.headers.get('Authorization')))
        except AdminError as exc:
            abort(exc.status)
        except errors as exc:
            return failure(exc)
        identifier = request.values.get('grant_id', '')
        if identifier and not re.fullmatch(r'[0-9]{1,20}', identifier):
            abort(400)
        selected = next((row for row in load_grants(control.redis) if str(row.get('id')) == identifier), None) if identifier else None
        if identifier and selected is None:
            abort(404)
        fields = {'subject', 'name', 'keycloak_sub', 'project', 'project_glob', 'project_set', 'host',
            'remote_user', 'sudo_mode', 'allowed_actions', 'starts_at', 'expires_at'}
        initial = {key: value for key, value in (selected or {}).items() if key in fields} if selected else {
            'subject': 'group', 'name': 'Support', 'project': 'stage', 'remote_user': 'observer',
            'sudo_mode': 'none', 'allowed_actions': ['ssh']}
        raw = request.form.get('grant', json.dumps(initial, indent=2, sort_keys=True))
        mode = request.form.get('mode', 'replace' if identifier else 'add')
        project = request.values.get('project', '')
        result, notice, status = None, None, 200
        if request.method == 'POST':
            if request.content_length is not None and request.content_length > 40000:
                abort(413)
            if not secrets.compare_digest(request.form.get('csrf_token', ''), form_csrf()):
                abort(403)
            if mode not in ('add', 'replace', 'remove') or mode in ('replace', 'remove') and not identifier:
                abort(400)
            if project and not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', project):
                abort(400)
            try:
                candidate = None if mode == 'remove' else json.loads(raw)
                if mode != 'remove' and not isinstance(candidate, dict):
                    raise ValueError()
                result = preview_policy_impact(control, identity, candidate,
                    replace_grant_id=identifier if mode != 'add' else None, remove=mode == 'remove', project=project or None)
            except ExplanationError as exc:
                notice, status = {'level': 'error', 'text': 'Preview unavailable: ' + exc.code}, exc.status
            except (ValueError, TypeError, RecursionError):
                notice, status = {'level': 'error', 'text': 'Enter a valid JSON grant object.'}, 400
        token = form_csrf()
        body = ('<h1>Policy impact preview</h1><p class="page-lead">Compare a proposed assignment change with current policy before saving it.</p>'
            '<p>This page only previews. Group and role rows are policy scenarios, not a complete IdP membership census. '
            'Current lifecycle restrictions, MFA, session approvals and target settings still apply.</p>'
            '<form method="post" action="/policy/impact"><input type="hidden" name="csrf_token" value="{}">'
            '<p><label>Change <select name="mode">{}</select></label> '
            '<label>Existing grant ID <input name="grant_id" value="{}" inputmode="numeric" placeholder="Required for replace/remove"></label> '
            '<label>Limit to project <input name="project" value="{}" placeholder="Optional exact project"></label></p>'
            '<p><label>Proposed grant JSON (a partial object is allowed for replacement)<br>'
            '<textarea name="grant" rows="14" cols="90" style="max-width:100%;width:100%" spellcheck="false">{}</textarea></label></p>'
            '<p><button type="submit">Preview impact</button> <a href="/grants">Back to grants</a></p></form>').format(
                html.escape(token, quote=True), ''.join('<option value="{}"{}>{}</option>'.format(value,
                    ' selected' if mode == value else '', label) for value, label in (('add', 'Add'), ('replace', 'Replace'), ('remove', 'Remove'))),
                html.escape(identifier, quote=True), html.escape(project, quote=True), html.escape(raw))
        if result is not None:
            body += '<h2>Preview result</h2><p role="status">Gained: {} · Lost: {} · Changed: {}</p>'.format(
                result['counts']['gained'], result['counts']['lost'], result['counts']['changed'])
            rows = []
            for item in result['impacts']:
                def summary(value):
                    if not value['allowed']:
                        return 'Denied: ' + value['reason_code']
                    return '{} · {} · rule {}'.format(value.get('remote_user'), value.get('sudo_mode'),
                        (value.get('selected_grant') or {}).get('id'))
                rows.append({'change': item['change'], 'principal': str(item['subject']) + ':' + str(item['name']),
                    'project': item['project'], 'resource': item['resource_name'], 'action': item['action'],
                    'before': summary(item['before']), 'after': summary(item['after'])})
            body += _table(rows, [('change', 'Change'), ('principal', 'Principal scenario'), ('project', 'Project'),
                ('resource', 'Resource'), ('action', 'Action'), ('before', 'Before'), ('after', 'After')]) if rows else '<p>No effective policy changes were found in this snapshot.</p>'
            body += '<p>{}</p>'.format(html.escape(result['membership_notice']))
            if result['truncated']:
                body += '<p>Result rows are truncated; use an exact project filter to review a smaller change.</p>'
        response = make_response(_html('Policy impact preview', body, config=config, notice=notice), status)
        response.headers['Cache-Control'] = 'no-store'
        return response
