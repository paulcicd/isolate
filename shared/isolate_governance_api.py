"""Scoped access-lifecycle API and the management workspace."""
import html
import secrets
import time
from functools import wraps

import isolate_governance as governance


def register_governance_api(app, config, runtime_factory, bearer, bounded_json, failure, errors, csrf_token):
    from flask import abort, jsonify, redirect, request

    def context(mutation=False, form=False):
        token = bearer(allow_browser=True, mutation=mutation and not form)
        runtime = runtime_factory()
        identity = runtime.authenticate(token)
        if identity.get('principal_type') == 'service':
            raise governance.GovernanceError('human_governance_operator_required', 403)
        return runtime.redis, identity

    def guarded(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            try:
                result = function(*args, **kwargs)
                response = app.make_response(result)
                response.headers['Cache-Control'] = 'no-store'
                return response
            except governance.GovernanceError as exc:
                return jsonify(error=exc.error), exc.status
            except errors as exc:
                return failure(exc)
        return wrapper

    def payload(fields):
        body = bounded_json(8192)
        if body.get('confirm') is not True or set(body) - set(fields) - {'confirm'}:
            abort(400, description='explicit confirm=true and supported fields are required')
        return {key: value for key, value in body.items() if key != 'confirm'}

    def complete(store, record, status=200):
        # Domain/evidence already committed. A down sink leaves a retryable
        # outbox; never ask clients to repeat the access mutation to republish.
        governance.publish_pending(store, config)
        # Publisher totals include other projects. Expose only this mutation's
        # durable evidence guarantee, never global queue activity to an owner.
        return jsonify(result=record, audit_delivery={'status': 'retained', 'publication': 'retryable_outbox'}), status

    @app.get('/api/v1/governance')
    @guarded
    def governance_dashboard():
        store, identity = context()
        return jsonify(governance.dashboard(store, config, identity, request.args.get('project')))

    @app.post('/api/v1/governance/reviews')
    @guarded
    def governance_review_create():
        store, identity = context(True)
        body = payload(('project', 'reason', 'due_at', 'owner_subject'))
        if not {'project', 'reason'} <= set(body):
            abort(400)
        record = governance.create_review(store, config, identity, idempotency_key=request.headers.get('Idempotency-Key'), **body)
        return complete(store, record, 201)

    @app.post('/api/v1/governance/reviews/<review_id>/decisions')
    @guarded
    def governance_review_decision(review_id):
        store, identity = context(True)
        body = payload(('grant_id', 'decision', 'reason'))
        if set(body) != {'grant_id', 'decision', 'reason'}:
            abort(400)
        return complete(store, governance.decide_review(store, config, identity, review_id, **body))

    @app.post('/api/v1/governance/assignments')
    @guarded
    def governance_assignment_create():
        store, identity = context(True)
        body = payload(('project', 'subject_id', 'username', 'remote_user', 'expires_at', 'starts_at', 'allowed_actions', 'category', 'reason'))
        if not {'project', 'subject_id', 'username', 'remote_user', 'expires_at', 'reason'} <= set(body):
            abort(400)
        return complete(store, governance.create_assignment(store, config, identity,
            idempotency_key=request.headers.get('Idempotency-Key'), **body), 201)

    @app.post('/api/v1/governance/assignments/<assignment_id>/revoke')
    @guarded
    def governance_assignment_revoke(assignment_id):
        store, identity = context(True)
        body = payload(('reason',))
        if set(body) != {'reason'}:
            abort(400)
        return complete(store, governance.revoke_assignment(store, config, identity, assignment_id, body['reason']))

    @app.post('/api/v1/governance/offboarding')
    @guarded
    def governance_offboarding():
        store, identity = context(True)
        body = payload(('subject_id', 'project', 'reason'))
        if set(body) != {'subject_id', 'project', 'reason'}:
            abort(400)
        return complete(store, governance.offboard(store, config, identity, **body))

    def field(name, label, value='', kind='text', required=True):
        return '<label>{}<input name="{}" type="{}" value="{}"{}></label>'.format(
            html.escape(label), html.escape(name), kind, html.escape(str(value), quote=True), ' required' if required else '')

    def form(operation, contents, label, **hidden):
        hidden.update(operation=operation, csrf_token=csrf_token())
        inputs = ''.join('<input type="hidden" name="{}" value="{}">'.format(html.escape(key), html.escape(str(value), quote=True)) for key, value in hidden.items())
        return ('<form method="post" action="/workspace/governance/actions">{}{}'
            '<label>Reason<input name="reason" required maxlength="2048"></label>'
            '<label><input type="checkbox" name="confirm" value="true" required> Confirm this access change</label>'
            '<button type="submit">{}</button></form>').format(inputs, contents, html.escape(label))

    def timestamp(value):
        import datetime
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if value else '—'

    @app.get('/workspace/governance')
    @guarded
    def governance_workspace():
        store, identity = context()
        data = governance.dashboard(store, config, identity, request.args.get('project'))
        projects = data['projects']
        body = '<section class="governance-workspace"><h1>Access lifecycle</h1><p>Review current access, track temporary assignments and end access with durable offboarding decisions.</p>'
        body += '<p><a href="/workspace/admin">Administration</a> · <a href="/workspace">Resources</a></p>'
        body += '<h2>Review schedule</h2><table><tr><th>Project</th><th>Last completed</th><th>Next review due</th></tr>'
        for schedule in data['review_schedule']:
            body += '<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(html.escape(schedule['project']), timestamp(schedule['last_completed_at']), timestamp(schedule['next_due_at']))
        body += '</table>'
        body += '<h2>Due and expiring</h2>'
        if not data['reminders']:
            body += '<p>No outstanding reminders.</p>'
        else:
            body += '<table><tr><th>Project</th><th>Action</th><th>Due</th></tr>'
            for item in data['reminders']:
                body += '<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(html.escape(item['project']), html.escape(item['kind'].replace('_', ' ')), timestamp(item['due_at']))
            body += '</table>'
        owner_projects = [p for p in projects if governance.has_permission(identity, config, 'access.approve', p)
                          and governance.has_permission(identity, config, 'inventory.write', p)]
        if owner_projects:
            options = '<label>Project<select name="project">' + ''.join('<option>{}</option>'.format(html.escape(p)) for p in owner_projects) + '</select></label>'
            body += '<section class="card"><h2>Start an owner review</h2>'
            body += '<p>A review freezes the visible grants. Keeping access records a decision without extending its expiry. Changed grants require a fresh review.</p>'
            body += form('create_review', options, 'Start review', intent=secrets.token_hex(16)) + '</section>'
            body += '<section class="card"><h2>Temporary or contractor assignment</h2><p>Assignments require an immutable provider-bound subject, expire within 90 days, and never grant sudo/root. Expiry does not remove any independent group access.</p>'
            body += form('assignment', options + field('subject_id', 'Stable subject') + field('username', 'Display username')
                + field('remote_user', 'Target account', 'support') + field('expires_days', 'Expires in days', '7', 'number')
                + field('allowed_actions', 'Actions (comma separated)', 'ssh,webssh'), 'Create assignment', intent=secrets.token_hex(16)) + '</section>'
            body += '<section class="card"><h2>End access</h2><p>Offboarding blocks this subject even when group or externally managed grants still exist. It does not delete the IdP account or rewrite GitOps policy. Reboarding needs an independent reviewed procedure.</p>'
            body += form('offboard', options + field('subject_id', 'Stable subject'), 'End project access') + '</section>'
        if governance.is_platform_admin(identity, config):
            body += '<section class="card"><h2>Global offboarding</h2>' + form('offboard', field('subject_id', 'Stable subject'), 'End all Isolate access', project='*') + '</section>'
        body += '<h2>Owner reviews</h2>'
        for review in sorted(data['reviews'], key=lambda item: item['created_at'], reverse=True):
            body += '<section class="card"><h3>{} · {}</h3><p>Owner: {} · Due: {}</p>'.format(html.escape(review['project']), html.escape(review['status']), html.escape(review['owner_subject']), timestamp(review['due_at']))
            for item in review['items']:
                body += '<p>Grant #{} · {} {} · {} · {}</p>'.format(html.escape(item['grant_id']), html.escape(str(item.get('subject', ''))), html.escape(str(item.get('name', ''))), html.escape(str(item.get('remote_user', ''))), html.escape(item.get('decision') or 'Awaiting review'))
                body += '<p><a href="/investigations?kind=grant&amp;id={}">Grant timeline</a></p>'.format(html.escape(item['grant_id']))
                if review['status'] == 'open' and not item.get('decision') and review['project'] in owner_projects:
                    choices = '<label>Decision<select name="decision"><option value="keep">Keep current access</option><option value="revoke">Revoke this rule</option><option value="removed">Confirm externally removed</option></select></label>'
                    body += form('review', choices, 'Record decision', review_id=review['id'], grant_id=item['grant_id'])
            body += '</section>'
        body += '<h2>Assignments</h2><table><tr><th>User / project</th><th>Expiry</th><th>Status</th><th>Action</th></tr>'
        for assignment in data['assignments']:
            action = form('revoke_assignment', '', 'Revoke assignment', assignment_id=assignment['id']) if assignment['project'] in owner_projects and assignment['status'] == 'active' else '—'
            body += '<tr><td>{} / {}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(html.escape(assignment['username']), html.escape(assignment['project']), timestamp(assignment['expires_at']), html.escape(assignment.get('effective_status', assignment['status'])), action)
        body += '</table><h2>Review candidates</h2><p>These findings are prompts for an owner review, not proof that access is unused or unnecessary. No rights are removed automatically.</p>'
        for finding in data['findings']:
            body += '<p>Grant #{} / {}: {}</p>'.format(html.escape(finding['grant_id']), html.escape(finding['project']), html.escape(', '.join(finding['reasons'])))
        body += '<h2>Offboarding decisions</h2>'
        for row in data['offboardings']:
            body += '<p>{} / {} · blocked · {}</p>'.format(html.escape(row['subject_id']), html.escape(row['project']), timestamp(row['created_at']))
        from isolate_web import _html
        body += '''</section><style>.governance-workspace{max-width:1100px;overflow-wrap:anywhere}.governance-workspace .card{padding:20px;margin:20px 0;border:1px solid var(--line);border-radius:12px;background:var(--surface)}
.governance-workspace form{display:grid;gap:12px;max-width:650px;margin:14px 0}.governance-workspace label{display:grid;gap:5px}.governance-workspace label:has(input[type=checkbox]){display:flex;align-items:center;gap:8px}
.governance-workspace input,.governance-workspace select{max-width:100%;width:100%;box-sizing:border-box}.governance-workspace input[type=checkbox]{width:auto}.governance-workspace button{justify-self:start}.governance-workspace table{table-layout:fixed;width:100%}.governance-workspace td,.governance-workspace th{min-width:0;white-space:normal;overflow-wrap:anywhere}</style>'''
        return _html('Access lifecycle', body, config=config)

    @app.post('/workspace/governance/actions')
    @guarded
    def governance_workspace_action():
        if request.content_length is not None and request.content_length > 8192:
            abort(413)
        supplied = request.form.get('csrf_token', '')
        if not supplied or not secrets.compare_digest(supplied, csrf_token()) or request.form.get('confirm') != 'true':
            abort(403)
        origin = request.headers.get('Origin')
        if origin and origin != str(config.get('dashboard', {}).get('public_url') or '').rstrip('/'):
            abort(403)
        store, identity = context(True, form=True)
        values = request.form
        operation, reason = values.get('operation'), values.get('reason')
        if operation == 'create_review':
            governance.create_review(store, config, identity, values.get('project'), reason, idempotency_key=values.get('intent'))
        elif operation == 'review':
            governance.decide_review(store, config, identity, values.get('review_id'), values.get('grant_id'), values.get('decision'), reason)
        elif operation == 'assignment':
            try:
                days = int(values.get('expires_days', ''))
            except ValueError:
                abort(400)
            governance.create_assignment(store, config, identity, project=values.get('project'), subject_id=values.get('subject_id'), username=values.get('username'),
                remote_user=values.get('remote_user'), expires_at=int(time.time()) + days * 86400, reason=reason,
                allowed_actions=[value.strip() for value in values.get('allowed_actions', '').split(',') if value.strip()], idempotency_key=values.get('intent'))
        elif operation == 'revoke_assignment':
            governance.revoke_assignment(store, config, identity, values.get('assignment_id'), reason)
        elif operation == 'offboard':
            governance.offboard(store, config, identity, values.get('subject_id'), values.get('project'), reason)
        else:
            abort(400)
        governance.publish_pending(store, config)
        return redirect('/workspace/governance', code=303)
