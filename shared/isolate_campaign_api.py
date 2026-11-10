"""Scoped runbook campaign API and server-rendered preview/confirmation flow."""
import html
import json
import secrets

from isolate_campaigns import (CampaignError, can_view, cancel_campaign, create_campaign,
    get_campaign, list_campaigns, preview_campaign, public_campaign)
from isolate_jobs import JobError


def register_campaign_api(app, config, runtime_factory, bearer, bounded_json, failure, errors, csrf_token):
    from flask import abort, jsonify, make_response, redirect, request
    from isolate_mcp import MCPAccessDenied

    handled = (CampaignError, JobError, MCPAccessDenied) + errors

    def current(mutation=False, form=False):
        if form:
            supplied = request.form.get('csrf_token', '')
            if not supplied or not secrets.compare_digest(supplied, csrf_token()):
                abort(403)
            origin = request.headers.get('Origin')
            if origin and origin != str(config.get('dashboard', {}).get('public_url') or '').rstrip('/'):
                abort(403)
        token = bearer(allow_browser=True, mutation=mutation and not form)
        service = runtime_factory()
        return service, service.authenticate(token), token

    def selected(service, identity, identifier):
        record = get_campaign(service.redis, identifier)
        if not can_view(record, identity, config):
            abort(404)
        return record

    def admission(service, identity):
        from isolate_admission import check_admission
        check_admission(service.redis, {'admission': dict(config.get('admission', {}), enabled=True)},
            identity['keycloak_sub'], request.remote_addr, kind='job')

    @app.post('/api/v1/runbook-campaigns/preview')
    def api_campaign_preview():
        try:
            service, identity, token = current(mutation=True)
            result = preview_campaign(service.redis, config, identity, bounded_json(65536), token)
            response = jsonify(result)
            response.headers['Cache-Control'] = 'no-store'
            return response
        except handled as exc:
            return failure(exc)

    @app.post('/api/v1/runbook-campaigns')
    def api_campaign_create():
        try:
            service, identity, token = current(mutation=True)
            admission(service, identity)
            record, created = create_campaign(service.redis, config, identity, bounded_json(65536), token,
                request.headers.get('Idempotency-Key'))
            return jsonify(campaign=public_campaign(service.redis, record)), 201 if created else 200
        except handled as exc:
            return failure(exc)

    @app.get('/api/v1/runbook-campaigns')
    def api_campaign_list():
        try:
            service, identity, token = current()
            return jsonify(campaigns=list_campaigns(service.redis, identity, config, request.args.get('limit', 50)))
        except handled as exc:
            return failure(exc)

    @app.get('/api/v1/runbook-campaigns/<identifier>')
    def api_campaign_detail(identifier):
        try:
            service, identity, token = current()
            return jsonify(campaign=public_campaign(service.redis, selected(service, identity, identifier)))
        except handled as exc:
            return failure(exc)

    @app.post('/api/v1/runbook-campaigns/<identifier>/cancel')
    def api_campaign_cancel(identifier):
        try:
            service, identity, token = current(mutation=True)
            selected(service, identity, identifier)
            payload = bounded_json(1024)
            if set(payload) != {'confirm'}:
                abort(400)
            record = cancel_campaign(service.redis, config, identifier, identity, payload.get('confirm'))
            return jsonify(campaign=public_campaign(service.redis, record))
        except handled as exc:
            return failure(exc)

    def page(title, body):
        from isolate_web import _html
        response = make_response(_html(title, body, config=dict(config, dashboard=dict(config.get('dashboard', {}), refresh_seconds=0))))
        response.headers.update({'Cache-Control': 'no-store', 'Referrer-Policy': 'same-origin'})
        return response

    def csrf():
        return '<input type="hidden" name="csrf_token" value="{}">'.format(html.escape(csrf_token(), quote=True))

    @app.get('/operations/campaigns')
    def campaign_page():
        try:
            service, identity, token = current()
            records = list_campaigns(service.redis, identity, config)
            from isolate_runbooks import list_runbooks
            from isolate_mcp import IsolateMCPService, token_scopes
            submitter = IsolateMCPService(config, service.redis)
            allowed = [row for row in list_runbooks(config) if submitter._runbook_access_error(identity,
                token_scopes(identity.get('raw_claims') or {}), row['class']) is None]
            choices = ''.join('<option value="{}">{}</option>'.format(html.escape(row['id'], quote=True), html.escape(row['title']))
                for row in allowed)
            body = '<h1>Staged runbook operations</h1><p>Run a small canary first, then bounded batches. Unknown outcomes always stop expansion; jobs are never retried automatically.</p>'
            form = '<form method="post" action="/operations/campaigns/preview">' + csrf()
            form += '<p><label>Runbook <select name="runbook_id">' + choices + '</select></label></p>'
            form += '<p><label>Target host IDs, separated by commas <input name="host_ids" required placeholder="10001,10002,10003"></label></p>'
            form += '<p><label>Parameters (JSON) <textarea name="parameters">{}</textarea></label></p>'
            for name, title, value in (('canary_count', 'Canary hosts', 1), ('batch_size', 'Batch size', 5),
                    ('failure_budget', 'Allowed failures after canary', 0), ('max_failure_percent', 'Maximum failure percentage', 100)):
                form += '<p><label>{} <input type="number" name="{}" value="{}" min="0" required></label></p>'.format(title, name, value)
            form += '<button type="submit">Review plan</button></form>'
            body += form if allowed else '<p>No runbooks are currently available for your identity. Existing campaign history remains available below.</p>'
            body += '<h2>Campaign history</h2><ul>'
            body += ''.join('<li><a href="/operations/campaigns/{}">{}</a> · {} · {}</li>'.format(record['id'],
                html.escape(record['runbook_id']), html.escape(record['status']), html.escape(record['stop_reason'] or '')) for record in records)
            body += '</ul>'
            return page('Staged runbook operations', body)
        except handled as exc:
            return failure(exc)

    @app.post('/operations/campaigns/preview')
    def campaign_preview_page():
        try:
            if request.content_length is not None and request.content_length > 65536:
                abort(413)
            service, identity, token = current(mutation=True, form=True)
            body = {'runbook_id': request.form.get('runbook_id'),
                'host_ids': [value.strip() for value in request.form.get('host_ids', '').split(',') if value.strip()],
                'parameters': _form_json(request.form.get('parameters', '{}'))}
            for name in ('canary_count', 'batch_size', 'failure_budget', 'max_failure_percent'):
                body[name] = int(request.form.get(name, ''))
            preview = preview_campaign(service.redis, config, identity, body, token)
            body['preview_digest'] = preview['preview_digest']
            body['confirm'] = True
            content = '<h1>Review campaign</h1><p>Canary: {} host(s). Later batches: {}. Failure budget: {}. Maximum failure rate: {}%.</p>'.format(
                preview['canary_count'], preview['batch_size'], preview['failure_budget'], preview['max_failure_percent'])
            content += '<p>The canary must succeed completely. Expired or revoked authorization, uncertain outcomes and configured failure thresholds stop new work.</p><ol>'
            for target in preview['targets']:
                content += '<li>{} · {} · {} · {}</li>'.format(*(html.escape(str(target[name])) for name in ('id', 'name', 'project', 'remote_user')))
            content += '</ol><form method="post" action="/operations/campaigns/create">' + csrf()
            content += '<input type="hidden" name="body" value="{}"><input type="hidden" name="idempotency_key" value="{}">'.format(
                html.escape(json.dumps(body), quote=True), secrets.token_urlsafe(24))
            content += '<label><input type="checkbox" name="confirm" value="true" required> I reviewed the targets and stop conditions</label><button type="submit">Start canary</button></form>'
            return page('Review campaign', content)
        except handled as exc:
            return failure(exc)

    @app.post('/operations/campaigns/create')
    def campaign_create_page():
        try:
            service, identity, token = current(mutation=True, form=True)
            if request.form.get('confirm') != 'true' or len(request.form.get('body', '')) > 65536:
                abort(400)
            admission(service, identity)
            record, created = create_campaign(service.redis, config, identity, _form_json(request.form['body']), token,
                request.form.get('idempotency_key'))
            return redirect('/operations/campaigns/' + record['id'], code=303)
        except handled as exc:
            return failure(exc)

    def _form_json(value):
        try:
            return json.loads(value)
        except (ValueError, RecursionError, OverflowError):
            abort(400, description='a bounded JSON object is required')

    @app.get('/operations/campaigns/<identifier>')
    def campaign_detail_page(identifier):
        try:
            service, identity, token = current()
            record = public_campaign(service.redis, selected(service, identity, identifier))
            body = '<h1>Campaign {}</h1><p>{} · stage {} · {}</p>'.format(html.escape(record['runbook_id']), html.escape(record['status']), record['current_stage'], html.escape(record['stop_reason'] or ''))
            body += '<p><a href="/investigations?kind=campaign&amp;id={}">Investigate campaign</a> · <a href="/operations/campaigns">All campaigns</a></p><ul>'.format(identifier)
            for child in record['jobs']:
                body += '<li>Host {} · stage {} · {} · <a href="/investigations?kind=job&amp;id={}">Job {}</a></li>'.format(
                    html.escape(child['host_id']), child['stage'], html.escape(child['status']), child['id'], child['id'])
            body += '</ul>'
            if record['status'] == 'active':
                body += '<form method="post" action="/operations/campaigns/{}/cancel">{}<label><input type="checkbox" name="confirm" value="true" required> Stop future batches and request cancellation of active jobs</label><button>Stop campaign</button></form>'.format(identifier, csrf())
            return page('Campaign status', body)
        except handled as exc:
            return failure(exc)

    @app.post('/operations/campaigns/<identifier>/cancel')
    def campaign_cancel_page(identifier):
        try:
            service, identity, token = current(mutation=True, form=True)
            selected(service, identity, identifier)
            cancel_campaign(service.redis, config, identifier, identity, request.form.get('confirm') == 'true')
            return redirect('/operations/campaigns/' + identifier, code=303)
        except handled as exc:
            return failure(exc)
