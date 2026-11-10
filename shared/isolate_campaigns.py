"""Durable canary-first runbook campaigns; ambiguous outcomes never advance.

Each child is a normal signed, delegated job. The campaign and held children are
published together. SQL/Redis WATCH fences stage promotion across controllers;
workers independently check the signed campaign binding before and during SSH.
"""
import hashlib
import hmac
import json
import re
import secrets
import time

from redis.exceptions import WatchError
from isolate_jobs import (JobError, _runbook_submission_plan, _signing_key,
    create_runbook_job, get_job, verify_job_signature)
from isolate_state import state_epoch


class CampaignError(ValueError):
    pass


ACTIVE = frozenset(('active',))
FINAL = frozenset(('completed', 'stopped', 'cancelled', 'recovery_required'))
JOB_FINAL = frozenset(('completed', 'failed', 'timed_out', 'cancelled', 'recovery_required'))
IMMUTABLE = ('id', 'subject', 'username', 'projects', 'runbook_id', 'definition_sha256',
    'parameters_sha256', 'created_at', 'expires_at', 'epoch', 'plan_digest', 'stages',
    'jobs', 'failure_budget', 'max_failure_percent', 'identity_session_sha256')


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _load(raw):
    return json.loads(raw) if raw is not None else None


def _key(identifier):
    if not isinstance(identifier, str) or re.fullmatch(r'[a-f0-9]{32}', identifier) is None:
        raise CampaignError('campaign was not found')
    return 'runbook_campaign_' + identifier


def _sign(record, config):
    record['signature'] = hmac.new(_signing_key(config), _json({k: record.get(k) for k in IMMUTABLE}).encode(), hashlib.sha256).hexdigest()
    progress = {key: record.get(key) for key in ('signature', 'status', 'current_stage', 'stop_reason', 'finished_at', 'events', 'updated_at')}
    record['progress_signature'] = hmac.new(_signing_key(config), _json(progress).encode(), hashlib.sha256).hexdigest()
    return record


def _verify(record, config):
    expected = _sign(dict(record), config)
    if (not hmac.compare_digest(str(record.get('signature') or ''), expected['signature'])
            or not hmac.compare_digest(str(record.get('progress_signature') or ''), expected['progress_signature'])):
        raise CampaignError('campaign authorization signature is invalid')


def _stage_events(target, config, record, events):
    from isolate_workflow_audit import stage_event
    actor = {'keycloak_sub': record['subject'], 'username': record['username']}
    for event in events:
        for project in record['projects']:
            stage_event(target, config, event['event'], actor, project=project, campaign_id=record['id'],
                runbook_id=record['runbook_id'], stage=event['stage'], status=event.get('status', record['status']),
                reason_code=event.get('reason'), identity_session_sha256=record.get('identity_session_sha256'))


def _publish(redis, config):
    # A publication outage after EXEC must not misreport the committed action
    # as failed. The retained evidence/pending outbox is retried by the worker.
    from isolate_workflow_audit import publish_pending
    try:
        publish_pending(redis, config, limit=100)
    except Exception:
        return


def terminal_result_receipt(redis, config, job, updates, owner):
    """Sign a worker-observed terminal result; normal authorization is separate."""
    record = get_campaign(redis, job['campaign_id'])
    _verify(record, config)
    merged = dict(job, **updates)
    value = {key: merged.get(key) for key in ('id', 'campaign_id', 'campaign_stage', 'campaign_slot',
        'authorization_signature', 'status', 'exit_code', 'finished_at')}
    value.update(version=1, execution_owner=owner, epoch=record['epoch'])
    value['signature'] = hmac.new(_signing_key(config), _json(value).encode(), hashlib.sha256).hexdigest()
    return value


def _verified_result(redis, config, record, job):
    receipt = job.get('campaign_result')
    if not isinstance(receipt, dict):
        return False
    signature = receipt.get('signature')
    payload = {key: value for key, value in receipt.items() if key != 'signature'}
    expected = hmac.new(_signing_key(config), _json(payload).encode(), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        return False
    for key in ('id', 'campaign_id', 'campaign_stage', 'campaign_slot', 'authorization_signature', 'status', 'exit_code', 'finished_at'):
        if receipt.get(key) != job.get(key):
            return False
    claim = _load(redis.get('job_execution_claim_' + job['id']))
    return bool(receipt.get('version') == 1 and receipt.get('epoch') == record['epoch'] and claim
        and receipt.get('execution_owner') == claim.get('owner') == job.get('execution_owner'))


def _event(record, name, **fields):
    record.setdefault('events', []).append({'event': name, 'ts': time.time(), 'campaign_id': record['id'],
        'keycloak_sub': record['subject'], 'username': record['username'], 'projects': record['projects'],
        'runbook_id': record['runbook_id'], 'stage': record.get('current_stage', 0), **fields})
    record['updated_at'] = int(time.time())


def get_campaign(redis, identifier):
    return _load(redis.get(_key(identifier)))


def can_view(record, identity, config):
    from isolate_permissions import is_platform_admin
    return bool(record and (record.get('subject') == identity.get('keycloak_sub') or is_platform_admin(identity, config)))


def public_campaign(redis, record):
    fields = ('id', 'subject', 'username', 'projects', 'runbook_id', 'created_at', 'expires_at',
        'updated_at', 'status', 'stop_reason', 'current_stage', 'failure_budget', 'max_failure_percent', 'events')
    result = {key: record.get(key) for key in fields}
    result['stages'] = [{'index': index, 'kind': 'canary' if index == 0 else 'batch', 'job_ids': stage}
        for index, stage in enumerate(record['stages'])]
    result['jobs'] = []
    for item in record['jobs']:
        job = get_job(redis, item['id']) or {}
        result['jobs'].append({**item, 'status': job.get('status', 'missing'),
            'exit_code': job.get('exit_code'), 'cancel_requested': job.get('cancel_requested', False)})
    return result


def list_campaigns(redis, identity, config, limit=50):
    identifiers = []
    for key in redis.scan_iter(match='runbook_campaign_*'):
        key = key.decode() if isinstance(key, bytes) else key
        if re.fullmatch(r'runbook_campaign_[a-f0-9]{32}', key):
            record = _load(redis.get(key))
            if can_view(record, identity, config):
                identifiers.append(record)
    identifiers.sort(key=lambda row: (row['created_at'], row['id']), reverse=True)
    return [public_campaign(redis, record) for record in identifiers[:max(1, min(100, int(limit)))]]


def _settings(config):
    options = config.get('campaigns') or {}
    if options.get('enabled') is not True:
        raise CampaignError('staged runbook campaigns are disabled')
    return options


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise CampaignError('{} must be an integer from {} to {}'.format(name, low, high))
    return value


def _plan(redis, config, identity, body, token):
    options = _settings(config)
    if not token or (config.get('identity_security', {}).get('delegation') or {}).get('enabled') is not True:
        raise CampaignError('campaigns require a verified token and enabled bounded job delegation')
    if not isinstance(body, dict) or set(body) - {'runbook_id', 'host_ids', 'parameters', 'timeout', 'canary_count', 'batch_size', 'failure_budget', 'max_failure_percent', 'preview_digest', 'confirm'}:
        raise CampaignError('unsupported campaign fields')
    host_ids = body.get('host_ids')
    if (not isinstance(host_ids, list) or not host_ids or any(type(value) not in (str, int) or not str(value).isdigit() for value in host_ids)
            or len(set(map(str, host_ids))) != len(host_ids)):
        raise CampaignError('host_ids must be a nonempty list of distinct numeric IDs')
    maximum = min(1000, int(options.get('max_hosts', 100)), int(config.get('runbooks', {}).get('max_fleet_hosts') or 100))
    if len(host_ids) > maximum:
        raise CampaignError('campaign exceeds the configured target limit')
    if body.get('timeout') is not None:
        _integer(body['timeout'], 'timeout', 1, int(config.get('command_execution', {}).get('max_timeout', 900)))
    canary = _integer(body.get('canary_count', 1), 'canary_count', 1, min(10, len(host_ids)))
    batch = _integer(body.get('batch_size', 5), 'batch_size', 1, min(50, int(options.get('max_batch_size', 50))))
    budget = _integer(body.get('failure_budget', 0), 'failure_budget', 0, len(host_ids))
    percent = _integer(body.get('max_failure_percent', 100), 'max_failure_percent', 0, 100)
    rendered, planned, timeout = _runbook_submission_plan(redis, config, identity, body.get('runbook_id'), host_ids,
        parameters=body.get('parameters'), timeout=body.get('timeout'), token=token)
    from isolate_mcp import IsolateMCPService, token_scopes
    IsolateMCPService(config, redis)._require_runbook_submitter(identity,
        token_scopes(identity.get('raw_claims') or {}), rendered['runbook']['class'])
    routes = [{'id': str(host['server_id']), 'name': host.get('server_name', ''), 'project': host['project_name'],
        'address': host['server_ip'], 'port': int(host.get('server_port') or 22),
        'remote_user': decision['remote_user'], 'sudo_mode': decision['sudo_mode'],
        'grant_sha256': hashlib.sha256(_json(decision.get('matched_rule')).encode()).hexdigest()}
        for host, decision in planned]
    effective = {'runbook_id': rendered['runbook']['id'], 'definition_sha256': rendered['runbook']['definition_sha256'],
        'parameters_sha256': hashlib.sha256(_json(rendered['parameters']).encode()).hexdigest(),
        'subject': identity['keycloak_sub'], 'routes': routes, 'timeout': timeout,
        'canary_count': canary, 'batch_size': batch, 'failure_budget': budget, 'max_failure_percent': percent,
        'epoch': state_epoch(redis)}
    effective['plan_digest'] = hashlib.sha256(_json(effective).encode()).hexdigest()
    return effective, rendered, planned


def preview_campaign(redis, config, identity, body, token):
    effective, rendered, planned = _plan(redis, config, identity, body, token)
    return {'preview_digest': effective['plan_digest'], 'runbook_id': effective['runbook_id'],
        'runbook_title': rendered['runbook']['title'], 'canary_count': effective['canary_count'],
        'batch_size': effective['batch_size'], 'failure_budget': effective['failure_budget'],
        'max_failure_percent': effective['max_failure_percent'],
        'targets': [{key: route[key] for key in ('id', 'name', 'project', 'remote_user', 'sudo_mode')} for route in effective['routes']],
        'stop_on_unknown': True, 'automatic_retries': False}


def create_campaign(redis, config, identity, body, token, idempotency_key):
    if not isinstance(idempotency_key, str) or not 16 <= len(idempotency_key) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in idempotency_key):
        raise CampaignError('Idempotency-Key must contain 16-128 printable non-space characters')
    if not isinstance(body, dict) or body.get('confirm') is not True:
        raise CampaignError('explicit confirm=true is required')
    effective, rendered, planned = _plan(redis, config, identity, body, token)
    if body.get('preview_digest') != effective['plan_digest']:
        raise CampaignError('preview is missing or changed; review a fresh preview before submission')
    submission_key = 'campaign_submission_' + hashlib.sha256((identity['keycloak_sub'] + ':' + idempotency_key).encode()).hexdigest()
    request_digest = hashlib.sha256(_json(body).encode()).hexdigest()
    existing = _load(redis.get(submission_key))
    if existing:
        if existing.get('digest') != request_digest:
            raise CampaignError('idempotency key was already used for a different campaign')
        return get_campaign(redis, existing['id']), False
    identifier = secrets.token_hex(16)
    epoch = effective['epoch']
    stages = [list(range(effective['canary_count']))]
    stages += [list(range(i, min(i + effective['batch_size'], len(planned))))
        for i in range(effective['canary_count'], len(planned), effective['batch_size'])]
    children = []
    for index, (host, decision) in enumerate(planned):
        stage = next(number for number, slots in enumerate(stages) if index in slots)
        children.append(create_runbook_job(redis, config, identity, host, decision, rendered,
            timeout=effective['timeout'], token=token, publish=False,
            campaign={'campaign_id': identifier, 'campaign_stage': stage, 'campaign_slot': index}))
    record = {'id': identifier, 'subject': identity['keycloak_sub'], 'username': identity['username'],
        'projects': sorted(set(host['project_name'] for host, decision in planned)),
        'runbook_id': effective['runbook_id'], 'definition_sha256': effective['definition_sha256'],
        'parameters_sha256': effective['parameters_sha256'], 'created_at': int(time.time()),
        'expires_at': min(job['delegation_expires_at'] for job in children), 'epoch': epoch,
        'plan_digest': effective['plan_digest'], 'failure_budget': effective['failure_budget'],
        'max_failure_percent': effective['max_failure_percent'], 'status': 'active', 'current_stage': 0,
        'jobs': [{'id': job['id'], 'host_id': job['host_id'], 'project': job['project'], 'stage': job['campaign_stage'], 'slot': job['campaign_slot']} for job in children],
        'stages': [[children[index]['id'] for index in slots] for slots in stages]}
    from isolate_investigations import identity_session_reference
    record['identity_session_sha256'] = identity_session_reference(identity)
    _event(record, 'campaign_created', host_count=len(children))
    _event(record, 'campaign_stage_started', job_ids=record['stages'][0])
    _sign(record, config)
    for _ in range(16):
        with redis.pipeline() as pipe:
            try:
                pipe.watch(submission_key, _key(identifier), 'isolate_authority_epoch')
                existing = _load(pipe.get(submission_key))
                if existing:
                    if existing.get('digest') != request_digest:
                        raise CampaignError('idempotency key was already used for a different campaign')
                    return get_campaign(redis, existing['id']), False
                if state_epoch(redis) != epoch:
                    raise CampaignError('authority changed while the campaign was prepared')
                pipe.multi()
                for job in children:
                    job['status'] = 'queued' if job['campaign_stage'] == 0 else 'held'
                    pipe.set('job_' + job['id'], _json(job))
                pipe.set(_key(identifier), _json(record))
                pipe.set('runbook_campaign_active_' + identifier, identifier)
                pipe.set(submission_key, _json({'id': identifier, 'digest': request_digest}))
                _stage_events(pipe, config, record, record['events'])
                pipe.execute()
                _publish(redis, config)
                return record, True
            except WatchError:
                continue
    raise CampaignError('campaign changed concurrently; review submission before retrying')


def _child(record, job):
    return next((value for value in record['jobs'] if value['id'] == job['id']), None)


def check_campaign_job(redis, config, job):
    if not job.get('campaign_id') and int(job.get('schema_version') or 1) < 4:
        return
    record = get_campaign(redis, job.get('campaign_id'))
    if record is None:
        raise CampaignError('campaign owner is unavailable')
    _verify(record, config)
    child = _child(record, job)
    if (not child or child['host_id'] != job.get('host_id') or child['stage'] != job.get('campaign_stage')
            or child['slot'] != job.get('campaign_slot') or record['subject'] != job.get('keycloak_sub')
            or record['runbook_id'] != job.get('runbook_id') or record['definition_sha256'] != job.get('runbook_definition_sha256')
            or record['status'] != 'active' or record['current_stage'] != job.get('campaign_stage')
            or record['epoch'] != state_epoch(redis) or record['expires_at'] <= time.time()):
        raise CampaignError('campaign is stopped, expired, changed or outside the active stage')


def _stop(record, children, reason, status='stopped'):
    record.update(status=status, stop_reason=reason, finished_at=int(time.time()))
    for job in children.values():
        if job and job.get('status') not in JOB_FINAL:
            job.update(cancel_requested=True, cancel_requested_by='campaign-controller', cancel_requested_at=int(time.time()))
            if job.get('status') in ('held', 'queued'):
                job.update(status='cancelled', finished_at=int(time.time()))
    _event(record, 'campaign_stopped', reason=reason, status=status)


def _transition(redis, config, identifier, change):
    key = _key(identifier)
    for _ in range(16):
        with redis.pipeline() as pipe:
            try:
                pipe.watch(key)
                record = _load(pipe.get(key))
                if record is None:
                    raise CampaignError('campaign was not found')
                _verify(record, config)
                keys = ['job_' + child['id'] for child in record['jobs']]
                pipe.watch(*keys, 'isolate_authority_epoch')
                children = {child['id']: _load(pipe.get('job_' + child['id'])) for child in record['jobs']}
                before = _json(record), _json(children)
                first_event = len(record.get('events', []))
                change(record, children)
                if before == (_json(record), _json(children)):
                    return record
                pipe.multi()
                _sign(record, config)
                pipe.set(key, _json(record))
                if record['status'] in FINAL:
                    pipe.delete('runbook_campaign_active_' + identifier)
                for job in children.values():
                    if job:
                        pipe.set('job_' + job['id'], _json(job))
                _stage_events(pipe, config, record, record.get('events', [])[first_event:])
                pipe.execute()
                _publish(redis, config)
                return record
            except WatchError:
                continue
    raise CampaignError('campaign state changed concurrently')


def reconcile_campaign(redis, config, identifier):
    def change(record, children):
        if record['status'] not in ACTIVE:
            return
        try:
            _verify(record, config)
            if record['epoch'] != state_epoch(redis):
                return _stop(record, children, 'stale_epoch')
            if _settings(config) is None or record['expires_at'] <= time.time():
                return _stop(record, children, 'authorization_expired')
            if any(not job or not verify_job_signature(job, config) for job in children.values()):
                return _stop(record, children, 'missing_or_changed_child', status='recovery_required')
            if any(job['status'] == 'recovery_required' or job['status'] in ('claimed', 'running')
                    and _lease_owner(redis, job['id']) != job.get('execution_owner') for job in children.values()):
                return _stop(record, children, 'unknown_outcome', status='recovery_required')
            # A killed SSH process cannot prove the remote command stopped.
            # Transport failures (255), timeouts and local execution failures
            # never spend a configurable budget to authorize more targets.
            if any(job['status'] == 'timed_out' or job['status'] == 'failed'
                    and (type(job.get('exit_code')) is not int or not 1 <= job['exit_code'] <= 254)
                    for job in children.values()):
                return _stop(record, children, 'unknown_outcome', status='recovery_required')
            if any(job['status'] == 'cancelled' for job in children.values()):
                return _stop(record, children, 'child_cancelled')
            if any(job['status'] in ('completed', 'failed') and not _verified_result(redis, config, record, job)
                    for job in children.values()):
                return _stop(record, children, 'unverified_child_result', status='recovery_required')
            active = [children[job_id] for job_id in record['stages'][record['current_stage']]]
            failed = sum(job['status'] in ('failed', 'timed_out', 'cancelled') for job in children.values())
            finished = sum(job['status'] in JOB_FINAL for job in children.values())
            if record['current_stage'] == 0 and any(job['status'] in ('failed', 'timed_out', 'cancelled') for job in active):
                return _stop(record, children, 'canary_failed')
            if failed > record['failure_budget']:
                return _stop(record, children, 'failure_budget_exceeded')
            if finished and failed * 100 > record['max_failure_percent'] * finished:
                return _stop(record, children, 'failure_rate_exceeded')
            from isolate_delegation import recheck_delegation
            from isolate_inventory import get_host
            for job in active:
                if job['status'] not in JOB_FINAL:
                    recheck_delegation(redis, config, job, get_host(redis, job['host_id']) or {})
            if not all(job['status'] in JOB_FINAL for job in active):
                return
            next_stage = record['current_stage'] + 1
            if next_stage == len(record['stages']):
                record.update(status='completed', finished_at=int(time.time()))
                return _event(record, 'campaign_completed', failures=failed)
            for job_id in record['stages'][next_stage]:
                job = children[job_id]
                if job['status'] != 'held':
                    return _stop(record, children, 'unexpected_child_state', status='recovery_required')
                recheck_delegation(redis, config, job, get_host(redis, job['host_id']) or {})
            record['current_stage'] = next_stage
            for job_id in record['stages'][next_stage]:
                children[job_id]['status'] = 'queued'
            _event(record, 'campaign_stage_started', job_ids=record['stages'][next_stage])
        except Exception:
            _stop(record, children, 'authorization_or_control_unavailable')
    return _transition(redis, config, identifier, change)


def reconcile_campaigns(redis, config):
    for key in redis.scan_iter(match='runbook_campaign_active_*', count=100):
        key = key.decode() if isinstance(key, bytes) else key
        if re.fullmatch(r'runbook_campaign_active_[a-f0-9]{32}', key):
            try:
                reconcile_campaign(redis, config, key.removeprefix('runbook_campaign_active_'))
            except CampaignError:
                # A damaged signed campaign can never authorize a child. Leave
                # its original evidence for review instead of re-signing it.
                continue
    _publish(redis, config)


def _lease_owner(redis, identifier):
    raw = redis.get('job_lock_' + identifier)
    return raw.decode() if isinstance(raw, bytes) else raw


def cancel_campaign(redis, config, identifier, identity, confirmed=False):
    if confirmed is not True:
        raise CampaignError('explicit confirmation is required')
    def change(record, children):
        if not can_view(record, identity, config):
            raise CampaignError('campaign was not found')
        if record['status'] not in FINAL:
            _stop(record, children, 'cancelled_by_user', status='cancelled')
    return _transition(redis, config, identifier, change)
