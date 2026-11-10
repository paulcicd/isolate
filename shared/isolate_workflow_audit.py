"""Transactional workflow evidence and retryable publication.

Call stage_event inside the domain transaction. A retained, signed event and a
pending key commit with the state change. Publication can repeat after failure;
the same event ID and payload make SQL ingestion idempotent. It never replays the
access mutation itself or claims a rolled-back change has committed.
"""
import json
import os
import re
import time
import uuid

from isolate_audit import append_jsonl_record, classify_audit_record, dispatch_audit_record, sign_audit_record


class WorkflowAuditError(ValueError):
    pass


def stage_event(target, config, event, actor, project=None, **fields):
    if config is None:
        return None
    if not isinstance(event, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,95}", event):
        raise WorkflowAuditError('invalid workflow event')
    if any(any(part in key.lower() for part in ('token', 'password', 'secret', 'private_key', 'command_text')) for key in fields):
        raise WorkflowAuditError('credentials do not belong in workflow evidence')
    identifier = uuid.uuid4().hex
    record = dict(ts=time.time(), event_id=identifier, event=event, outcome='committed', source='isolate-workflow',
        keycloak_sub=(actor or {}).get('keycloak_sub'), username=(actor or {}).get('username'), project=project, **fields)
    record = sign_audit_record(classify_audit_record(record), (config or {}).get('logging', {}))
    encoded = json.dumps(record, sort_keys=True)
    target.set('workflow_event_' + identifier, encoded)
    target.set('workflow_pending_' + identifier, encoded)
    return record


def publish_pending(store, config, limit=100):
    """Publish only committed immutable evidence; leave failures pending."""
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise WorkflowAuditError('invalid publication bound')
    published = 0
    failures = 0
    keys = list(store.keys('workflow_pending_*'))
    for key in sorted(keys)[:limit]:
        raw = store.get(key)
        if raw is None:
            continue
        try:
            record = json.loads(raw)
            identifier = record['event_id']
            key_text = key.decode() if isinstance(key, bytes) else key
            if (not re.fullmatch(r'[a-f0-9]{32}', identifier) or key_text != 'workflow_pending_' + identifier
                    or record.get('outcome') != 'committed' or not isinstance(record.get('ts'), (int, float))):
                raise WorkflowAuditError('workflow evidence is malformed')
            retained = store.get('workflow_event_' + identifier)
            if retained is None or json.loads(retained) != record:
                raise WorkflowAuditError('workflow evidence differs from its retained source')
            logging = dict(config.get('logging') or {}, fail_closed=True, sync=True)
            base = logging.get('base_path')
            if base:
                parent = os.path.join(base, 'workflows')
                os.makedirs(parent, mode=0o700, exist_ok=True)
                if os.path.islink(parent):
                    raise WorkflowAuditError('workflow evidence directory cannot be a symlink')
                append_jsonl_record(os.path.join(parent, 'audit.jsonl'), record, mode=0o600, sync=True)
            dispatch_audit_record(record, logging)
            if config.get('audit_index', {}).get('enabled'):
                from isolate_audit_index import AuditIndex
                AuditIndex(config['audit_index']).ingest(record)
            # The source record stays durable even after publication succeeds.
            store.delete(key)
            published += 1
        except Exception:
            failures += 1
    return {'published': published, 'pending': len(keys) - published, 'failed': failures}
