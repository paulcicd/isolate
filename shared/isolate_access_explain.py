"""Read-only, visibility-scoped access diagnostics and policy impact previews.

Diagnostics never mint a ticket, consume approval or contact a target. The grant
resolver remains the sole policy authority; explanations preserve its selected
rule precedence, including deny-by-omission. They are snapshots, not capabilities.
"""
import copy
import hashlib
import json
import re
import time

from isolate_policy import PolicyDenied, grant_specificity, matching_grants, resolve_grant
from isolate_permissions import has_permission, is_platform_admin

ACTION = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
PROTOCOLS = frozenset(('ssh', 'webssh', 'http', 'kubernetes', 'postgresql', 'mysql'))


class ExplanationError(ValueError):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def _defaults(config):
    return {**config.get('policy', {}), **config.get('ssh', {})}


def _verified(identity):
    if not isinstance(identity, dict) or not identity.get('keycloak_sub') or not identity.get('username'):
        raise ExplanationError(403, 'verified_identity_required')


def _selected_public(grant, config, admin=False):
    if not grant:
        return None
    result = {key: grant[key] for key in ('id', 'temporary', 'starts_at', 'expires_at') if key in grant}
    result.update(temporary=bool(grant.get('temporary')), specificity=grant_specificity(grant), precedence='first-most-specific-active-rule',
        allowed_actions=grant.get('allowed_actions') or ['ssh'])
    if admin:
        result.update({key: grant.get(key) for key in ('subject', 'name', 'project', 'project_glob', 'project_set',
            'host', 'remote_user', 'sudo_mode', 'managed_by')})
    return result


def policy_explanation(config, identity, host, grants, project_sets, action='ssh', admin=False):
    """Evaluate exactly one action using actual resolver order and defaults."""
    if not isinstance(action, str) or not ACTION.fullmatch(action):
        raise ExplanationError(400, 'invalid_action')
    matches = matching_grants(identity, project=host.get('project_name'), host=host,
        grants=grants, project_sets=project_sets)
    selected = matches[0] if matches else None
    result = {'allowed': False, 'reason_code': 'no_matching_grant', 'missing_actions': [],
        'selected_grant': _selected_public(selected, config, admin),
        'precedence_note': 'The selected active rule is checked first. Actions from other rules are not combined.'}
    if selected:
        if action not in (selected.get('allowed_actions') or ['ssh']):
            result.update(reason_code='action_not_allowed', missing_actions=[action])
        else:
            result['reason_code'] = 'remote_identity_unresolved'
    try:
        decision = resolve_grant(identity, project=host.get('project_name'), host=host,
            grants=grants, project_sets=project_sets, defaults=_defaults(config), action=action)
    except PolicyDenied:
        return result
    result.update(allowed=True, reason_code='policy_allowed',
        remote_user=decision['remote_user'], sudo_mode=decision['sudo_mode'])
    return result


def _can_see(identity, config, host, grants, project_sets):
    # Matching a currently active assignment establishes a resource relationship,
    # even if that selected rule omits the requested protocol action. It never
    # exposes another subject's assignment or an unrelated inventory object.
    return bool(has_permission(identity, config, 'inventory.read', host.get('project_name'))
        or matching_grants(identity, project=host.get('project_name'), host=host,
            grants=grants, project_sets=project_sets))


def explain_resource(runtime, identity, host_id, protocol='ssh', action=None, token=None, source_ip=None):
    from isolate import load_grants, load_project_sets
    from isolate_inventory import get_host, is_host_in_maintenance
    from isolate_identity import IdentityError
    from isolate_identity_security import assert_workload_action, check_step_up, StepUpRequired
    from isolate_session_approvals import session_approval_required
    from isolate_connection_auth import ConnectionDenied
    from isolate_protocols import resolve_target, ProtocolError

    _verified(identity)
    if protocol not in PROTOCOLS or not str(host_id).isdigit():
        raise ExplanationError(400, 'invalid_resource')
    action = action or ('ssh' if protocol == 'webssh' else protocol)
    if not isinstance(action, str) or not ACTION.fullmatch(action):
        raise ExplanationError(400, 'invalid_action')
    host = get_host(runtime.redis, str(host_id))
    grants, sets = load_grants(runtime.redis), load_project_sets(runtime.redis)
    if not host or not _can_see(identity, runtime.config, host, grants, sets):
        raise ExplanationError(404, 'resource_not_found_or_not_visible')
    config = runtime.config
    admin = is_platform_admin(identity, config)
    policy = policy_explanation(config, identity, host, grants, sets, action, admin)
    canonical = 'ssh' if protocol == 'webssh' else protocol
    result = {'resource': {'host_id': str(host_id), 'name': host.get('server_name'),
        'project': host.get('project_name'), 'protocol': canonical}, 'action': action,
        'policy': policy, 'state': 'available', 'checks': [], 'evaluated_at': int(time.time()),
        'snapshot_only': True, 'next_action': None,
        'notice': 'Access is rechecked when an operation starts and while it runs. This explanation does not grant access.'}

    def check(code, passed, message, state='denied', next_action=None, required=False):
        result['checks'].append({'code': code, 'status': 'required' if required else 'passed' if passed else 'failed',
            'message': message})
        if not passed and result['state'] == 'available':
            result.update(state=state, summary=message, next_action=next_action)

    policy_messages = {'no_matching_grant': 'No active assignment matches this resource.',
        'action_not_allowed': 'The selected rule does not allow the requested action.',
        'remote_identity_unresolved': 'The selected policy does not resolve a remote account.',
        'policy_allowed': 'The selected active rule permits this action.'}
    check('policy', policy['allowed'], policy_messages[policy['reason_code']],
        next_action={'label': 'Request access', 'url': '/me/access?host=' + str(host_id)})
    from isolate_governance import check_governance_access
    try:
        check_governance_access(runtime.redis, identity, host['project_name'])
    except IdentityError as exc:
        ended = str(exc) == 'access has been ended by an access lifecycle decision'
        check('offboarded' if ended else 'lifecycle_unavailable', False,
            'Access for this identity has been ended by a lifecycle decision.' if ended else 'Current access lifecycle evidence could not be verified.',
            state='denied' if ended else 'unavailable', next_action={'label': 'Contact an administrator', 'url': '/me/access?host=' + str(host_id)})
    else:
        check('lifecycle', True, 'No access lifecycle restriction blocks this identity for the resource project.')
    if not policy['allowed']:
        return result
    decision = resolve_grant(identity, project=host['project_name'], host=host, grants=grants,
        project_sets=sets, defaults=_defaults(config), action=action)
    try:
        assert_workload_action(config, identity, action)
    except IdentityError:
        check('principal_action', False, 'This workload identity is not enabled for the requested action.')
    else:
        check('principal_action', True, 'The principal type permits this action.')
    bypass = set(config.get('maintenance', {}).get('bypass_groups') or [])
    maintenance = is_host_in_maintenance(host) and not bypass.intersection(identity.get('groups') or [])
    check('maintenance', not maintenance, 'The resource is in maintenance.' if maintenance else 'The resource is not blocked by maintenance.',
        state='maintenance', next_action={'label': 'Contact the resource owner', 'url': '/me/resources/' + str(host_id)})
    check('connections', config.get('connection_authorization', {}).get('connections_enabled', True) is True,
        'New connections are enabled.' if config.get('connection_authorization', {}).get('connections_enabled', True) else 'New connections are administratively disabled.', state='unavailable')
    enabled = bool(config.get('api', {}).get('enabled') and config.get('gateway', {}).get('enabled'))
    check('gateway', enabled, 'The connection services are enabled.' if enabled else 'The connection services are not enabled.', state='unavailable')
    target = None
    if canonical != 'ssh':
        try:
            target = resolve_target(config, host, canonical)
        except (ProtocolError, ValueError, TypeError):
            check('protocol', False, 'The resource protocol configuration needs administrator attention.', state='unavailable')
        else:
            check('protocol', True, 'The resource protocol has a valid inventory-bound configuration.')
    if canonical == 'ssh':
        ports = config.get('connection_authorization', {}).get('allowed_target_ports') or []
        check('target_port', not ports or int(host.get('server_port') or 22) in ports,
            'The SSH target port is permitted.' if not ports or int(host.get('server_port') or 22) in ports else 'The SSH target port is not permitted.', state='unavailable')
    if action in ('sftp', 'forward'):
        features = config.get('gateway', {}).get('ssh_features', {})
        enabled_channel = bool((features.get('sftp') or features.get('scp')) and decision.get('sudo_mode') == 'none') if action == 'sftp' else bool(features.get('forwarding'))
        check('channel_configuration', enabled_channel, 'This SSH channel is enabled.' if enabled_channel else 'This channel requires an enabled compatible SSH profile.', state='unavailable')
    if action.startswith('kubernetes-') and target:
        operation = action.removeprefix('kubernetes-')
        options = target.get('kubernetes') or {}
        allowed = options.get('enabled') is True and operation in (options.get('allowed_operations') or [])
        check('operation_configuration', allowed, 'The Kubernetes operation is enabled.' if allowed else 'This Kubernetes operation is not enabled for the resource.', state='unavailable')
    try:
        check_step_up(config, identity, host=host, decision=decision)
    except StepUpRequired:
        check('step_up', False, 'Fresh authentication at the required assurance level is needed.', state='step_up_required',
            next_action={'label': 'Verify identity', 'url': '/login?step_up=true'}, required=True)
    except IdentityError:
        check('step_up', False, 'Identity assurance configuration needs administrator attention.', state='unavailable')
    else:
        check('step_up', True, 'The current authentication meets the configured assurance requirement.')
    if session_approval_required(config, host, decision):
        check('session_approval', False, 'A separate approval is required for each new session.', state='approval_required',
            next_action={'label': 'Request session', 'url': '/me/terminal/' + str(host_id) if canonical == 'ssh' else '/workspace/resource/' + str(host_id) + '/' + canonical}, required=True)
    else:
        check('session_approval', True, 'No separate session approval is required.')
    # Runtime preflight is authoritative for route hops, live lifecycle and deny
    # overlays. It does not acquire leases, connect, or consume an approval.
    resource_action = action == canonical or protocol == 'webssh' and action == 'ssh'
    if result['state'] in ('available', 'approval_required') and resource_action:
        try:
            runtime.authorize_identity(identity, str(host_id), protocol, token=token, source_ip=source_ip)
        except StepUpRequired:
            result['state'] = 'available'
            check('runtime', False, 'Fresh authentication is required.', state='step_up_required',
                next_action={'label': 'Verify identity', 'url': '/login?step_up=true'}, required=True)
        except (ConnectionDenied, PolicyDenied, IdentityError, ValueError):
            result['state'] = 'available'
            check('runtime', False, 'Current identity, lifecycle or route requirements prevent access. Ask an administrator to review the resource.',
                next_action={'label': 'Request access', 'url': '/me/access?host=' + str(host_id)})
        else:
            result['checks'].append({'code': 'runtime', 'status': 'passed', 'message': 'Current identity and route preflight passed.'})
    if result['state'] == 'available':
        result['summary'] = 'Access is available.' if resource_action else 'Policy permits this action; operation-specific submission and channel checks still apply.'
        result['next_action'] = {'label': 'Connect' if resource_action else 'View resource',
            'url': '/me/terminal/' + str(host_id) if canonical == 'ssh' else '/workspace/resource/' + str(host_id) + '/' + canonical}
    return result


def _scenario_identity(grant):
    value = {'keycloak_sub': grant.get('keycloak_sub'), 'username': ':policy-principal-scenario:', 'groups': [], 'roles': []}
    subject, name = grant.get('subject'), grant.get('name')
    if subject == 'user':
        value['username'] = name
    elif subject == 'group':
        value['groups'] = [name]
    elif subject == 'role':
        value['roles'] = [name]
    elif subject == 'service':
        value.update(principal_type='service', service_client_id=name)
    return value


def preview_policy_impact(runtime, actor, candidate, replace_grant_id=None, remove=False, project=None, max_entries=500):
    """Bounded counterfactual preview, never an IdP membership census.

    The API supplies the same admin scope as policy mutations. Direct callers
    must be platform admins; scoped project owners cannot enumerate other users.
    """
    from isolate import load_grants, load_project_sets
    from isolate_inventory import list_hosts
    from isolate_policy_bundle import validate_bundle
    _verified(actor)
    if not is_platform_admin(actor, runtime.config) or actor.get('principal_type') == 'service':
        raise ExplanationError(403, 'platform_administrator_required')
    if type(remove) is not bool or type(max_entries) is not int or not 1 <= max_entries <= 1000:
        raise ExplanationError(400, 'invalid_preview_options')
    if replace_grant_id is not None and not re.fullmatch(r'[0-9]{1,20}', str(replace_grant_id)):
        raise ExplanationError(400, 'invalid_grant_id')
    if remove and not replace_grant_id:
        raise ExplanationError(400, 'replacement_grant_required')
    current, sets = load_grants(runtime.redis), load_project_sets(runtime.redis)
    existing = next((row for row in current if str(row.get('id')) == str(replace_grant_id)), None) if replace_grant_id else None
    if replace_grant_id and existing is None:
        raise ExplanationError(404, 'grant_not_found')
    desired = [copy.deepcopy(row) for row in current if str(row.get('id')) != str(replace_grant_id)]
    if not remove:
        fields = {'subject', 'name', 'keycloak_sub', 'project', 'project_glob', 'project_set', 'host', 'remote_user', 'sudo_mode', 'allowed_actions', 'starts_at', 'expires_at'}
        if not isinstance(candidate, dict) or set(candidate) - fields:
            raise ExplanationError(400, 'invalid_candidate_grant')
        proposed = dict(existing or {}, **copy.deepcopy(candidate))
        if any(key in candidate for key in ('project', 'project_glob', 'project_set')):
            for key in ('project', 'project_glob', 'project_set'):
                if key not in candidate:
                    proposed.pop(key, None)
        proposed['id'] = str(replace_grant_id or 'preview')
        validation = validate_bundle({'schema_version': 2, 'project_sets': list(sets.values()),
            'grants': [{k: v for k, v in proposed.items() if k != 'id'}]})
        if not validation['valid']:
            raise ExplanationError(400, 'invalid_candidate_grant')
        for field in ('starts_at', 'expires_at'):
            if field in proposed and (type(proposed[field]) is not int or proposed[field] < 0):
                raise ExplanationError(400, 'invalid_candidate_grant')
        if proposed.get('expires_at') is not None and proposed.get('starts_at', 0) >= proposed['expires_at']:
            raise ExplanationError(400, 'invalid_candidate_grant')
        if existing:
            # A replacement preserves resolver order for equal-specificity rules.
            desired = [proposed if str(row.get('id')) == str(replace_grant_id) else copy.deepcopy(row) for row in current]
        else:
            desired.append(proposed)
    hosts = list_hosts(runtime.redis, project=project)
    if len(hosts) > 10000 or len(current) > 10000:
        raise ExplanationError(413, 'preview_inventory_limit')
    scenarios = {}
    for grant in current + desired:
        key = (grant.get('subject'), grant.get('name'), grant.get('keycloak_sub'))
        scenarios[key] = _scenario_identity(grant)
    actions = sorted({action for row in current + desired for action in row.get('allowed_actions') or ['ssh'] if isinstance(action, str)})
    if len(scenarios) * len(hosts) * max(1, len(actions)) * max(1, len(current), len(desired)) > 2000000:
        raise ExplanationError(413, 'preview_work_limit')
    rows, counts = [], {'gained': 0, 'lost': 0, 'changed': 0}
    for (subject, name, subject_id), identity in sorted(scenarios.items(), key=lambda item: str(item[0])):
        for host in hosts:
            for action in actions:
                before = policy_explanation(runtime.config, identity, host, current, sets, action, admin=True)
                after = policy_explanation(runtime.config, identity, host, desired, sets, action, admin=True)
                signature = lambda value: (value['allowed'], value.get('remote_user'), value.get('sudo_mode'),
                    (value.get('selected_grant') or {}).get('id'), (value.get('selected_grant') or {}).get('expires_at'),
                    (value.get('selected_grant') or {}).get('starts_at'), value['reason_code'])
                if signature(before) == signature(after):
                    continue
                change = 'gained' if after['allowed'] and not before['allowed'] else 'lost' if before['allowed'] and not after['allowed'] else 'changed'
                counts[change] += 1
                if len(rows) < max_entries:
                    rows.append({'change': change, 'subject': subject, 'name': name, 'subject_id': subject_id,
                        'host_id': str(host['server_id']), 'resource_name': host['server_name'], 'project': host['project_name'],
                        'action': action, 'before': before, 'after': after})
    return {'counts': counts, 'impacts': rows, 'truncated': sum(counts.values()) > len(rows),
        'evaluated_hosts': len(hosts), 'evaluated_scenarios': len(scenarios), 'evaluated_actions': len(actions),
        'coverage': 'grant-principal-scenarios', 'snapshot_only': True, 'evaluated_at': int(time.time()),
        'evaluation_scope': 'policy-only; live lifecycle, IdP, assurance, approvals and target checks still apply',
        'membership_notice': 'Group/role rows model policy principals, not a complete list of people. Combined memberships and current IdP membership must be reviewed separately.',
        'candidate_sha256': hashlib.sha256(json.dumps({'grant': candidate, 'replace': replace_grant_id, 'remove': remove}, sort_keys=True).encode()).hexdigest()}
