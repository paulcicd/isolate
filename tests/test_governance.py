"""Authoritative lifecycle decisions, deny overlays, owner scopes and HTTP UI."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'shared'))
import fakeredis
from flask import Flask
import isolate_governance as governance
from isolate_governance_api import register_governance_api
from isolate_identity import IdentityError
from isolate_policy import PolicyDenied, resolve_grant
from isolate_state import SQLState, StateClient


class GovernanceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = {'dashboard': {'admin_groups': ['Admins'], 'role_bindings': [
            {'group': 'StageOwners', 'role': 'project-owner', 'projects': ['stage']},
            {'group': 'Readers', 'role': 'auditor', 'projects': ['stage']}]},
            'logging': {'base_path': str(self.root / 'logs'), 'sinks': []}}
        self.owner = {'keycloak_sub': 'owner-sub', 'username': 'owner', 'groups': ['StageOwners']}
        self.admin = {'keycloak_sub': 'admin-sub', 'username': 'admin', 'groups': ['Admins']}
        self.subject = {'keycloak_sub': 'contractor-sub', 'username': 'contractor', 'groups': ['Support']}
        self.reader = {'keycloak_sub': 'reader-sub', 'username': 'auditor', 'groups': ['Readers']}
        options = {'backend': 'sqlite', 'sqlite_path': str(self.root / 'authority.sqlite')}
        SQLState(options).initialize()
        self.store = StateClient(fakeredis.FakeRedis(), options)
        self.store.set('server_1', json.dumps({'server_id': '1', 'project_name': 'stage'}))
        self.store.set('server_2', json.dumps({'server_id': '2', 'project_name': 'prod'}))
        self.grant = {'subject': 'group', 'name': 'Support', 'project': 'stage', 'remote_user': 'support',
            'sudo_mode': 'none', 'allowed_actions': ['ssh', 'webssh']}
        self.store.set('grant_1', json.dumps(self.grant))
        self.store.set('grant_2', json.dumps(dict(self.grant, project='prod', name='PrivateProdGroup')))
        self.store.set('offset_grant_id', 2)

    def assignment(self, **changes):
        values = dict(project='stage', subject_id='contractor-sub', username='contractor', remote_user='support',
            expires_at=int(time.time()) + 3 * 86400, reason='contract for incident response', idempotency_key='assignment-intent-001')
        values.update(changes)
        return governance.create_assignment(self.store, self.config, self.owner, **values)

    def review(self, **changes):
        values = dict(project='stage', reason='quarterly owner review', idempotency_key='owner-review-intent-001')
        values.update(changes)
        return governance.create_review(self.store, self.config, self.owner, **values)

    def test_expiring_subject_bound_assignment_and_replay_are_atomic(self):
        before = int(time.time())
        record = self.assignment()
        with mock.patch.object(governance.time, 'time', return_value=before + 30):
            replay = self.assignment(expires_at=record['expires_at'])
        self.assertEqual(record['id'], replay['id'])
        self.assertEqual(len(self.store.keys('governance_assignment_*')), 1)
        grant = json.loads(self.store.get('grant_' + record['grant_id']))
        self.assertEqual(grant['keycloak_sub'], self.subject['keycloak_sub'])
        self.assertEqual(grant['sudo_mode'], 'none')
        self.assertEqual(resolve_grant(self.subject, 'stage', grants=[grant])['remote_user'], 'support')
        with mock.patch('isolate_policy.time.time', return_value=record['expires_at']):
            with self.assertRaises(PolicyDenied):
                resolve_grant(self.subject, 'stage', grants=[grant])
        self.assertIsNone(self.store.redis.get('governance_assignment_' + record['id']))
        self.assertTrue(self.store.keys('workflow_event_*'))

    def test_concurrent_identical_assignments_create_one_grant(self):
        expiry = int(time.time()) + 86400
        with ThreadPoolExecutor(max_workers=4) as pool:
            records = list(pool.map(lambda _: self.assignment(expires_at=expiry), range(4)))
        self.assertEqual(len({record['id'] for record in records}), 1)
        self.assertEqual(len(self.store.keys('grant_*')), 3)

    def test_owner_scopes_and_no_self_or_privileged_assignments(self):
        for change in ({'project': 'prod'}, {'subject_id': 'owner-sub'}, {'remote_user': 'root'},
                       {'expires_at': int(time.time()) + 100 * 86400}, {'allowed_actions': ['command']}, {'allowed_actions': []}, {'allowed_actions': 'ssh'}):
            with self.subTest(change=change), self.assertRaises(governance.GovernanceError):
                self.assignment(**change)
        data = governance.dashboard(self.store, self.config, self.owner)
        self.assertEqual(data['projects'], ['stage'])
        self.assertNotIn('PrivateProdGroup', json.dumps(data))
        self.assertNotIn('prod', json.dumps(data))
        with self.assertRaises(governance.GovernanceError):
            governance.create_review(self.store, self.config, self.reader, 'stage', 'not an owner', idempotency_key='reader-create-intent')

    def test_review_keep_does_not_extend_access_and_sets_periodic_due(self):
        record = self.assignment()
        review = self.review()
        for item in review['items']:
            governance.decide_review(self.store, self.config, self.owner, review['id'], item['grant_id'], 'keep', 'business need confirmed')
        grant = json.loads(self.store.get('grant_' + record['grant_id']))
        self.assertEqual(grant['expires_at'], record['expires_at'])
        complete = json.loads(self.store.get('governance_review_' + review['id']))
        self.assertEqual(complete['status'], 'completed')
        schedule = json.loads(self.store.get('governance_schedule_stage'))
        self.assertEqual(schedule['next_due_at'] - schedule['last_completed_at'], 90 * 86400)

    def test_review_stale_revision_and_current_owner_permissions_fail_closed(self):
        review = self.review()
        changed = dict(self.grant, allowed_actions=['http'])
        self.store.set('grant_1', json.dumps(changed))
        with self.assertRaisesRegex(governance.GovernanceError, 'snapshot_stale'):
            governance.decide_review(self.store, self.config, self.owner, review['id'], '1', 'keep', 'changed behind review')
        self.config['dashboard']['role_bindings'] = []
        with self.assertRaises(governance.GovernanceError):
            governance.decide_review(self.store, self.config, self.owner, review['id'], '1', 'revoke', 'no longer current owner')
        self.assertEqual(json.loads(self.store.get('grant_1')), changed)

    def test_direct_bound_or_username_own_access_needs_independent_review(self):
        for binding in ({'keycloak_sub': 'owner-sub'}, {}):
            self.store.set('grant_1', json.dumps(dict(self.grant, subject='user', name='owner', **binding)))
            review = self.review(idempotency_key='self-review-' + ('bound' if binding else 'name') + '-intent')
            with self.assertRaisesRegex(governance.GovernanceError, 'independent_review'):
                governance.decide_review(self.store, self.config, self.owner, review['id'], '1', 'keep', 'cannot certify my own rule')

    def test_revocation_keeps_precedence_and_managed_grants_require_remediation(self):
        direct = dict(self.grant, subject='user', name='contractor', keycloak_sub='contractor-sub')
        self.store.set('grant_3', json.dumps(direct))
        self.store.set('offset_grant_id', 3)
        review = self.review()
        governance.decide_review(self.store, self.config, self.owner, review['id'], '3', 'revoke', 'role is no longer required')
        denied = json.loads(self.store.get('grant_3'))
        with self.assertRaises(PolicyDenied):
            resolve_grant(self.subject, 'stage', grants=[self.grant, denied])
        self.store.set('grant_1', json.dumps(dict(self.grant, managed_by='gitops')))
        other = self.review(idempotency_key='managed-review-intent-002')
        with self.assertRaisesRegex(governance.GovernanceError, 'managed_grant'):
            governance.decide_review(self.store, self.config, self.owner, other['id'], '1', 'revoke', 'reconcile in repository')
        self.assertEqual(json.loads(self.store.get('grant_1'))['allowed_actions'], ['ssh', 'webssh'])

    def test_offboarding_blocks_renamed_identity_and_reimported_group_grants(self):
        record = governance.offboard(self.store, self.config, self.owner, 'contractor-sub', 'stage', 'contract ended')
        self.assertEqual(governance.offboard(self.store, self.config, self.owner, 'contractor-sub', 'stage', 'already ended')['id'], record['id'])
        self.store.set('grant_1', json.dumps(self.grant))
        renamed = dict(self.subject, username='new-name')
        with self.assertRaises(IdentityError):
            governance.check_governance_access(self.store, renamed, 'stage')
        with self.assertRaises(IdentityError):
            governance.check_governance_access(self.store, renamed, 'STAGE')
        governance.check_governance_access(self.store, renamed, 'legacy,project')
        governance.check_governance_access(self.store, renamed, 'prod')
        governance.check_governance_access(self.store, renamed)
        with self.assertRaises(governance.GovernanceError):
            governance.offboard(self.store, self.config, self.owner, 'contractor-sub', '*', 'global not owned')
        governance.offboard(self.store, self.config, self.admin, 'contractor-sub', '*', 'company offboarding')
        with self.assertRaises(IdentityError):
            governance.check_governance_access(self.store, renamed)

    def test_malformed_marker_and_store_outage_never_allow_access(self):
        key = governance._offboard_key('contractor-sub', '*')
        for value in ('not-json', '{}', json.dumps({'subject_id': 'different', 'project': '*', 'status': 'blocked'})):
            self.store.set(key, value)
            with self.assertRaises(IdentityError):
                governance.check_governance_access(self.store, self.subject)
        with mock.patch.object(self.store, 'get', side_effect=OSError('control store down')):
            with self.assertRaises(IdentityError):
                governance.check_governance_access(self.store, self.subject)

    def test_expiry_and_review_due_reminders_and_findings_are_scoped_candidates(self):
        record = self.assignment()
        review = self.review(due_at=int(time.time()) + 20)
        with mock.patch.object(governance.time, 'time', return_value=time.time() + 30):
            data = governance.dashboard(self.store, self.config, self.reader)
        self.assertTrue(any(item['kind'] == 'assignment_expiring' and item['assignment_id'] == record['id'] for item in data['reminders']))
        self.assertTrue(any(item['kind'] == 'review_overdue' and item['review_id'] == review['id'] for item in data['reminders']))
        self.assertTrue(data['findings'])
        self.assertEqual(data['findings'][0]['assessment'], 'review_candidate_not_proof_of_excess_access')
        self.assertNotIn('PrivateProdGroup', json.dumps(data))

    def test_durable_outbox_retries_without_replaying_domain_action_or_reason_leak(self):
        record = self.assignment(reason='private-review-reason')
        event = json.loads(self.store.get('workflow_event_' + record['id']))
        self.assertEqual(event['outcome'], 'committed')
        self.assertNotIn('private-review-reason', json.dumps(event))
        self.config['logging']['sinks'] = [{'type': 'not-a-sink'}]
        first = governance.publish_pending(self.store, self.config)
        self.assertEqual(first['published'], 0)
        self.assertTrue(self.store.get('workflow_pending_' + record['id']))
        self.config['logging']['sinks'] = []
        second = governance.publish_pending(self.store, self.config)
        self.assertEqual(second['published'], 1)
        self.assertIsNone(self.store.get('workflow_pending_' + record['id']))
        self.assertEqual(len(self.store.keys('governance_assignment_*')), 1)


class GovernanceHTTPTest(unittest.TestCase):
    def setUp(self):
        self.fixture = GovernanceTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config, self.store, self.owner = self.fixture.config, self.fixture.store, self.fixture.owner
        self.app = Flask(__name__)
        self.app.secret_key = 'synthetic-governance-session-key'
        def bearer(allow_browser=False, mutation=False):
            from flask import abort, request
            if request.headers.get('Authorization') == 'Bearer owner-token':
                return 'owner-token'
            if allow_browser and request.headers.get('X-Browser') == 'yes':
                if mutation and request.headers.get('X-CSRF-Token') != 'csrf-value':
                    abort(403)
                return 'owner-token'
            abort(401)
        def bounded_json(maximum):
            from flask import abort, request
            data = request.get_json()
            if not isinstance(data, dict):
                abort(400)
            return data
        runtime = SimpleNamespace(redis=self.store, authenticate=lambda token: self.owner)
        register_governance_api(self.app, self.config, lambda: runtime, bearer, bounded_json,
            lambda error: ('denied', 403), (IdentityError, ValueError), lambda: 'csrf-value')
        self.client = self.app.test_client()
        self.headers = {'Authorization': 'Bearer owner-token', 'Idempotency-Key': 'http-governance-create-01'}

    def test_authenticated_confirmed_scoped_mutations_and_browser_csrf(self):
        path = '/api/v1/governance/offboarding'
        body = {'subject_id': 'contractor-sub', 'project': 'stage', 'reason': 'contract ended', 'confirm': True}
        self.assertEqual(self.client.post(path, json=body).status_code, 401)
        self.assertEqual(self.client.post(path, json=dict(body, confirm=1), headers=self.headers).status_code, 400)
        self.assertEqual(self.client.post(path, json=dict(body, project='prod'), headers=self.headers).status_code, 403)
        self.assertEqual(self.client.post(path, json=body, headers={'X-Browser': 'yes'}).status_code, 403)
        response = self.client.post(path, json=body, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.get_json()['result']['status'], 'blocked')
        self.assertEqual(response.get_json()['audit_delivery'], {'status': 'retained', 'publication': 'retryable_outbox'})
        self.assertEqual(self.client.get('/api/v1/governance?project=prod', headers=self.headers).status_code, 403)

    def test_management_workspace_has_forms_reminders_and_escapes_values(self):
        from unittest import mock
        with mock.patch('isolate_web._html', side_effect=lambda title, body, config: body):
            response = self.client.get('/workspace/governance', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Start an owner review', response.data)
        self.assertIn(b'Temporary or contractor assignment', response.data)
        self.assertIn(b'csrf-value', response.data)
        self.assertNotIn(b'PrivateProdGroup', response.data)
        form = {'operation': 'offboard', 'subject_id': 'contractor-sub', 'project': 'stage', 'reason': 'end contract', 'confirm': 'true'}
        self.assertEqual(self.client.post('/workspace/governance/actions', data=form, headers={'X-Browser': 'yes'}).status_code, 403)
        form['csrf_token'] = 'csrf-value'
        self.assertEqual(self.client.post('/workspace/governance/actions', data=form, headers={'X-Browser': 'yes'}).status_code, 303)


if __name__ == '__main__':
    unittest.main()
