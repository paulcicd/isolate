"""Real SQL correlation with signed API identities and project/subject fences."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import test_runtime_api_index as fixtures
from isolate_audit_index import AuditIndex, AuditIndexError
from isolate_investigations import timeline, identity_session_reference, InvestigationError


class InvestigationTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = self.fixture.config
        self.config['audit_index'] = {'enabled': True, 'driver': 'sqlite', 'path': str(Path(self.fixture.directory.name) / 'audit.sqlite')}
        self.config['dashboard']['role_bindings'] = [{'group': 'Prod-Auditors', 'role': 'auditor', 'projects': ['prod']}]
        self.index = AuditIndex(self.config['audit_index'])
        self.index.initialize()
        self.identity = self.fixture.runtime.authenticate(self.fixture.token)
        self.session = identity_session_reference(self.identity)
        self.record('1', 10, 'identity_login', '', identity_session_sha256=self.session)
        self.record('2', 11, 'access_request_created', 'prod', access_request_id='7', grant_id='5')
        self.record('3', 12, 'session_approval_approved', 'prod', keycloak_sub='manager', access_request_id='7', session_approval_id='approval-1')
        self.record('4', 13, 'ssh_start', 'prod', connection_id='conn-1', access_request_id='7', grant_id='5',
            session_approval_id='approval-1', identity_session_sha256=self.session)
        self.record('5', 14, 'command_start', 'prod', connection_id='conn-1', command='never expose raw private SQL', token='private-bearer',
            raw_claims={'sub': 'private'}, command_sha256='a' * 64)
        self.record('6', 15, 'ssh_end', 'prod', connection_id='conn-1', result='success')
        self.record('7', 14, 'command_start', 'stage', keycloak_sub='foreign', connection_id='conn-1', campaign_id='hidden-campaign')
        self.record('8', 16, 'ssh_start', 'prod', keycloak_sub='foreign', grant_id='5', connection_id='unrelated')

    def record(self, event_id, ts, event, project, **extra):
        self.index.ingest(dict({'event_id': event_id, 'ts': ts, 'event': event, 'project': project,
            'keycloak_sub': self.identity['keycloak_sub'], 'username': 'alice'}, **extra))

    def test_explicit_graph_retains_current_scope_before_expansion_and_avoids_grant_fanout(self):
        analyst = {'keycloak_sub': 'analyst', 'username': 'analyst', 'groups': ['Prod-Auditors']}
        result = timeline(self.config, analyst, {'kind': 'connection', 'id': 'conn-1'})
        self.assertEqual([row['event_id'] for row in result['events']], ['2', '3', '4', '5', '6'])
        self.assertNotIn('authentication', result['coverage']['observed'])
        self.assertIn('approval', result['coverage']['observed'])
        self.assertNotIn('hidden-campaign', json.dumps(result))
        self.assertNotIn('unrelated', json.dumps(result))
        self.assertNotIn('never expose', json.dumps(result))
        self.assertNotIn('private-bearer', json.dumps(result))
        self.assertNotIn('raw_claims', json.dumps(result))

    def test_employee_can_follow_only_own_evidence_and_authentication_hash(self):
        result = timeline(self.config, self.identity, {'kind': 'connection', 'id': 'conn-1'})
        self.assertEqual([row['event_id'] for row in result['events']], ['1', '2', '4', '5', '6'])
        self.assertIn('approval', result['coverage']['not_observed'])
        self.assertEqual(timeline(self.config, self.identity, {'subject': 'foreign'})['events'], [])
        self.assertEqual(timeline(self.config, self.identity, {'kind': 'campaign', 'id': 'hidden-campaign'})['events'], [])

    def test_pagination_is_stable_with_equal_timestamps_and_order_is_explicit(self):
        first = timeline(self.config, self.identity, {'limit': 2})
        second = timeline(self.config, self.identity, {'limit': 2, 'before': first['next']})
        self.assertEqual([r['event_id'] for r in first['events']], ['5', '6'])
        self.assertEqual([r['event_id'] for r in second['events']], ['2', '4'])
        self.assertEqual(first['page_direction'], 'earlier')
        self.assertEqual(first['order'], 'chronological-within-page')
        self.assertFalse(set(r['event_id'] for r in first['events']) & set(r['event_id'] for r in second['events']))

    def test_invalid_references_times_and_cursor_cannot_widen_query(self):
        for filters in ({'kind': 'unknown', 'id': '1'}, {'id': '1'}, {'kind': 'job', 'id': '../x'}, {'since': 'nan'},
                        {'since': 10, 'until': 1}, {'limit': True}, {'related': 'false'}, {'before': [1]}, {'untrusted': 'x'}):
            with self.subTest(filters=filters), self.assertRaises(InvestigationError):
                timeline(self.config, self.identity, filters)
        with self.assertRaises(AuditIndexError):
            self.index.search(references={"x') OR 1=1 --": ['1']})
        self.assertEqual(self.index.search(references={})['events'], [])

    def test_identity_session_reference_is_issuer_bound_and_never_raw_sid(self):
        reference = identity_session_reference(self.identity)
        self.assertEqual(len(reference), 64)
        other = copy.deepcopy(self.identity)
        other['raw_claims']['iss'] = 'https://other.test'
        self.assertNotEqual(reference, identity_session_reference(other))
        self.assertIsNone(identity_session_reference({}))

    def test_person_filter_includes_authorized_decisions_about_subject_and_marks_legacy_time(self):
        self.record('9', 17, 'governance_offboarded', 'prod', keycloak_sub='manager', target_subject='alice-stable')
        self.record('10', 18, 'governance_offboarded', 'stage', keycloak_sub='manager', target_subject='alice-stable')
        self.index.ingest({'event_id': 'legacy', 'event': 'identity_login', 'keycloak_sub': 'alice-stable'})
        analyst = {'keycloak_sub': 'analyst', 'groups': ['Prod-Auditors']}
        result = timeline(self.config, analyst, {'subject': 'alice-stable'})
        self.assertIn('9', [event['event_id'] for event in result['events']])
        self.assertNotIn('10', [event['event_id'] for event in result['events']])
        own = timeline(self.config, self.identity, {'subject': 'alice-stable'})
        legacy = next(event for event in own['events'] if event['event_id'] == 'legacy')
        self.assertEqual(legacy['timestamp_source'], 'index-ingestion')
        self.assertIsInstance(legacy['ts'], (int, float))
        self.assertNotIn('9', [event['event_id'] for event in own['events']])
        self.assertNotIn('_index_timestamp', self.index.search(event='identity_login')['events'][0])

    def test_real_api_auth_projection_page_escaping_and_disabled_index(self):
        app = self.fixture.app()
        client = app.test_client()
        path = '/api/v1/investigations/timeline'
        self.assertEqual(client.get(path).status_code, 401)
        headers = {'Authorization': 'Bearer ' + self.fixture.token}
        response = client.get(path + '?kind=connection&id=conn-1', headers=headers)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(len(response.get_json()['events']), 5)
        self.assertEqual(client.get(path + '?before=not-json', headers=headers).status_code, 400)
        self.record('9', 17, 'command<script>alert(1)</script>', 'prod', connection_id='conn-1')
        response = client.get('/investigations?kind=connection&id=conn-1', headers=headers)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>alert(1)</script>', response.data)
        self.config['audit_index']['enabled'] = False
        self.assertEqual(client.get(path, headers=headers).status_code, 404)


if __name__ == '__main__':
    unittest.main()
