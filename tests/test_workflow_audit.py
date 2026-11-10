"""Atomic workflow evidence survives publication failure and restart/retry."""
import concurrent.futures
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import test_runtime_api_index as fixtures
from isolate_access import create_access_request, approve_access_request
from isolate_audit import AuditSinkError
from isolate_audit_index import AuditIndex
from isolate_state import SQLState, StateClient
from isolate_workflow_audit import stage_event, publish_pending


class WorkflowEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = self.fixture.config
        self.config['audit_index'] = {'enabled': True, 'path': str(Path(self.fixture.directory.name) / 'audit.sqlite')}
        options = {'backend': 'sqlite', 'sqlite_path': str(Path(self.fixture.directory.name) / 'state.sqlite')}
        SQLState(options).initialize()
        self.store = StateClient(self.fixture.redis, options)
        self.index = AuditIndex(self.config['audit_index'])
        self.index.initialize()
        self.actor = {'username': 'manager', 'keycloak_sub': 'manager-sub', 'groups': ['Owners']}
        self.person = {'username': 'alice', 'keycloak_sub': 'alice-sub', 'groups': ['Support']}
        self.config['dashboard']['role_bindings'] = [{'group': 'Owners', 'role': 'project-owner', 'projects': ['prod']}]

    def test_request_and_approval_evidence_commit_with_domain_and_retry_without_replaying(self):
        record = create_access_request(self.store, self.person, 'prod', remote_user='support', reason='private justification', config=self.config)
        approved, grant = approve_access_request(self.store, record['id'], self.actor, 300, config=self.config)
        self.assertEqual(approved['status'], 'approved')
        self.assertEqual(len(self.store.keys('workflow_pending_*')), 2)
        self.assertFalse(self.fixture.redis.keys('workflow_*'))
        with mock.patch.object(AuditIndex, 'ingest', side_effect=OSError('index unavailable')):
            failed = publish_pending(self.store, self.config)
        self.assertEqual(failed['failed'], 2)
        self.assertEqual(json.loads(self.store.get('access_request_' + record['id']))['status'], 'approved')
        result = publish_pending(self.store, self.config)
        self.assertEqual(result['published'], 2)
        events = self.index.search(projects=['prod'])['events']
        self.assertEqual({event['event'] for event in events}, {'access_request_created', 'access_request_approved'})
        self.assertTrue(all(event['outcome'] == 'committed' for event in events))
        self.assertNotIn('private justification', json.dumps(events))
        self.assertEqual(len(self.store.keys('grant_*')), 1)
        self.assertEqual(len(self.store.keys('workflow_event_*')), 2)
        self.assertEqual(publish_pending(self.store, self.config)['published'], 0)

    def test_failed_signing_rolls_back_request_and_all_workflow_evidence(self):
        with mock.patch('isolate_workflow_audit.sign_audit_record', side_effect=AuditSinkError('unavailable')):
            with self.assertRaises(AuditSinkError):
                create_access_request(self.store, self.person, 'prod', reason='private', config=self.config)
        self.assertEqual(self.store.keys('access_request_*'), [])
        self.assertEqual(self.store.keys('workflow_event_*'), [])
        self.assertEqual(self.store.keys('workflow_pending_*'), [])

    def test_concurrent_publishers_deduplicate_index_without_losing_retained_source(self):
        with self.store.pipeline() as transaction:
            transaction.multi()
            source = stage_event(transaction, self.config, 'access_request_created', self.person, 'prod', access_request_id='42')
            transaction.execute()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: publish_pending(self.store, self.config), range(2)))
        events = self.index.search(projects=['prod'])['events']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_id'], source['event_id'])
        self.assertIsNotNone(self.store.get('workflow_event_' + source['event_id']))
        self.assertEqual(self.store.keys('workflow_pending_*'), [])

    def test_changed_pending_evidence_is_not_published_or_acknowledged(self):
        source = stage_event(self.store, self.config, 'access_request_created', self.person, 'prod', access_request_id='42')
        self.store.set('workflow_pending_' + source['event_id'], json.dumps(dict(source, project='foreign')))
        self.assertEqual(publish_pending(self.store, self.config)['failed'], 1)
        self.assertEqual(self.index.search()['events'], [])
        self.assertEqual(len(self.store.keys('workflow_pending_*')), 1)


if __name__ == '__main__':
    unittest.main()
