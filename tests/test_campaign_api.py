"""Real Flask/Runtime campaign boundaries with signed tokens and SQL authority."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import test_campaigns as fixtures
from isolate_runtime import Runtime
from isolate_web import create_app


class CampaignAPITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CampaignTest.setUpClass()

    def setUp(self):
        self.state = fixtures.CampaignTest()
        self.state.setUp()
        self.addCleanup(self.state.doCleanups)
        patcher = mock.patch('isolate_web.redis_client', return_value=self.state.store)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.app = create_app(self.state.config)
        self.app.config.update(TESTING=True, SECRET_KEY='campaign-api-test-key')
        self.client = self.app.test_client()
        self.headers = {'Authorization': 'Bearer ' + self.state.token}

    def login(self):
        runtime = Runtime(self.state.config, self.state.store)
        identity = runtime.authenticate(self.state.token)
        handle = 'campaign-browser-session-1234'
        self.state.store.set('isolate_browser_' + handle, json.dumps({'sub': identity['keycloak_sub'], 'token': self.state.token}))
        with self.client.session_transaction() as session:
            session.update(identity=identity, runtime_session=handle, csrf_token='campaign-csrf')

    def test_preview_confirmation_idempotency_and_foreign_subject_boundaries(self):
        preview = self.client.post('/api/v1/runbook-campaigns/preview', headers=self.headers, json=self.state.body)
        self.assertEqual(preview.status_code, 200, preview.data)
        body = dict(self.state.body, preview_digest=preview.json['preview_digest'], confirm=True)
        response = self.client.post('/api/v1/runbook-campaigns', headers=dict(self.headers, **{'Idempotency-Key': 'api-idempotent-key-001'}), json=body)
        self.assertEqual(response.status_code, 201, response.data)
        identifier = response.json['campaign']['id']
        replay = self.client.post('/api/v1/runbook-campaigns', headers=dict(self.headers, **{'Idempotency-Key': 'api-idempotent-key-001'}), json=body)
        self.assertEqual(replay.status_code, 200, replay.data)
        self.assertEqual(replay.json['campaign']['id'], identifier)
        self.assertNotIn(self.state.token, response.get_data(as_text=True))
        foreign = self.state.fixture.sign(dict(self.state.claims, sub='other-signed-subject', preferred_username='bob'))
        foreign_headers = {'Authorization': 'Bearer ' + foreign}
        self.assertEqual(self.client.get('/api/v1/runbook-campaigns/' + identifier, headers=foreign_headers).status_code, 404)
        self.assertEqual(self.client.get('/api/v1/runbook-campaigns', headers=foreign_headers).json['campaigns'], [])
        self.assertEqual(self.client.post('/api/v1/runbook-campaigns/' + identifier + '/cancel', headers=foreign_headers, json={'confirm': True}).status_code, 404)
        self.assertEqual(self.client.post('/api/v1/runbook-campaigns/' + identifier + '/cancel', headers=self.headers, json={'confirm': 1}).status_code, 403)
        cancelled = self.client.post('/api/v1/runbook-campaigns/' + identifier + '/cancel', headers=self.headers, json={'confirm': True})
        self.assertEqual(cancelled.json['campaign']['status'], 'cancelled')

    def test_browser_json_csrf_and_real_form_preview_require_confirmation(self):
        self.login()
        response = self.client.get('/operations/campaigns')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('Review plan', response.get_data(as_text=True))
        self.assertEqual(self.client.post('/api/v1/runbook-campaigns/preview', json=self.state.body).status_code, 403)
        preview = self.client.post('/api/v1/runbook-campaigns/preview', headers={'X-CSRF-Token': 'campaign-csrf'}, json=self.state.body)
        self.assertEqual(preview.status_code, 200, preview.data)
        form = {'csrf_token': 'campaign-csrf', 'runbook_id': 'uptime', 'host_ids': '1,2,3,4', 'parameters': '{}',
            'canary_count': '1', 'batch_size': '2', 'failure_budget': '0', 'max_failure_percent': '100'}
        response = self.client.post('/operations/campaigns/preview', data=form)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('Start canary', response.get_data(as_text=True))
        self.assertIn('I reviewed the targets', response.get_data(as_text=True))
        self.assertNotIn(self.state.token, response.get_data(as_text=True))
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        wrong = self.client.post('/operations/campaigns/preview', data=dict(form, csrf_token='wrong'))
        self.assertEqual(wrong.status_code, 403)

    def test_authenticated_caller_without_runbook_rights_cannot_see_catalogue_titles(self):
        claims = dict(self.state.claims, groups=['Unrelated'], scope='openid')
        token = self.state.fixture.sign(claims)
        response = self.client.get('/operations/campaigns', headers={'Authorization': 'Bearer ' + token})
        self.assertEqual(response.status_code, 200, response.data)
        text = response.get_data(as_text=True)
        self.assertNotIn('System uptime and load', text)
        self.assertNotIn('Review plan', text)
        self.assertIn('No runbooks are currently available', text)


if __name__ == '__main__':
    unittest.main()
