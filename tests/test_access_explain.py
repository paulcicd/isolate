"""Signed caller diagnostics, selected-rule semantics and bounded policy previews."""
import copy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
from flask import Flask, abort, jsonify, request, session
from isolate_access_explain import ExplanationError, explain_resource, policy_explanation, preview_policy_impact
from isolate_explain_api import explanation_link, explanation_panel, register_explain_api
from isolate_identity import IdentityError
import test_runtime_api_index as fixtures


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.runtime, self.config, self.store = self.fixture.runtime, self.fixture.config, self.fixture.redis
        self.config['dashboard']['admin_groups'] = ['Platform']
        self.identity = self.runtime.authenticate(self.fixture.token)
        self.host = json.loads(self.store.get('server_1'))
        self.grant = json.loads(self.store.get('grant_1'))

    def explain(self, **kwargs):
        return explain_resource(self.runtime, self.identity, '1', token=self.fixture.token, **kwargs)

    def admin(self):
        return dict(self.identity, groups=['Platform'])


class AccessExplanationTest(_Fixture):
    def test_snapshot_reports_actual_rule_without_creating_session_capabilities(self):
        result = self.explain()
        self.assertEqual(result['state'], 'available')
        self.assertTrue(result['policy']['allowed'])
        self.assertEqual(result['policy']['selected_grant']['id'], '1')
        self.assertEqual(result['policy']['remote_user'], 'support')
        self.assertNotIn('name', result['policy']['selected_grant'])
        for pattern in ('isolate_ticket_*', 'isolate_session_owner_*', 'session_approval_*', 'active_session_*'):
            self.assertEqual(self.store.keys(pattern), [])
        wire = json.dumps(result)
        for secret in ('do-not-leak', self.fixture.token, 'raw_claims', '192.0.2.', 'password'):
            self.assertNotIn(secret, wire)

    def test_specific_rule_deny_by_omission_never_falls_back_to_broad_allow(self):
        self.store.set('grant_2', json.dumps(dict(self.grant, allowed_actions=['http'])))
        self.store.set('grant_3', json.dumps(dict(self.grant, subject='user', name=self.identity['username'],
            keycloak_sub=self.identity['keycloak_sub'], host='1', allowed_actions=['ssh'], secret='NEVER-SHOW')))
        result = self.explain(protocol='http')
        self.assertEqual(result['state'], 'denied')
        self.assertEqual(result['policy']['selected_grant']['id'], '3')
        self.assertEqual(result['policy']['reason_code'], 'action_not_allowed')
        self.assertEqual(result['policy']['missing_actions'], ['http'])
        self.assertNotIn('NEVER-SHOW', json.dumps(result))

    def test_unrelated_inventory_and_missing_inventory_have_same_visibility_boundary(self):
        self.store.set('server_2', json.dumps(dict(self.host, server_id='2', project_name='foreign', server_name='hidden-inventory')))
        for identifier in ('2', '999'):
            with self.subTest(identifier=identifier), self.assertRaises(ExplanationError) as failure:
                explain_resource(self.runtime, self.identity, identifier)
            self.assertEqual((failure.exception.status, failure.exception.code), (404, 'resource_not_found_or_not_visible'))

    def test_scoped_inventory_role_can_explain_denial_without_foreign_projects(self):
        self.config['dashboard']['role_bindings'] = [{'group': 'Audit', 'role': 'auditor', 'projects': ['prod']}]
        auditor = dict(self.identity, groups=['Audit'])
        result = explain_resource(self.runtime, auditor, '1', token=self.fixture.token)
        self.assertEqual(result['policy']['reason_code'], 'no_matching_grant')
        self.assertEqual(result['state'], 'denied')
        self.store.set('server_2', json.dumps(dict(self.host, server_id='2', project_name='foreign')))
        with self.assertRaises(ExplanationError) as failure:
            explain_resource(self.runtime, auditor, '2')
        self.assertEqual(failure.exception.status, 404)

    def test_expired_or_future_assignments_never_claim_active_policy_access(self):
        for interval in ({'expires_at': int(time.time()) - 1}, {'starts_at': int(time.time()) + 60}):
            grants = [dict(self.grant, **interval)]
            result = policy_explanation(self.config, self.identity, self.host, grants, {}, action='ssh')
            self.assertFalse(result['allowed'])
            self.assertEqual(result['reason_code'], 'no_matching_grant')
            self.assertIsNone(result['selected_grant'])

    def test_step_up_and_approval_are_distinct_and_nothing_is_consumed(self):
        self.config['identity_security']['step_up'] = {'enabled': True, 'all_connections': True,
            'acr_values': ['mfa'], 'max_age_seconds': 300}
        self.config['session_approval'] = {'enabled': True, 'required_projects': ['prod']}
        result = self.explain()
        self.assertEqual(result['state'], 'step_up_required')
        self.assertEqual(result['next_action']['url'], '/login?step_up=true')
        self.assertEqual({row['code'] for row in result['checks'] if row['status'] == 'required'}, {'step_up', 'session_approval'})
        self.assertEqual(self.store.keys('session_approval_*'), [])
        self.config['identity_security']['step_up']['enabled'] = False
        result = self.explain()
        self.assertEqual(result['state'], 'approval_required')
        self.assertEqual(self.store.keys('session_approval_*'), [])

    def test_disabled_services_maintenance_and_channel_configuration_are_explicit(self):
        self.config['gateway']['enabled'] = False
        result = self.explain()
        self.assertEqual(result['state'], 'unavailable')
        self.assertIn('gateway', {row['code'] for row in result['checks'] if row['status'] == 'failed'})
        self.config['gateway']['enabled'] = True
        self.store.set('server_1', json.dumps(dict(self.host, maintenance_enabled=True)))
        self.assertEqual(self.explain()['state'], 'maintenance')
        self.store.set('server_1', json.dumps(self.host))
        self.store.set('grant_1', json.dumps(dict(self.grant, allowed_actions=['ssh', 'sftp'])))
        result = self.explain(action='sftp')
        self.assertEqual(result['state'], 'unavailable')
        self.assertTrue(result['policy']['allowed'])

    def test_protocol_configuration_failure_is_redacted(self):
        self.store.set('grant_1', json.dumps(dict(self.grant, allowed_actions=['http'])))
        self.config['protocols'] = {'enabled': True, 'targets': {'1': {'protocol': 'http', 'project': 'prod',
            'upstream': 'https://secret-user:private-password@internal.example', 'bearer_token_file': '/private/secret-token'}}}
        result = self.explain(protocol='http')
        self.assertEqual(result['state'], 'unavailable')
        wire = json.dumps(result)
        for secret in ('private-password', 'secret-user', '/private/secret-token', 'internal.example'):
            self.assertNotIn(secret, wire)

    def test_live_project_offboarding_has_an_explicit_safe_reason(self):
        from isolate_governance import _offboard_key
        self.store.set(_offboard_key(self.identity['keycloak_sub'], 'prod'), json.dumps({'schema_version': 1,
            'subject_id': self.identity['keycloak_sub'], 'project': 'prod', 'status': 'blocked', 'reason': 'private-HR-details'}))
        result = self.explain()
        self.assertEqual(result['state'], 'denied')
        self.assertIn('offboarded', {row['code'] for row in result['checks'] if row['status'] == 'failed'})
        self.assertNotIn('private-HR-details', json.dumps(result))

    def test_impact_preserves_equal_priority_order_and_never_mutates_policy(self):
        self.store.set('grant_2', json.dumps(dict(self.grant, remote_user='other', allowed_actions=['ssh'])))
        before = {key: self.store.get(key) for key in self.store.keys('*')}
        result = preview_policy_impact(self.runtime, self.admin(), {'allowed_actions': ['ssh', 'http']}, replace_grant_id='1')
        self.assertEqual(result['counts']['gained'], 1)
        row = next(row for row in result['impacts'] if row['action'] == 'http')
        self.assertEqual(row['after']['remote_user'], 'support')
        self.assertEqual(row['after']['selected_grant']['id'], '1')
        self.assertEqual(result['coverage'], 'grant-principal-scenarios')
        self.assertIn('not a complete list of people', result['membership_notice'])
        self.assertEqual({key: self.store.get(key) for key in self.store.keys('*')}, before)

    def test_bound_user_preview_and_expiry_changes_are_not_ignored(self):
        grant = dict(self.grant, subject='user', name='renamed-login', keycloak_sub='stable-directory-subject',
            expires_at=int(time.time()) + 600)
        self.store.set('grant_1', json.dumps(grant))
        result = preview_policy_impact(self.runtime, self.admin(), {'expires_at': int(time.time()) + 120}, replace_grant_id='1')
        self.assertEqual(result['counts']['changed'], 1)
        self.assertTrue(result['impacts'][0]['before']['allowed'])
        self.assertEqual(result['impacts'][0]['subject_id'], 'stable-directory-subject')

    def test_impact_requires_platform_admin_and_has_bounded_output(self):
        for actor in (self.identity, dict(self.admin(), principal_type='service', service_client_id='terraform')):
            with self.assertRaises(ExplanationError) as failure:
                preview_policy_impact(self.runtime, actor, {'remote_user': 'reader'}, replace_grant_id='1')
            self.assertEqual(failure.exception.status, 403)
        self.store.set('server_2', json.dumps(dict(self.host, server_id='2', server_name='second')))
        result = preview_policy_impact(self.runtime, self.admin(), None, replace_grant_id='1', remove=True, max_entries=1)
        self.assertEqual(result['counts']['lost'], 2)
        self.assertEqual(len(result['impacts']), 1)
        self.assertTrue(result['truncated'])
        for candidate in ({'password_file': '/never-accept'}, {'allowed_actions': []}, {'starts_at': True}):
            with self.subTest(candidate=candidate), self.assertRaises(ExplanationError):
                preview_policy_impact(self.runtime, self.admin(), candidate, replace_grant_id='1')


class ExplanationHTTPTest(_Fixture):
    def setUp(self):
        super().setUp()
        self.app = Flask(__name__, static_folder=str(Path(__file__).resolve().parents[1] / 'shared/static'))
        self.app.config.update(SECRET_KEY='explanation-test-secret', TESTING=True)

        def bearer(allow_browser=False, mutation=False):
            header = request.headers.get('Authorization', '')
            if header.startswith('Bearer '):
                return header[7:]
            if allow_browser and session.get('runtime_session') == 'synthetic-browser-handle':
                if mutation and request.headers.get('X-CSRF-Token') != 'browser-csrf':
                    abort(403)
                return self.fixture.token
            abort(401)

        def bounded_json(maximum):
            if not request.is_json:
                abort(415)
            if len(request.get_data()) > maximum:
                abort(413)
            value = request.get_json()
            if not isinstance(value, dict):
                abort(400)
            return value

        register_explain_api(self.app, self.config, lambda: self.runtime, bearer, bounded_json,
            lambda exc: (jsonify(error='access_denied'), 403), (ValueError, IdentityError))
        self.client = self.app.test_client()
        self.headers = {'Authorization': 'Bearer ' + self.fixture.token}

    def test_http_requires_signature_and_uses_noncacheable_explanations(self):
        path = '/api/v1/access/explain/1'
        self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.get(path, headers={'Authorization': 'Bearer invalid-token'}).status_code, 403)
        response = self.client.get(path, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertTrue(response.json['snapshot_only'])
        self.assertEqual(self.client.get(path + '?username=another-user', headers=self.headers).status_code, 400)
        unknown = self.client.get('/api/v1/access/explain/999', headers=self.headers)
        self.assertEqual(unknown.status_code, 404)
        self.assertNotIn(self.fixture.token.encode(), response.data)

    def test_api_impact_requires_explicit_bearer_scope_and_browser_csrf(self):
        path = '/api/v1/admin/policy/impact'
        body = {'grant': {'remote_user': 'reader'}, 'replace_grant_id': '1'}
        self.assertEqual(self.client.post(path, headers=self.headers, json=body).status_code, 403)
        self.config['dashboard']['admin_groups'] = ['Support']
        scoped = self.fixture.sign(dict(self.fixture.claims, scope='isolate.policy.write'))
        response = self.client.post(path, headers={'Authorization': 'Bearer ' + scoped}, json=body)
        self.assertEqual(response.status_code, 200, response.data)
        with self.client.session_transaction() as signed:
            signed['runtime_session'] = 'synthetic-browser-handle'
        self.assertEqual(self.client.post(path, json=body).status_code, 403)
        response = self.client.post(path, headers={'X-CSRF-Token': 'browser-csrf'}, json=body)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.client.post(path, headers={'X-CSRF-Token': 'browser-csrf'}, json=dict(body, apply=True)).status_code, 400)

    def test_html_helpers_and_page_escape_untrusted_inventory_and_use_external_script(self):
        self.store.set('server_1', json.dumps(dict(self.host, server_name='<img src=x onerror=alert(1)>')))
        response = self.client.get('/workspace/access/1', headers=self.headers)
        self.assertEqual(response.status_code, 200, response.data)
        text = response.get_data(as_text=True)
        self.assertNotIn('<img src=x', text)
        self.assertIn('&lt;img', text)
        panel = explanation_panel('1', protocol='http', action='a"bad', russian=True)
        self.assertIn('/static/access-explain.js', panel)
        self.assertNotIn('a"bad', panel)
        self.assertIn('aria-live="polite"', panel)
        self.assertIn('/workspace/access/1?', explanation_link('1'))
        self.assertEqual(explanation_panel('1"><script>'), '')

    def test_browser_impact_prefill_csrf_and_remove_preview_never_apply(self):
        path = '/policy/impact?grant_id=1'
        self.assertEqual(self.client.get(path, headers=self.headers).status_code, 403)
        self.config['dashboard']['admin_groups'] = ['Support']
        with self.client.session_transaction() as signed:
            signed['runtime_session'] = 'synthetic-browser-handle'
            signed['csrf_token'] = 'browser-csrf'
        before = self.store.get('grant_1')
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('name="grant_id" value="1"', response.get_data(as_text=True))
        self.assertIn('support', response.get_data(as_text=True))
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        values = {'mode': 'remove', 'grant_id': '1'}
        self.assertEqual(self.client.post('/policy/impact', data=values).status_code, 403)
        response = self.client.post('/policy/impact', data=dict(values, csrf_token='browser-csrf'))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('Lost: 1', response.get_data(as_text=True))
        self.assertEqual(self.store.get('grant_1'), before)
        invalid = self.client.post('/policy/impact', data={'mode': 'replace', 'grant_id': '1',
            'grant': '{malformed-private-grant', 'csrf_token': 'browser-csrf'})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(self.store.get('grant_1'), before)


class LegacyExplanationTest(_Fixture):
    def test_cli_explicit_action_uses_precedence_and_redacts_credentials_and_denied_host(self):
        import isolate
        self.store.set('grant_1', json.dumps(dict(self.grant, allowed_actions=['ssh', 'http'])))
        args = SimpleNamespace(user=self.identity['username'], group=['Support'], role=None, project=None, host='1', action='http')
        with mock.patch.object(isolate, 'redis_client', return_value=self.store), redirect_stdout(StringIO()) as stdout:
            self.assertEqual(isolate.cmd_grant_explain(args, self.config), 0)
        result = json.loads(stdout.getvalue())
        self.assertTrue(result['allowed'])
        self.assertEqual(result['action'], 'http')
        self.assertEqual(result['matched_grant']['id'], '1')
        self.assertNotIn('do-not-leak', stdout.getvalue())
        self.assertNotIn('server_ip', result['host'])
        self.store.set('server_2', json.dumps(dict(self.host, server_id='2', project_name='private-project', password='private-password')))
        args.host = '2'
        with mock.patch.object(isolate, 'redis_client', return_value=self.store), redirect_stdout(StringIO()) as stdout:
            self.assertEqual(isolate.cmd_grant_explain(args, self.config), 2)
        self.assertNotIn('private-project', stdout.getvalue())
        self.assertNotIn('private-password', stdout.getvalue())
        self.assertIsNone(json.loads(stdout.getvalue())['host'])

    def test_mcp_known_and_forbidden_resources_do_not_expose_raw_inventory(self):
        from isolate_mcp import IsolateMCPService
        service = IsolateMCPService(self.config, self.store)
        result = service.grant_explain(self.identity, host_id='1')
        self.assertTrue(result['allowed'])
        self.assertNotIn('password', json.dumps(result))
        self.assertNotIn('server_ip', result['host'])
        self.store.set('server_2', json.dumps(dict(self.host, server_id='2', project_name='hidden-project', server_name='hidden-resource')))
        for host in ('2', '999'):
            result = service.grant_explain(self.identity, host_id=host)
            self.assertFalse(result['allowed'])
            self.assertEqual(result['reason_code'], 'resource_not_found_or_not_visible')
            self.assertIsNone(result['project'])
            self.assertNotIn('hidden-project', json.dumps(result))
            self.assertNotIn('hidden-resource', json.dumps(result))
        self.store.set('grant_2', json.dumps(dict(self.grant, allowed_actions=['http'])))
        result = service.grant_explain(self.identity, host_id='1', action='http')
        self.assertFalse(result['allowed'])


if __name__ == '__main__':
    unittest.main()
