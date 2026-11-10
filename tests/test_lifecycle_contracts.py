"""Critical safety requirements are explicit in the new public API contract."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
from isolate_openapi import build_openapi


class LifecycleContractTest(unittest.TestCase):
    def setUp(self):
        self.document = build_openapi()
        self.schemas = self.document['components']['schemas']
        self.paths = self.document['paths']

    def request_schema(self, path, method='post'):
        request = self.paths[path][method]['requestBody']
        self.assertTrue(request['required'])
        schema = request['content']['application/json']['schema']
        return self.schemas[schema['$ref'].split('/')[-1]] if '$ref' in schema else schema

    def test_lifecycle_mutations_require_confirmation_and_creation_intents(self):
        paths = ['/api/v1/governance/reviews', '/api/v1/governance/reviews/{review_id}/decisions',
            '/api/v1/governance/assignments', '/api/v1/governance/assignments/{assignment_id}/revoke',
            '/api/v1/governance/offboarding']
        for path in paths:
            schema = self.request_schema(path)
            self.assertIn('confirm', schema['required'])
            self.assertEqual(schema['properties']['confirm'], {'const': True})
            self.assertFalse(schema['additionalProperties'])
            self.assertIn({'BrowserSession': [], 'CSRFToken': []}, self.paths[path]['post']['security'])
        for path in ('/api/v1/governance/reviews', '/api/v1/governance/assignments'):
            self.assertIn({'$ref': '#/components/parameters/IdempotencyKey'}, self.paths[path]['post']['parameters'])
        offboard = self.schemas['OffboardingRequest']
        self.assertIn('subject_id', offboard['required'])
        self.assertEqual(offboard['properties']['project']['oneOf'][1], {'const': '*'})

    def test_campaign_create_binds_preview_and_stops_are_in_response_contract(self):
        preview = self.request_schema('/api/v1/runbook-campaigns/preview')
        self.assertEqual(set(preview['required']), {'runbook_id', 'host_ids'})
        create = self.request_schema('/api/v1/runbook-campaigns')
        self.assertIn('preview_digest', create['required'])
        self.assertIn('confirm', create['required'])
        self.assertNotIn('readOnly', create['properties']['preview_digest'])
        self.assertEqual(self.schemas['CampaignPreview']['properties']['stop_on_unknown'], {'const': True})
        self.assertEqual(self.schemas['CampaignPreview']['properties']['automatic_retries'], {'const': False})
        self.assertIn('200', self.paths['/api/v1/runbook-campaigns']['post']['responses'])
        self.assertIn('201', self.paths['/api/v1/runbook-campaigns']['post']['responses'])
        self.assertEqual(set(self.schemas['RunbookCampaign']['properties']['status']['enum']),
            {'active', 'completed', 'stopped', 'cancelled', 'recovery_required'})

    def test_explanations_and_impact_are_snapshots_with_explicit_visibility_and_scope(self):
        explain = self.paths['/api/v1/access/explain/{host_id}']
        self.assertEqual(set(explain), {'get'})
        self.assertIn('404', explain['get']['responses'])
        self.assertEqual(self.schemas['AccessExplanation']['properties']['snapshot_only'], {'const': True})
        impact = self.paths['/api/v1/admin/policy/impact']['post']
        self.assertEqual(impact['x-required-oauth-scopes'], ['isolate.policy.write'])
        self.assertFalse(self.request_schema('/api/v1/admin/policy/impact')['additionalProperties'])
        self.assertEqual(self.schemas['PolicyImpact']['properties']['coverage'], {'const': 'grant-principal-scenarios'})

    def test_governance_responses_describe_delivery_and_schedules(self):
        for path, model in (('/api/v1/governance/reviews', 'AccessReview'),
                            ('/api/v1/governance/assignments', 'AccessAssignment'),
                            ('/api/v1/governance/offboarding', 'Offboarding')):
            operation = self.paths[path]['post']
            success = '201' if '201' in operation['responses'] else '200'
            envelope = operation['responses'][success]['content']['application/json']['schema']
            self.assertEqual(set(envelope['required']), {'result', 'audit_delivery'})
            self.assertEqual(envelope['properties']['result'], {'$ref': '#/components/schemas/' + model})
        self.assertIn('review_schedule', self.schemas['GovernanceDashboard']['required'])
        self.assertEqual(self.schemas['AuditDelivery']['properties']['status'], {'const': 'retained'})
        self.assertEqual(set(self.schemas['AuditDelivery']['properties']), {'status', 'publication'})


if __name__ == '__main__':
    unittest.main()
