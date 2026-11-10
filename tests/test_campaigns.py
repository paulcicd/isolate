"""Signed live delegation, SQL CAS campaigns and actual worker subprocesses."""
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import isolate_campaigns as campaigns
import isolate_jobs as jobs
from isolate_identity import normalize_claims
from isolate_state import SQLState, StateClient
import test_delegation as fixtures


class CampaignTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.DelegationTest.setUpClass()

    def setUp(self):
        self.fixture = fixtures.DelegationTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config = self.fixture.config
        self.root = Path(self.fixture.directory.name)
        self.config['state'] = {'backend': 'sqlite', 'sqlite_path': str(self.root / 'campaigns.sqlite')}
        SQLState(self.config['state']).initialize()
        self.store = StateClient(self.fixture.redis, self.config['state'])
        for key in ('server_1', 'grant_1'):
            self.store.set(key, self.fixture.redis.get(key))
            self.fixture.redis.delete(key)
        grant = json.loads(self.store.get('grant_1'))
        grant['request_id'] = '41'
        self.store.set('grant_1', json.dumps(grant))
        self.config['campaigns'] = {'enabled': True, 'max_hosts': 100, 'max_batch_size': 50}
        self.config['logging']['base_path'] = str(self.root / 'logs')
        self.config['runbooks']['enabled'] = True
        self.config['runbooks']['read_only']['allowed_groups'] = ['Support']
        self.config['api']['enabled'] = True
        self.claims = dict(self.fixture.claims, scope='isolate.runbook isolate.execute')
        self.token = self.fixture.sign(self.claims)
        self.identity = normalize_claims(self.claims, self.config['keycloak'])
        for identifier in range(2, 5):
            self.store.set('server_' + str(identifier), json.dumps(dict(self.fixture.host,
                server_id=str(identifier), server_name='host-' + str(identifier))))
        self.body = {'runbook_id': 'uptime', 'host_ids': ['1', '2', '3', '4'],
            'canary_count': 1, 'batch_size': 2, 'failure_budget': 0}

    def create(self, body=None, key='campaign-idempotent-0001'):
        body = copy.deepcopy(body or self.body)
        preview = campaigns.preview_campaign(self.store, self.config, self.identity, body, self.token)
        body.update(preview_digest=preview['preview_digest'], confirm=True)
        return campaigns.create_campaign(self.store, self.config, self.identity, body, self.token, key)[0]

    def complete(self, record, index, status='completed'):
        from isolate_worker_ownership import claim_job, update_owned_job, release_lock
        job = jobs.get_job(self.store, record['jobs'][index]['id'])
        owner = 'fixture-result-owner-' + job['id']
        self.store.set('job_lock_' + job['id'], owner, ex=60)
        job = claim_job(self.store, job['id'], owner)
        updates = dict(status=status, exit_code=0 if status == 'completed' else 1, finished_at=int(time.time()))
        if status in ('completed', 'failed'):
            updates['campaign_result'] = campaigns.terminal_result_receipt(self.store, self.config, job, updates, owner)
        update_owned_job(self.store, job['id'], owner, updates)
        release_lock(self.store, 'job_lock_' + job['id'], owner)

    def test_unsigned_or_changed_terminal_results_cannot_authorize_next_batch(self):
        for index, mode in enumerate(('unsigned', 'changed-result', 'changed-signature')):
            record = self.create(key='forged-terminal-result-' + str(index))
            child_id = record['jobs'][0]['id']
            if mode != 'unsigned':
                self.complete(record, 0)
            child = jobs.get_job(self.store, child_id)
            if mode == 'unsigned':
                child.update(status='completed', exit_code=0, finished_at=int(time.time()))
            elif mode == 'changed-result':
                child['finished_at'] += 1
            else:
                child['campaign_result']['signature'] = '0' * 64
            self.store.set('job_' + child_id, json.dumps(child))
            result = campaigns.reconcile_campaign(self.store, self.config, record['id'])
            self.assertEqual(result['status'], 'recovery_required')
            self.assertEqual(result['stop_reason'], 'unverified_child_result')
            self.assertEqual(jobs.get_job(self.store, record['jobs'][1]['id'])['status'], 'cancelled')

    def test_publication_is_atomic_and_schema4_seals_campaign_before_delegation(self):
        record = self.create()
        children = [jobs.get_job(self.store, item['id']) for item in record['jobs']]
        self.assertEqual([job['status'] for job in children], ['queued', 'held', 'held', 'held'])
        self.assertEqual(len(self.fixture.redis.keys('job_*')), 0)
        for child in children:
            self.assertEqual(child['schema_version'], 4)
            self.assertEqual(child['access_request_id'], '41')
            self.assertTrue(jobs.verify_job_signature(child, self.config))
            from isolate_delegation import recheck_delegation
            identity, decision = recheck_delegation(self.store, self.config, child,
                json.loads(self.store.get('server_' + child['host_id'])))
            self.assertEqual(identity['keycloak_sub'], self.identity['keycloak_sub'])
            self.assertFalse(jobs.verify_job_signature(dict(child, campaign_id='0' * 32), self.config))
        self.assertNotIn(self.token, json.dumps(campaigns.public_campaign(self.store, record)))
        evidence = [json.loads(self.store.get(key)) for key in self.store.keys('workflow_event_*')]
        self.assertEqual({event['event'] for event in evidence}, {'campaign_created', 'campaign_stage_started'})
        self.assertTrue(all(event['outcome'] == 'committed' and event['campaign_id'] == record['id'] for event in evidence))

    def test_concurrent_duplicate_submissions_publish_only_one_fleet(self):
        preview = campaigns.preview_campaign(self.store, self.config, self.identity, self.body, self.token)
        body = dict(self.body, preview_digest=preview['preview_digest'], confirm=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: campaigns.create_campaign(self.store, self.config, self.identity, body,
                self.token, 'concurrent-key-00001'), range(2)))
        self.assertEqual(len({record['id'] for record, created in results}), 1)
        self.assertEqual(sum(created for record, created in results), 1)
        self.assertEqual(len(jobs.list_jobs(self.store)), 4)

    def test_stale_preview_partial_denial_and_missing_confirmation_create_no_jobs(self):
        preview = campaigns.preview_campaign(self.store, self.config, self.identity, self.body, self.token)
        body = dict(self.body, preview_digest=preview['preview_digest'], confirm=True)
        host = json.loads(self.store.get('server_4'))
        host['server_ip'] = '192.0.2.44'
        self.store.set('server_4', json.dumps(host))
        with self.assertRaisesRegex(campaigns.CampaignError, 'preview'):
            campaigns.create_campaign(self.store, self.config, self.identity, body, self.token, 'stale-preview-key000')
        with self.assertRaises(campaigns.CampaignError):
            campaigns.create_campaign(self.store, self.config, self.identity, dict(body, confirm=1), self.token, 'numeric-confirm-key1')
        self.store.delete('server_4')
        with self.assertRaises(jobs.JobError):
            self.create()
        self.assertEqual(jobs.list_jobs(self.store), [])

    def test_successful_canary_and_complete_batches_promote_once_under_concurrency(self):
        record = self.create()
        self.complete(record, 0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: campaigns.reconcile_campaign(self.store, self.config, record['id']), range(2)))
        record = campaigns.get_campaign(self.store, record['id'])
        self.assertEqual(record['current_stage'], 1)
        self.assertEqual(sum(event['event'] == 'campaign_stage_started' for event in record['events']), 2)
        self.assertEqual([jobs.get_job(self.store, row['id'])['status'] for row in record['jobs']], ['completed', 'queued', 'queued', 'held'])
        self.complete(record, 1)
        campaigns.reconcile_campaign(self.store, self.config, record['id'])
        self.assertEqual(jobs.get_job(self.store, record['jobs'][3]['id'])['status'], 'held')
        self.complete(record, 2)
        campaigns.reconcile_campaign(self.store, self.config, record['id'])
        self.assertEqual(jobs.get_job(self.store, record['jobs'][3]['id'])['status'], 'queued')

    def test_canary_failure_unknown_result_and_thresholds_stop_future_work(self):
        for index, mode in enumerate(('failed', 'recovery_required', 'claimed', 'budget', 'percentage')):
            record = self.create(dict(self.body, failure_budget=1, max_failure_percent=0 if mode == 'percentage' else 100), key='threshold-case-key' + str(index))
            if mode in ('budget', 'percentage'):
                self.complete(record, 0)
                campaigns.reconcile_campaign(self.store, self.config, record['id'])
                self.complete(record, 1, 'failed')
                if mode == 'budget':
                    self.complete(record, 2, 'failed')
            else:
                self.complete(record, 0, mode)
            stopped = campaigns.reconcile_campaign(self.store, self.config, record['id'])
            self.assertIn(stopped['status'], ('stopped', 'recovery_required'))
            self.assertEqual(jobs.get_job(self.store, record['jobs'][3]['id'])['status'], 'cancelled')
            self.assertNotIn('retry_of', stopped)

    def test_current_authority_loss_offboarding_and_epoch_rotation_stop_dispatch(self):
        from isolate_governance import _offboard_key
        for index, mode in enumerate(('grant', 'offboard', 'epoch')):
            record = self.create(key='revocation-case-000' + str(index))
            if mode == 'grant':
                saved = self.store.get('grant_1')
                self.store.delete('grant_1')
            elif mode == 'offboard':
                self.store.set(_offboard_key(self.identity['keycloak_sub'], 'prod'), json.dumps({'schema_version': 1,
                    'subject_id': self.identity['keycloak_sub'], 'project': 'prod', 'status': 'blocked'}))
            else:
                self.store.set('isolate_authority_epoch', 'different-authority')
            stopped = campaigns.reconcile_campaign(self.store, self.config, record['id'])
            self.assertEqual(stopped['status'], 'stopped', mode)
            self.assertTrue(all(jobs.get_job(self.store, child['id'])['status'] == 'cancelled' for child in record['jobs']))
            if mode == 'grant':
                self.store.set('grant_1', saved)
            elif mode == 'offboard':
                self.store.delete(_offboard_key(self.identity['keycloak_sub'], 'prod'))

    def test_transport_failure_or_timeout_never_spends_failure_budget_to_expand(self):
        for index, (status, exit_code) in enumerate((('failed', 255), ('failed', None), ('timed_out', -9))):
            record = self.create(dict(self.body, failure_budget=4), key='unknown-transport-00' + str(index))
            self.complete(record, 0)
            campaigns.reconcile_campaign(self.store, self.config, record['id'])
            job = jobs.get_job(self.store, record['jobs'][1]['id'])
            job.update(status=status, exit_code=exit_code)
            self.store.set('job_' + job['id'], json.dumps(job))
            result = campaigns.reconcile_campaign(self.store, self.config, record['id'])
            self.assertEqual(result['status'], 'recovery_required')
            self.assertEqual(result['stop_reason'], 'unknown_outcome')
            self.assertEqual(jobs.get_job(self.store, record['jobs'][3]['id'])['status'], 'cancelled')

    def test_cancel_racing_promotion_and_tampered_progress_never_bypass_canary(self):
        record = self.create()
        self.complete(record, 0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda operation: operation(), [
                lambda: campaigns.reconcile_campaign(self.store, self.config, record['id']),
                lambda: campaigns.cancel_campaign(self.store, self.config, record['id'], self.identity, confirmed=True)]))
        self.assertEqual(campaigns.get_campaign(self.store, record['id'])['status'], 'cancelled')
        self.assertTrue(all(jobs.get_job(self.store, child['id'])['status'] == 'cancelled' for child in record['jobs'][1:]))
        other = self.create(key='tampered-progress-001')
        altered = dict(other, current_stage=1)
        self.store.set('runbook_campaign_' + other['id'], json.dumps(altered))
        queued = jobs.get_job(self.store, other['jobs'][1]['id'])
        queued['status'] = 'queued'
        self.store.set('job_' + queued['id'], json.dumps(queued))
        with mock.patch.object(jobs.subprocess, 'Popen') as remote:
            result = jobs.execute_job(self.store, self.config, queued)
        self.assertEqual(result['status'], 'failed')
        remote.assert_not_called()

    def test_real_worker_processes_canary_then_batches_without_repeating_claims(self):
        record = self.create()
        argv = [sys.executable, '-u', '-c', 'print("real-worker-output")']
        with mock.patch.object(jobs, 'build_ssh_argv', return_value=argv):
            jobs.run_worker(self.config, self.store, once=True)
            self.assertEqual(campaigns.get_campaign(self.store, record['id'])['current_stage'], 1)
            self.assertEqual(jobs.get_job(self.store, record['jobs'][3]['id'])['status'], 'held')
            jobs.run_worker(self.config, self.store, once=True)
            jobs.run_worker(self.config, self.store, once=True)
            jobs.run_worker(self.config, self.store, once=True)
        self.assertEqual(campaigns.get_campaign(self.store, record['id'])['status'], 'completed')
        self.assertEqual(len(self.store.keys('job_execution_claim_*')), 4)
        for child in record['jobs']:
            job = jobs.get_job(self.store, child['id'])
            self.assertEqual(job['status'], 'completed')
            self.assertIn('real-worker-output', Path(job['output_path']).read_text())
        with self.assertRaises(jobs.JobError):
            jobs.retry_job(self.store, self.config, record['jobs'][0]['id'], self.identity, current_identity=self.identity, token=self.token)

    def test_cancelling_actual_running_canary_terminates_process_and_cancels_held_children(self):
        record = self.create()
        child_id = record['jobs'][0]['id']
        argv = [sys.executable, '-u', '-c', 'import time; print("running-canary", flush=True); time.sleep(20)']
        with mock.patch.object(jobs, 'build_ssh_argv', return_value=argv), concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            worker = pool.submit(jobs.run_worker, self.config, self.store, True)
            for _ in range(200):
                child = jobs.get_job(self.store, child_id)
                if child['status'] == 'running' and child.get('output_path') and Path(child['output_path']).exists() and Path(child['output_path']).stat().st_size:
                    break
                time.sleep(.02)
            self.assertEqual(child['status'], 'running')
            campaigns.cancel_campaign(self.store, self.config, record['id'], self.identity, confirmed=True)
            worker.result(timeout=5)
        self.assertEqual(jobs.get_job(self.store, child_id)['status'], 'cancelled')
        self.assertTrue(all(jobs.get_job(self.store, value['id'])['status'] == 'cancelled' for value in record['jobs'][1:]))
        self.assertEqual(len(self.store.keys('job_execution_claim_*')), 1)


if __name__ == '__main__':
    unittest.main()
