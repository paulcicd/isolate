"""Offboarding crosses signed runtime, legacy SSH and real HTTP/WS boundaries."""
import asyncio
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import test_runtime_api_index as fixtures
from isolate_connection_auth import bind_identity
from isolate_governance import offboard
from isolate_identity import IdentityError
from isolate_runtime import Runtime


class GovernanceRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RuntimeTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.config, self.store = self.fixture.config, self.fixture.redis
        self.config['dashboard'].update(admin_groups=['Platform'], role_bindings=[{'group': 'Owners', 'role': 'project-owner', 'projects': ['prod']}])
        self.owner = {'username': 'owner', 'keycloak_sub': 'independent-owner', 'groups': ['Owners', 'Platform']}
        self.person = self.fixture.runtime.authenticate(self.fixture.token)
        grant = json.loads(self.store.get('grant_1'))
        grant['allowed_actions'] = ['ssh', 'http', 'kubernetes', 'postgresql', 'mysql']
        self.store.set('grant_1', json.dumps(grant))
        secret = Path(self.fixture.directory.name) / 'kubernetes-token'
        secret.write_text('synthetic-service-credential')
        secret.chmod(0o600)
        targets = {}
        for identifier, protocol, upstream in (('2', 'http', 'https://api.internal:443'),
                ('3', 'kubernetes', 'https://cluster.internal:6443'), ('4', 'postgresql', 'postgresql://database.internal:5432'),
                ('5', 'mysql', 'mysql://database.internal:3306')):
            self.store.set('server_' + identifier, json.dumps({'server_id': identifier, 'server_ip': '127.0.0.1',
                'server_name': 'resource-' + identifier, 'project_name': 'prod', 'server_port': 22}))
            target = {'protocol': protocol, 'project': 'prod', 'upstream': upstream}
            if protocol == 'kubernetes':
                target.update(impersonation=True, bearer_token_file=str(secret), allowed_paths=['/api/*'])
            if protocol in ('postgresql', 'mysql'):
                target.update(database_native_auth=True, require_native_tls=True)
            targets[identifier] = target
        self.config['protocols'] = {'enabled': True, 'targets': targets}
        self.runtime = Runtime(self.config, self.store)

    def test_project_offboarding_denies_every_protocol_and_preissued_ticket_and_live_context(self):
        protocols = [('1', 'ssh'), ('1', 'webssh'), ('2', 'http'), ('3', 'kubernetes'), ('4', 'postgresql'), ('5', 'mysql')]
        tickets = [(self.runtime.create_ticket(self.fixture.token, host, protocol)['ticket'], protocol) for host, protocol in protocols]
        context = self.runtime.authorize(self.fixture.token, '1')
        self.runtime.prepare(context)
        self.runtime.start(context)
        self.addCleanup(self.runtime.finish, context)
        offboard(self.store, self.config, self.owner, self.person['keycloak_sub'], 'prod', 'End project assignment')
        self.assertEqual(self.runtime.authenticate(self.fixture.token)['keycloak_sub'], self.person['keycloak_sub'])
        for host, protocol in protocols:
            with self.subTest(protocol=protocol), self.assertRaises(IdentityError):
                self.runtime.authorize(self.fixture.token, host, protocol)
        for ticket, protocol in tickets:
            with self.subTest(ticket_protocol=protocol), self.assertRaises(IdentityError):
                self.runtime.consume_ticket(ticket, protocol)
        with self.assertRaises(IdentityError):
            self.runtime.recheck(context)
        # Reimporting the same wider group grant cannot undo the overlay.
        grant = json.loads(self.store.get('grant_1'))
        self.store.set('grant_1', json.dumps(grant))
        with self.assertRaises(IdentityError):
            self.runtime.authorize(self.fixture.token, '1')

    def test_global_offboarding_denies_existing_browser_bearer_and_legacy_ssh_identity(self):
        self.assertEqual(bind_identity(self.fixture.token, self.config, 'alice', self.store)['keycloak_sub'], self.person['keycloak_sub'])
        app = self.fixture.app()
        client = app.test_client()
        with client.session_transaction() as session:
            session.update(identity=self.person, runtime_session='existing-browser-session')
        self.store.set('isolate_browser_existing-browser-session', json.dumps({'sub': self.person['keycloak_sub'], 'token': self.fixture.token}))
        offboard(self.store, self.config, self.owner, self.person['keycloak_sub'], '*', 'End product access')
        with self.assertRaises(IdentityError):
            self.runtime.authenticate(self.fixture.token)
        with self.assertRaises(IdentityError):
            bind_identity(self.fixture.token, self.config, 'alice', self.store)
        self.assertEqual(client.get('/api/v1/me', headers={'Authorization': 'Bearer ' + self.fixture.token}).status_code, 403)
        self.assertIn(client.get('/workspace').status_code, (302, 403))


class GovernanceStreamsTest(unittest.IsolatedAsyncioTestCase):
    def owner(self, config):
        config['dashboard']['role_bindings'] = [{'group': 'Owners', 'role': 'project-owner', 'projects': ['prod']}]
        return {'username': 'owner', 'keycloak_sub': 'independent-owner', 'groups': ['Owners']}

    async def test_project_offboarding_closes_real_browser_application_socket(self):
        import test_web_apps as applications
        fixture = applications.BrowserApplicationsTest()
        await fixture.asyncSetUp()
        try:
            owner = self.owner(fixture.config)
            cookie, _ = await fixture.launch()
            socket = await fixture.client.ws_connect(fixture.base + '/ws', headers=fixture.headers(cookie, origin=fixture.origin), protocols=['chat'])
            await socket.send_str('before-offboarding')
            self.assertEqual((await socket.receive()).data, 'echo:before-offboarding')
            await asyncio.to_thread(offboard, fixture.store, fixture.config, owner, fixture.fixture.claims['sub'], 'prod', 'End project access')
            from aiohttp import WSMsgType
            self.assertIn((await asyncio.wait_for(socket.receive(), 3)).type, (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING))
            self.assertFalse(fixture.sessions.active)
        finally:
            await fixture.asyncTearDown()

    async def test_project_offboarding_closes_real_kubernetes_stream(self):
        import test_kubernetes_streams as kubernetes
        fixture = kubernetes.KubernetesNetworkTest()
        await fixture.asyncSetUp()
        try:
            owner = self.owner(fixture.fixture.config)
            path = fixture.base + '/api/v1/namespaces/prod/pods/demo/attach?stdin=true&stdout=true'
            socket = await fixture.client.ws_connect(path, headers=fixture.auth, protocols=kubernetes.REMOTE_PROTOCOLS)
            self.assertEqual((await socket.receive()).data[0], 1)
            await asyncio.to_thread(offboard, fixture.fixture.redis, fixture.fixture.config, owner, fixture.fixture.claims['sub'], 'prod', 'End project access')
            from aiohttp import WSMsgType
            self.assertIn((await asyncio.wait_for(socket.receive(), 3)).type, (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING))
        finally:
            await fixture.client.close()
            await fixture.upstream.close()
            fixture.fixture.doCleanups()


if __name__ == '__main__':
    unittest.main()
