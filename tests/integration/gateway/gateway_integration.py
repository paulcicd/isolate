"""Real HTTPS Keycloak -> API -> native/Web SSH -> Redis/PostgreSQL checks.

Run through the adjacent Docker Compose file. No live environment is contacted;
the realm, CA, users, keys, database and Redis belong only to this test network.
"""

import asyncio
import contextlib
import copy
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'shared'))

import aiohttp
from aiohttp import web
import asyncssh
import redis
import requests
from werkzeug.serving import WSGIRequestHandler, make_server

from isolate_audit_index import AuditIndex
from isolate_config import DEFAULT_CONFIG
from isolate_gateway import create_native_listener, create_web_app
from isolate_identity import IdentityError
from isolate_runtime import Runtime
from isolate_web import create_app


ISSUER = 'https://keycloak:8443/realms/isolate-integration'
DASHBOARD = 'https://runner:9443'
CA = '/fixtures/ca.pem'


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def progress(message):
    print(message, flush=True)


class Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {'action': attrs.get('action'), 'id': attrs.get('id'), 'inputs': {}}
            self.forms.append(self.current)
        if tag == 'input' and self.current is not None and attrs.get('name'):
            self.current['inputs'][attrs['name']] = attrs.get('value', '')

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


class QuietHandler(WSGIRequestHandler):
    # Callback URLs contain one-time authorization codes. Keep them out of logs.
    def log_request(self, *args, **kwargs):
        pass


def browser_session():
    session = requests.Session()
    session.trust_env = False
    session.verify = CA
    return session


def wait_for_keycloak():
    session = browser_session()
    for _ in range(90):
        try:
            response = session.get(ISSUER + '/.well-known/openid-configuration', timeout=3)
            if response.status_code == 200:
                check(response.json()['issuer'] == ISSUER, 'discovery issuer differs')
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise RuntimeError('isolated HTTPS Keycloak did not become ready')


def browser_login(browser):
    start = browser.get(DASHBOARD + '/login', timeout=10, allow_redirects=False)
    check(start.status_code == 302, 'dashboard did not start OIDC login')
    auth_url = start.headers['Location']
    query = parse_qs(urlsplit(auth_url).query)
    check(bool(query.get('state')) and bool(query.get('nonce')), 'OIDC state/nonce missing')
    page = browser.get(auth_url, timeout=10)
    parser = Forms()
    parser.feed(page.text)
    forms = [form for form in parser.forms if form['id'] == 'kc-form-login']
    check(len(forms) == 1, 'Keycloak did not render the browser login form')
    form = forms[0]
    credentials = dict(form['inputs'], username='alice', password='isolated-integration-user-password')
    result = browser.post(form['action'], data=credentials, timeout=15)
    check(result.status_code == 200 and urlsplit(result.url).netloc == 'runner:9443',
          'authorization-code login/callback did not finish at dashboard')
    check('alice' in result.text, 'verified browser identity is missing')
    return browser


async def main():
    progress('Waiting for isolated HTTPS Keycloak (password grant disabled)')
    await asyncio.to_thread(wait_for_keycloak)
    store = redis.Redis(host='redis', socket_timeout=3)
    store.flushdb()  # Compose's private test-only Redis, never the demo Redis.
    with tempfile.TemporaryDirectory(prefix='isolate-gateway-integration-') as directory:
        work = Path(directory)
        config = copy.deepcopy(DEFAULT_CONFIG)
        config['data_root'] = directory
        config['redis'].update(host='redis')
        config['keycloak'].update(issuer=ISSUER, client_id='isolate-integration',
            expected_audience='isolate-integration', client_secret='isolated-integration-client-secret',
            jwks_cache_path=str(work / 'jwks.json'), tls_verify=True, verify_tokens=True)
        config['dashboard'].update(enabled=True, public_url=DASHBOARD, self_service_enabled=True,
            self_service_groups=['Integration-Operators'], admin_groups=[])
        secret = work / 'dashboard-secret'
        secret.write_text('integration-dashboard-secret-with-enough-entropy-for-tests')
        config['dashboard']['secret_key_file'] = str(secret)
        config['api'].update(enabled=True, bind_ticket_ip=False)
        config['gateway'].update(enabled=True, listen_host='127.0.0.1', ssh_port=0,
            web_host='0.0.0.0', web_port=0, recheck_interval=0.2,
            allowed_origins=[DASHBOARD], public_ssh_host='runner')
        config['identity_security']['backchannel_logout']['enabled'] = True
        config['connection_authorization'].update(max_session_seconds=120)
        config['logging'].update(base_path=str(work / 'logs'), fail_closed=True, sync=True)
        dsn = work / 'audit-dsn'
        dsn.write_text('postgresql://isolate_test:isolated-integration-database-password@postgres/isolate_test')
        dsn.chmod(0o600)
        config['audit_index'].update(enabled=True, driver='postgresql', dsn_file=str(dsn))
        config['logging']['sinks'] = [dict(config['audit_index'], type='sql')]
        index = AuditIndex(config['audit_index'])
        await asyncio.to_thread(index.initialize)

        target_key = asyncssh.generate_private_key('ssh-ed25519')
        client_key = asyncssh.generate_private_key('ssh-ed25519')
        gateway_key = asyncssh.generate_private_key('ssh-ed25519')
        keyfile = work / 'client-key'
        keyfile.write_bytes(client_key.export_private_key())
        keyfile.chmod(0o600)
        gateway_keyfile = work / 'gateway-key'
        gateway_keyfile.write_bytes(gateway_key.export_private_key())
        gateway_keyfile.chmod(0o600)
        config['gateway']['host_key_file'] = str(gateway_keyfile)

        class TargetServer(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True
            def public_key_auth_supported(self):
                return True
            def validate_public_key(self, username, key):
                return username == 'observer' and key == client_key.convert_to_public()

        async def target_process(process):
            if process.command == 'whoami':
                process.stdout.write('observer\n')
            elif process.command == 'hold':
                process.stdout.write('ready\n')
                await process.stdin.read()
            elif process.command is None:
                async for line in process.stdin:
                    if line.strip() == 'whoami':
                        process.stdout.write('observer\n')
                    elif line.strip() == 'exit':
                        break
            else:
                process.stderr.write('unsupported integration command\n')
                process.exit(2)
                return
            process.exit(0)

        target = await asyncssh.create_server(TargetServer, '127.0.0.1', 0, server_host_keys=[target_key],
            process_factory=target_process, encoding='utf-8', config=[], line_editor=False)
        target_port = target.get_port()
        known_hosts = work / 'known-hosts'
        known_hosts.write_text('[127.0.0.1]:{} {}'.format(target_port, target_key.export_public_key().decode()))
        config['gateway']['known_hosts'] = str(known_hosts)
        config['credentials'] = {'default': 'integration', 'known_hosts': str(known_hosts), 'targets': {},
            'providers': {'integration': {'type': 'file', 'private_key_file': str(keyfile)}}}
        host = {'server_id': '10001', 'server_name': 'integration-target', 'server_ip': '127.0.0.1',
                'server_port': target_port, 'server_user': 'observer', 'project_name': 'integration'}
        store.set('server_10001', json.dumps(host))
        store.set('grant_1', json.dumps({'subject': 'group', 'name': 'Integration-Operators',
            'project': 'integration', 'host': '10001', 'remote_user': 'observer', 'sudo_mode': 'none',
            'allowed_actions': ['ssh']}))
        runtime = Runtime(config, store)
        native = await create_native_listener(runtime)
        native_port = native.get_port()
        config['gateway']['ssh_port'] = native_port
        gateway_known = work / 'gateway-known-hosts'
        gateway_known.write_text('[127.0.0.1]:{} {}'.format(native_port, gateway_key.export_public_key().decode()))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain('/fixtures/runner.pem', '/fixtures/runner.key')
        gateway_app = create_web_app(runtime)
        gateway_runner = web.AppRunner(gateway_app)
        await gateway_runner.setup()
        gateway_site = web.TCPSite(gateway_runner, '0.0.0.0', 0, ssl_context=tls)
        await gateway_site.start()
        gateway_port = gateway_site._server.sockets[0].getsockname()[1]
        config['gateway']['public_web_url'] = 'wss://runner:{}'.format(gateway_port)
        flask_app = create_app(config)
        logout_deliveries = []

        @flask_app.before_request
        def observe_test_logout():
            from flask import request
            if request.path == '/auth/backchannel-logout':
                logout_deliveries.append(request.form.get('logout_token'))

        server = make_server('0.0.0.0', 9443, flask_app, threaded=True, request_handler=QuietHandler,
                             ssl_context=('/fixtures/runner.pem', '/fixtures/runner.key'))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # Exercise real Authlib state/nonce handling, not an injected cookie.
            invalid_browser = browser_session()
            await asyncio.to_thread(invalid_browser.get, DASHBOARD + '/login', allow_redirects=False, timeout=10)
            invalid = await asyncio.to_thread(invalid_browser.get, DASHBOARD + '/auth/callback?state=invalid&code=invalid', timeout=10)
            check(invalid.status_code == 401, 'OIDC callback accepted an invalid state')
            browser = await asyncio.to_thread(browser_login, browser_session())
            cookie = browser.cookies.get('session')
            session = flask_app.session_interface.get_signing_serializer(flask_app).loads(cookie)
            token_record = json.loads(store.get('isolate_browser_' + session['runtime_session']))
            token = token_record['token']
            identity = await asyncio.to_thread(runtime.authenticate, token)
            check(identity['username'] == 'alice' and 'Integration-Operators' in identity['groups'],
                  'real Keycloak subject/groups did not survive authentication')
            check(token not in cookie, 'bearer token leaked into the browser cookie')
            progress('PASS: real authorization-code login, signed token/groups, invalid state rejection')

            async def issue(protocol):
                response = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/connections',
                    headers={'Authorization': 'Bearer ' + token}, json={'host_id': '10001', 'protocol': protocol}, timeout=10)
                check(response.status_code == 201, 'API did not issue a connection ticket')
                return response.json()['ticket']

            ticket = await issue('ssh')
            async with asyncssh.connect('127.0.0.1', port=native_port, username='10001', password=ticket,
                    known_hosts=str(gateway_known), client_keys=[], agent_path=None, config=[]) as connection:
                result = await asyncio.wait_for(connection.run('whoami', check=True), 10)
                check(result.stdout.strip() == 'observer', 'native SSH target account differs from policy')
            try:
                await asyncssh.connect('127.0.0.1', port=native_port, username='10001', password=ticket,
                    known_hosts=str(gateway_known), client_keys=[], agent_path=None, config=[])
            except asyncssh.PermissionDenied:
                pass
            else:
                raise AssertionError('native gateway reused a consumed ticket')
            progress('PASS: API ticket -> native SSH -> policy-selected target account; replay denied')

            terminal = await asyncio.to_thread(browser.get, DASHBOARD + '/me/terminal/10001', timeout=10)
            check(terminal.status_code == 200, 'authenticated browser terminal page failed')
            match = re.search(r'data-csrf-token="([^"]+)"', terminal.text)
            check(match is not None, 'terminal did not expose its CSRF token')
            denied = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/connections',
                json={'host_id': '10001', 'protocol': 'webssh'}, timeout=10)
            check(denied.status_code == 403, 'browser ticket mutation accepted missing CSRF')
            issued = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/connections',
                headers={'X-CSRF-Token': html.unescape(match.group(1))},
                json={'host_id': '10001', 'protocol': 'webssh'}, timeout=10)
            check(issued.status_code == 201, 'browser session+CSRF did not issue Web SSH ticket')
            client_tls = ssl.create_default_context(cafile=CA)
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=client_tls)) as client:
                async with client.ws_connect(config['gateway']['public_web_url'] + '/ssh',
                        headers={'Origin': DASHBOARD}) as websocket:
                    await websocket.send_json({'ticket': issued.json()['ticket'], 'cols': 80, 'rows': 24})
                    for _ in range(10):
                        state = await websocket.receive_json(timeout=10)
                        if state.get('state') == 'connected':
                            break
                    else:
                        raise AssertionError('Web SSH did not connect')
                    await websocket.send_json({'type': 'input', 'data': 'whoami\n'})
                    output = await websocket.receive(timeout=10)
                    check(output.type == aiohttp.WSMsgType.BINARY and b'observer' in output.data,
                          'Web SSH did not stream the target output')
                    await websocket.send_json({'type': 'resize', 'cols': 100, 'rows': 30})
                    await websocket.send_json({'type': 'input', 'data': 'exit\n'})
                    for _ in range(10):
                        message = await websocket.receive(timeout=10)
                        if message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                            break
            progress('PASS: browser session+CSRF, WebSocket SSH input/output and resize')

            # Keep a real target command open while Keycloak delivers its signed
            # backchannel logout over verified HTTPS to the application's route.
            hold_ticket = await issue('ssh')
            async with asyncssh.connect('127.0.0.1', port=native_port, username='10001', password=hold_ticket,
                    known_hosts=str(gateway_known), client_keys=[], agent_path=None, config=[]) as connection:
                process = await connection.create_process('hold')
                check((await asyncio.wait_for(process.stdout.readline(), 5)).strip() == 'ready', 'hold session did not start')
                response = await asyncio.to_thread(browser.get, ISSUER + '/protocol/openid-connect/logout',
                    params={'id_token_hint': token, 'post_logout_redirect_uri': DASHBOARD + '/me'},
                    allow_redirects=False, timeout=15)
                check(response.status_code in (200, 302, 303), 'Keycloak logout endpoint failed')
                for _ in range(50):
                    if logout_deliveries:
                        break
                    await asyncio.sleep(0.1)
                check(bool(logout_deliveries), 'Keycloak did not deliver backchannel logout')
                result = await asyncio.wait_for(process.wait(), timeout=5)
                check(result.exit_status != 0, 'revoked native session continued as successful')
            rejected = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/connections',
                headers={'Authorization': 'Bearer ' + token}, json={'host_id': '10001', 'protocol': 'ssh'}, timeout=10)
            check(rejected.status_code == 403, 'old Keycloak token authorized a new connection after logout')
            replay = await asyncio.to_thread(browser.post, DASHBOARD + '/auth/backchannel-logout',
                data={'logout_token': logout_deliveries[0]}, timeout=10)
            check(replay.status_code == 400, 'backchannel logout replay was accepted')
            progress('PASS: real Keycloak HTTPS backchannel logout ends active SSH and rejects token/replay')

            for _ in range(30):
                events = await asyncio.to_thread(index.search, subject=identity['keycloak_sub'], query='alice', limit=100)
                if any(event['event'] == 'ssh_end' for event in events['events']):
                    break
                await asyncio.sleep(0.1)
            check(any(event['event'] == 'ssh_start' for event in events['events']), 'PostgreSQL audit lacks SSH start')
            check(any(event['event'] == 'ssh_end' for event in events['events']), 'PostgreSQL audit lacks SSH end')
            check(await asyncio.to_thread(index.ingest, events['events'][0]) is False, 'audit replay was not idempotent')
            check(all(token not in json.dumps(event) for event in events['events']), 'bearer token leaked into audit')
            progress('PASS: shared PostgreSQL audit ingestion/search, event idempotency, token exclusion')
            progress('ALL GATEWAY INTEGRATION CHECKS PASSED')
        finally:
            await asyncio.to_thread(server.shutdown)
            server.server_close()
            await gateway_runner.cleanup()
            native.close()
            await native.wait_closed()
            target.close()
            await target.wait_closed()


if __name__ == '__main__':
    asyncio.run(main())
