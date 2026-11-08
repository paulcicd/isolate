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
from isolate_state import SQLState
from isolate_redis import create_redis_client
from isolate_jobs import execute_job


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
        config['gateway']['browser_auth']['enabled'] = True
        config['gateway']['ssh_features'].update(multiple_channels=True, sftp=True, scp=True)
        config['identity_security']['backchannel_logout']['enabled'] = True
        config['connection_authorization'].update(max_session_seconds=120)
        config['logging'].update(base_path=str(work / 'logs'), fail_closed=True, sync=True)
        dsn = work / 'audit-dsn'
        dsn.write_text('postgresql://isolate_test:isolated-integration-database-password@postgres/isolate_test')
        dsn.chmod(0o600)
        config['audit_index'].update(enabled=True, driver='postgresql', dsn_file=str(dsn))
        config['state'].update(backend='postgresql', dsn_file=str(dsn), require_tls=False)  # private test network only
        await asyncio.to_thread(SQLState(config['state']).initialize)
        store = create_redis_client(config)
        membership_secret = work / 'membership-client-secret'
        membership_secret.write_text('isolated-membership-reader-secret')
        membership_secret.chmod(0o600)
        config['identity_security']['membership'].update(enabled=True, client_id='isolate-membership-reader',
            client_secret_file=str(membership_secret), timeout_seconds=10)
        job_key = work / 'job-key'
        job_key.write_bytes(b'isolated-job-key-with-at-least-32-bytes')
        job_key.chmod(0o600)
        config['identity_security']['delegation'].update(enabled=True, max_seconds=120, recheck_interval=0.2)
        config['command_execution'].update(enabled=True, allowed_groups=['Integration-Operators'],
            allowed_command_patterns=['whoami', 'hold'], default_timeout=30,
            jobs_path=str(work / 'jobs'), signing_key_file=str(job_key))
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
            import shlex
            command = process.command
            if command:
                words = shlex.split(command)
                if len(words) == 3 and words[:2] == ['/bin/sh', '-lc']:
                    command = words[2]
            if command == 'whoami':
                process.stdout.write('observer\n')
            elif command == 'hold':
                process.stdout.write('ready\n')
                await process.wait_closed()
            elif process.command is None:
                while True:
                    try:
                        line = await process.stdin.readline()
                    except asyncssh.TerminalSizeChanged:
                        continue
                    if not line:
                        break
                    if line.strip() == 'whoami':
                        process.stdout.write('observer\n')
                    elif line.strip() == 'exit':
                        break
            else:
                process.stderr.write('unsupported integration command\n')
                process.exit(2)
                return
            process.exit(0)

        target_files = work / 'target-files'
        target_files.mkdir()
        target = await asyncssh.create_server(TargetServer, '127.0.0.1', 0, server_host_keys=[target_key],
            process_factory=target_process, sftp_factory=lambda channel: asyncssh.SFTPServer(channel, chroot=str(target_files)),
            encoding='utf-8', config=[], line_editor=False)
        target_port = target.get_port()
        known_hosts = work / 'known-hosts'
        known_hosts.write_text('[127.0.0.1]:{} {}'.format(target_port, target_key.export_public_key().decode()))
        ssh_config = work / 'worker-ssh-config'
        ssh_config.write_text('Host *\n  IdentityFile {}\n  IdentitiesOnly yes\n  UserKnownHostsFile {}\n'.format(keyfile, known_hosts))
        config['ssh']['config_path'] = str(ssh_config)
        config['gateway']['known_hosts'] = str(known_hosts)
        config['credentials'] = {'default': 'integration', 'known_hosts': str(known_hosts), 'targets': {},
            'providers': {'integration': {'type': 'file', 'private_key_file': str(keyfile)}}}
        host = {'server_id': '10001', 'server_name': 'integration-target', 'server_ip': '127.0.0.1',
                'server_port': target_port, 'server_user': 'observer', 'project_name': 'integration'}
        store.set('server_10001', json.dumps(host))
        store.set('grant_1', json.dumps({'subject': 'group', 'name': 'Integration-Operators',
            'project': 'integration', 'host': '10001', 'remote_user': 'observer', 'sudo_mode': 'none',
            'allowed_actions': ['ssh', 'command', 'sftp']}))
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

            # An unmodified OpenSSH client receives a browser confirmation URL.
            # Askpass waits only for this test browser to approve the same code.
            allow_askpass = work / 'askpass-approved'
            askpass_prompt = work / 'askpass-prompt'
            askpass = work / 'askpass'
            askpass.write_text('#!/usr/bin/python3\nimport os,time,sys\nfrom pathlib import Path\nPath(os.environ["ISOLATE_TEST_PROMPT"]).write_text(" ".join(sys.argv[1:]))\np=Path(os.environ["ISOLATE_TEST_APPROVED"])\nfor _ in range(300):\n if p.exists(): break\n time.sleep(.1)\nprint("")\n')
            askpass.chmod(0o700)
            openssh = await asyncio.create_subprocess_exec('ssh', '-F', '/dev/null', '-T',
                '-o', 'PreferredAuthentications=keyboard-interactive', '-o', 'PasswordAuthentication=no',
                '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(gateway_known),
                '-p', str(native_port), '10001@127.0.0.1', 'whoami',
                env=dict(os.environ, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY='isolated-test',
                    ISOLATE_TEST_APPROVED=str(allow_askpass), ISOLATE_TEST_PROMPT=str(askpass_prompt)), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                for _ in range(200):
                    line = askpass_prompt.read_bytes() if askpass_prompt.exists() else b''
                    match = re.search(rb'https://runner:9443/ssh/authorize\?code=([A-Z2-7-]+)', line)
                    if match:
                        break
                    await asyncio.sleep(.1)
                else:
                    raise AssertionError('OpenSSH did not receive browser confirmation URL')
                confirmation = await asyncio.to_thread(browser.get, DASHBOARD + '/ssh/authorize?code=' + match[1].decode(), timeout=10)
                csrf = re.search(r'name="csrf_token" value="([^"]+)"', confirmation.text)
                check(confirmation.status_code == 200 and csrf, 'browser SSH confirmation form was not authorized')
                approved = await asyncio.to_thread(browser.post, DASHBOARD + '/ssh/authorize',
                    data={'code': match[1].decode(), 'csrf_token': html.unescape(csrf[1]), 'confirm': 'yes'}, timeout=10)
                check(approved.status_code == 200, 'browser SSH confirmation failed')
                allow_askpass.touch()
                stdout, _ = await asyncio.wait_for(openssh.communicate(), 15)
                check(openssh.returncode == 0 and stdout.strip() == b'observer', 'unmodified OpenSSH browser sign-in failed')
            finally:
                if openssh.returncode is None:
                    openssh.kill()
                    await openssh.wait()
            progress('PASS: unmodified OpenSSH keyboard-interactive browser sign-in through real Keycloak session')

            multiplex_ticket = await issue('ssh')
            async with asyncssh.connect('127.0.0.1', port=native_port, username='10001', password=multiplex_ticket,
                    known_hosts=str(gateway_known), client_keys=[], agent_path=None, config=[]) as connection:
                results = await asyncio.gather(connection.run('whoami', check=True), connection.run('whoami', check=True))
                check(all(result.stdout.strip() == 'observer' for result in results), 'multiplexed commands failed')
                async with connection.start_sftp_client() as sftp:
                    payload = b'isolated-binary-file\0\xff' * 60000
                    async with sftp.open('/binary.bin', 'wb') as file:
                        await file.write(payload)
                    async with sftp.open('/binary.bin', 'rb') as file:
                        check(await file.read() == payload, 'policy-bound SFTP transfer changed bytes')
                check((target_files / 'binary.bin').read_bytes() == payload, 'SFTP wrote outside target fixture')
            progress('PASS: SQL-backed channel authorization, concurrent SSH commands and audited binary SFTP')

            terminal = await asyncio.to_thread(browser.get, DASHBOARD + '/me/terminal/10001', timeout=10)
            check(terminal.status_code == 200, 'authenticated browser terminal page failed')
            match = re.search(r'<script id="terminal-workspace-config" type="application/json">(.*?)</script>', terminal.text)
            check(match is not None, 'terminal did not expose its protected workspace configuration')
            terminal_csrf = json.loads(match[1])['csrf']
            denied = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/connections',
                json={'host_id': '10001', 'protocol': 'webssh'}, timeout=10)
            check(denied.status_code == 403, 'browser ticket mutation accepted missing CSRF')
            issued = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/connections',
                headers={'X-CSRF-Token': terminal_csrf},
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
                    await websocket.send_json({'type': 'input', 'data': 'whoami\n'})
                    after_resize = await websocket.receive(timeout=10)
                    check(after_resize.type == aiohttp.WSMsgType.BINARY and b'observer' in after_resize.data,
                          'Web SSH did not remain usable after PTY resize')
                    await websocket.send_json({'type': 'input', 'data': 'exit\n'})
                    for _ in range(10):
                        message = await websocket.receive(timeout=10)
                        if message.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                            break
            progress('PASS: browser session+CSRF, WebSocket SSH input/output and resize')

            async def submit(command, key):
                body = {'type': 'command', 'host_id': '10001', 'command': command, 'confirm': True}
                response = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/jobs',
                    headers={'Authorization': 'Bearer ' + token, 'Idempotency-Key': key}, json=body, timeout=15)
                check(response.status_code in (200, 201), 'delegated API job was not authorized: HTTP {} {}'.format(response.status_code, response.text))
                return response.json()['job']

            diagnostic = await submit('whoami', 'integration-command-once')
            duplicate = await submit('whoami', 'integration-command-once')
            check(diagnostic['id'] == duplicate['id'], 'idempotent API retry created another job')
            result = await asyncio.to_thread(execute_job, store, config, diagnostic)
            check(result['status'] == 'completed', 'actual delegated OpenSSH command failed')
            progress('PASS: SQL-authoritative idempotent job API and encrypted delegated OpenSSH execution')

            control = browser_session()
            admin_token = await asyncio.to_thread(control.post, ISSUER + '/protocol/openid-connect/token',
                data={'grant_type': 'client_credentials', 'client_id': 'isolate-fixture-admin',
                      'client_secret': 'isolated-fixture-admin-secret'}, timeout=10)
            check(admin_token.status_code == 200, 'fixture administration token failed')
            admin_headers = {'Authorization': 'Bearer ' + admin_token.json()['access_token']}
            admin_base = ISSUER.replace('/realms/', '/admin/realms/')
            groups = await asyncio.to_thread(control.get, admin_base + '/users/' + identity['keycloak_sub'] + '/groups', headers=admin_headers, timeout=10)
            check(groups.status_code == 200 and len(groups.json()) == 1, 'fixture group lookup failed')
            membership_url = admin_base + '/users/' + identity['keycloak_sub'] + '/groups/' + groups.json()[0]['id']
            running = await submit('hold', 'integration-live-membership')
            queued = await submit('whoami', 'integration-queued-membership')
            worker = asyncio.create_task(asyncio.to_thread(execute_job, store, config, running))
            live_ticket = await issue('ssh')
            live_channels = await asyncssh.connect('127.0.0.1', port=native_port, username='10001', password=live_ticket,
                known_hosts=str(gateway_known), client_keys=[], agent_path=None, config=[])
            live_process = await live_channels.create_process('hold')
            check((await asyncio.wait_for(live_process.stdout.readline(), 5)).strip() == 'ready', 'multiplexed hold did not start')
            live_sftp = await live_channels.start_sftp_client()
            for _ in range(100):
                output_path = work / 'jobs' / ('job-' + running['id'] + '.log')
                if output_path.exists() and b'ready' in output_path.read_bytes():
                    break
                await asyncio.sleep(0.05)
            else:
                raise AssertionError('delegated background SSH did not start')
            try:
                removal = await asyncio.to_thread(control.delete, membership_url, headers=admin_headers, timeout=10)
                check(removal.status_code == 204, 'fixture group removal failed')
                me = await asyncio.to_thread(browser.get, DASHBOARD + '/api/v1/me', headers={'Authorization': 'Bearer ' + token}, timeout=10)
                check(me.status_code == 200 and 'Integration-Operators' not in me.json()['groups'], 'stale token membership was used')
                await asyncio.wait_for(live_channels.wait_closed(), 10)
                try:
                    await live_sftp.stat('/binary.bin')
                except (asyncssh.Error, OSError):
                    pass
                else:
                    raise AssertionError('SFTP channel survived live Keycloak group removal')
                stopped = await asyncio.wait_for(worker, 15)
                check(stopped['status'] != 'completed', 'background job continued after group removal')
                rejected_job = await asyncio.to_thread(execute_job, store, config, queued)
                check(rejected_job['status'] == 'failed', 'queued job used stale group claims')
                denied = await asyncio.to_thread(browser.post, DASHBOARD + '/api/v1/connections', headers={'Authorization': 'Bearer ' + token},
                    json={'host_id': '10001', 'protocol': 'ssh'}, timeout=10)
                check(denied.status_code == 403, 'old token opened SSH after membership removal')
            finally:
                live_sftp.exit()
                live_channels.close()
                await live_channels.wait_closed()
                restored = await asyncio.to_thread(control.put, membership_url, headers=admin_headers, timeout=10)
                check(restored.status_code == 204, 'fixture group restoration failed')
            progress('PASS: live Keycloak group removal overrides stale JWT claims and stops queued/running jobs')

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
