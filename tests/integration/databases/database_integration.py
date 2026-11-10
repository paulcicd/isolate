"""Real native clients through the production helper, WSS and protocol proxy."""
import asyncio
import contextlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import tempfile
import time
import uuid

ROOT = Path('/opt/auth')
sys.path.insert(0, str(ROOT / 'shared'))
import fakeredis
from aiohttp import web
from isolate_cluster import Lease
from isolate_gateway import create_web_app
from isolate_sessions import mark_session_start, mark_session_end


class Runtime:
    def __init__(self):
        self.redis = fakeredis.FakeRedis()
        self.events, self.tickets, self.revoked = [], {}, False
        self.finished = []
        self.config = {'cluster': {}, 'gateway': {'recheck_interval': .1}, 'protocols': {'enabled': True, 'targets': {}}}
        self.hosts = {}
        for identifier, protocol, port in [('1', 'postgresql', 5432), ('2', 'mysql', 3306)]:
            self.hosts[identifier] = {'server_id': identifier, 'server_ip': socket.gethostbyname('postgres' if identifier == '1' else 'mysql'), 'project_name': 'stage'}
            self.config['protocols']['targets'][identifier] = {'protocol': protocol, 'project': 'stage',
                'upstream': protocol + '://' + ('postgres' if identifier == '1' else 'mysql') + ':' + str(port),
                'ca_file': '/fixtures/ca.pem', 'database_proxy': {'enabled': True, 'databases': ['app'], 'default_database': 'app',
                    'frontend_cert_file': '/fixtures/frontend.pem', 'frontend_key_file': '/fixtures/frontend.key',
                    'credentials': {'type': 'file', 'username': 'db_reader', 'password_file': '/fixtures/' + ('postgres' if identifier == '1' else 'mysql') + '-password'}}}

    def authorize(self, identifier, protocol):
        if self.revoked or self.config['protocols']['targets'][identifier]['protocol'] != protocol:
            raise ValueError('denied')
        return {'identity': {'keycloak_sub': 'fixture-stable-subject', 'username': 'engineer', 'groups': ['Support']},
            'host': self.hosts[identifier], 'decision': {'remote_user': 'db_reader', 'sudo_mode': 'none'},
            'protocol': protocol, 'deadline': int(time.time()) + 600, 'connection_id': uuid.uuid4().hex,
            'authority_epoch': 'fixture-epoch', 'authorization_revision': 'fixture-policy', 'target_revision': 'fixture-route'}

    def consume_ticket(self, ticket, protocol, source_ip=None):
        identifier, intended = self.tickets.pop(ticket)
        return self.authorize(identifier, protocol)

    def prepare(self, context):
        context['_lease'] = Lease(self.redis, 'isolate_session_owner_' + context['connection_id']).acquire()

    def start(self, context):
        mark_session_start(self.redis, context['connection_id'], {'username': 'engineer', 'keycloak_sub': 'fixture-stable-subject'})

    def recheck(self, context):
        if self.revoked or time.time() >= context['deadline']:
            raise ValueError('revoked')
        context['_lease'].renew()

    def channel_event(self, context, event, **fields):
        self.events.append({'event': event, 'connection_id': context['connection_id'], **fields})

    def finish(self, context, exit_code=None):
        if context.get('_lease'):
            context['_lease'].release()
            mark_session_end(self.redis, context['connection_id'])
            self.finished.append((context['protocol'], dict(context.get('protocol_stats', {}))))


async def command(*argv, env=None):
    proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=None if env is None else dict(os.environ, **env))
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    if proc.returncode:
        raise RuntimeError('Native fixture command failed: ' + stderr.decode(errors='replace')[:300])
    return stdout.decode()


async def main():
    # Keep gateway-side failures visible in this synthetic integration fixture;
    # the production route deliberately returns only a generic denial.
    import isolate_protocols
    guarded = isolate_protocols._guarded
    async def checked_guard(*args):
        try:
            return await guarded(*args)
        except Exception:
            import traceback
            traceback.print_exc()
            raise
    isolate_protocols._guarded = checked_guard
    with open('/etc/hosts', 'a') as hosts:
        hosts.write('\n127.0.0.1 db.test\n')
    runtime = Runtime()
    application = create_web_app(runtime)

    async def ticket(request):
        if request.headers.get('Authorization') != 'Bearer fixture-bearer':
            raise web.HTTPForbidden()
        body = await request.json()
        value = secrets.token_urlsafe(32)
        runtime.authorize(body['host_id'], body['protocol'])
        runtime.tickets[value] = (body['host_id'], body['protocol'])
        return web.json_response({'ticket': value}, status=201)

    application.router.add_post('/api/v1/connections', ticket)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain('/fixtures/frontend.pem', '/fixtures/frontend.key')
    runner = web.AppRunner(application, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=tls)
    await site.start()
    gateway_port = site._server.sockets[0].getsockname()[1]
    processes = []
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'identity.json'
            cache.write_text(json.dumps({'schema_version': 3, 'id_token': 'fixture-bearer'}))
            cache.chmod(0o600)
            password_file = root / 'frontend-password'
            capability = secrets.token_urlsafe(32)
            password_file.write_text(capability)
            password_file.chmod(0o600)
            ports = {}
            for identifier, protocol in [('1', 'postgresql'), ('2', 'mysql')]:
                proc = await asyncio.create_subprocess_exec(sys.executable, str(ROOT / 'scripts/isolate-protocol-proxy.py'), 'database',
                    '--api-url', 'https://localhost:' + str(gateway_port), '--gateway-url', 'wss://localhost:' + str(gateway_port),
                    '--host-id', identifier, '--protocol', protocol, '--identity-file', str(cache), '--ca-file', '/fixtures/ca.pem',
                    '--database-proxy', '--frontend-password-file', str(password_file), stdout=asyncio.subprocess.PIPE)
                processes.append(proc)
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=15)
                if b'listening on 127.0.0.1:' not in line:
                    raise RuntimeError('Native helper did not become ready')
                ports[protocol] = int(line.decode().strip().rsplit(':', 1)[1])

            pg_dsn = 'host=db.test hostaddr=127.0.0.1 port={} dbname=app user=client-cannot-choose-identity sslmode=verify-full sslrootcert=/fixtures/ca.pem'.format(ports['postgresql'])
            output = await command('psql', pg_dsn, '-X', '-q', '-t', '-v', 'ON_ERROR_STOP=1', '-c',
                'select current_user; begin; create table if not exists probe (id integer, payload text); insert into probe values (1,\'row-secret\'); commit; select count(*) from probe;', env={'PGPASSWORD': capability})
            assert 'db_reader' in output
            print('PASS: actual psql, policy-selected upstream identity and transactions', flush=True)

            def postgres_extended():
                import psycopg
                with psycopg.connect(pg_dsn, password=capability, autocommit=True) as connection:
                    with connection.cursor() as cursor:
                        cursor.execute('select %s::text', ('private-bound-parameter',), prepare=True)
                        assert cursor.fetchone()[0] == 'private-bound-parameter'
                        with cursor.copy('COPY probe FROM STDIN') as copy:
                            copy.write_row((2, 'private-copy-payload'))
                        with cursor.copy('COPY probe TO STDOUT') as copy:
                            result = b''.join(bytes(chunk) for chunk in copy)
                            assert b'private-copy-payload' in result
                    try:
                        with connection.pipeline():
                            connection.execute('select 1', prepare=True)
                            connection.execute('select * from isolate_missing_pipeline_relation', prepare=True)
                            connection.execute('select 2', prepare=True)
                    except psycopg.errors.UndefinedTable:
                        pass
                    else:
                        raise AssertionError('synthetic pipeline error unexpectedly succeeded')
                    assert connection.execute('select 3').fetchone()[0] == 3
            await asyncio.to_thread(postgres_extended)
            assert any(event['event'] == 'database_result' and event.get('result') == 'not-executed' for event in runtime.events)
            print('PASS: real libpq prepared statements, bound parameters and bidirectional COPY', flush=True)
            print('PASS: native libpq pipeline failure, skipped-operation audit and recovery', flush=True)

            try:
                await command('psql', pg_dsn, '-X', '-v', 'ON_ERROR_STOP=1', '-c',
                    'select 1; select * from isolate_missing_relation;', env={'PGPASSWORD': capability})
            except RuntimeError:
                pass
            else:
                raise AssertionError('synthetic SQL error unexpectedly succeeded')
            assert any(event['event'] == 'database_result' and event.get('result') == 'failed'
                and event.get('sqlstate') == '42P01' and event.get('command_count') == 1 for event in runtime.events)
            print('PASS: later errors in a multi-statement packet remain visible in SQL audit', flush=True)

            # Some libpq builds hold the GIL in PQcancel. The real native client
            # must run separately from the gateway, including in this fixture.
            await command(sys.executable, __file__, '--cancel', pg_dsn, str(password_file))
            assert any(event['event'] == 'database_cancel' for event in runtime.events)
            print('PASS: native libpq cancellation through a fresh authorized helper channel', flush=True)

            output = await command('mysql', '--host=db.test', '--port=' + str(ports['mysql']), '--user=client-cannot-choose-identity',
                '--database=app', '--ssl-ca=/fixtures/ca.pem', '--ssl-verify-server-cert', '-N', '-e',
                "select current_user(); create table if not exists probe (id integer, payload text); begin; insert into probe values (1,'mysql-row-secret'); commit; select count(*) from probe;", env={'MYSQL_PWD': capability})
            assert 'db_reader@' in output
            print('PASS: actual mysql CLI, caching_sha2 upstream credential injection and transactions', flush=True)

            def mysql_prepared():
                import mysql.connector
                connection = mysql.connector.connect(host='db.test', port=ports['mysql'], user='client-cannot-choose-identity', password=capability,
                    database='app', ssl_ca='/fixtures/ca.pem', ssl_verify_cert=True, ssl_verify_identity=True, use_pure=True)
                try:
                    cursor = connection.cursor(prepared=True)
                    cursor.execute('select %s', ('mysql-private-bound-value',))
                    assert cursor.fetchone()[0] == 'mysql-private-bound-value'
                    cursor.close()
                finally:
                    connection.close()
            await asyncio.to_thread(mysql_prepared)
            print('PASS: real MySQL prepared/binary result protocol', flush=True)
            for protocol in ('postgresql', 'mysql'):
                assert any(kind == protocol and stats.get('received_bytes', 0) > 0 and stats.get('sent_bytes', 0) > 0
                    for kind, stats in runtime.finished)
            print('PASS: native database connection audit counts actual wire bytes in both directions', flush=True)
            audit = json.dumps(runtime.events)
            for secret in ('isolated-postgres-upstream-password', 'isolated-mysql-upstream-password', capability,
                    'private-bound-parameter', 'private-copy-payload', 'private-row-value', 'mysql-private-bound-value', 'row-secret', 'mysql-row-secret'):
                assert secret not in audit
            assert any(event['event'] == 'database_query' and event.get('prepared') for event in runtime.events)
            assert any(event['event'] == 'database_result' and event.get('result') == 'completed' for event in runtime.events)
            print('PASS: SQL lifecycle audit excludes passwords, capabilities, parameters, result rows and COPY data', flush=True)
    finally:
        for proc in processes:
            proc.terminate()
        await asyncio.gather(*(proc.wait() for proc in processes), return_exceptions=True)
        await runner.cleanup()
    print('ALL DATABASE PROTOCOL INTEGRATION CHECKS PASSED', flush=True)


def native_cancel(dsn, password_file):
    import concurrent.futures
    import psycopg
    with psycopg.connect(dsn, password=Path(password_file).read_text().strip(), autocommit=True) as connection:
        def sleeping():
            try:
                connection.execute('select pg_sleep(20)')
            except psycopg.errors.QueryCanceled:
                return True
            return False
        with concurrent.futures.ThreadPoolExecutor() as pool:
            query = pool.submit(sleeping)
            time.sleep(.5)
            connection.cancel()
            assert query.result(timeout=8), 'native query was not cancelled'
        assert connection.execute('select 42').fetchone()[0] == 42


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--cancel':
        native_cancel(sys.argv[2], sys.argv[3])
    else:
        asyncio.run(main())
