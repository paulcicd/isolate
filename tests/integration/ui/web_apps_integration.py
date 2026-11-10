"""Real browser cross-site POST launch, host cookies and application WebSocket.

Synthetic local DNS/TLS and signed JWT only; no deployed service is contacted.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / 'shared'), str(ROOT / 'tests')]
from aiohttp import web
from werkzeug.serving import make_server, WSGIRequestHandler
from test_web_apps import BrowserApplicationsTest


class Quiet(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


def browser_checks(control, origin, cookie, output):
    from playwright.sync_api import sync_playwright, expect
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel='msedge' if os.name == 'nt' else None,
            args=['--no-proxy-server', '--host-resolver-rules=MAP access.control.test 127.0.0.1, MAP app1.isolate-apps.test 127.0.0.1'])
        # Only these short-lived, synthetic fixture certificates are untrusted.
        context = browser.new_context(ignore_https_errors=True)
        context.add_cookies([{'name': 'session', 'value': cookie, 'url': control,
            'secure': True, 'httpOnly': True, 'sameSite': 'Lax'}])
        page = context.new_page()
        def launch_response(response):
            if response.url.endswith('/_isolate/launch') and response.status != 303:
                print('Browser app launch failed: status={}, origin={}, reason={}'.format(
                    response.status, response.request.headers.get('origin'), response.text()), flush=True)
        page.on('response', launch_response)
        page.goto(control + '/workspace/resource/1/http')
        page.get_by_role('button', name='Open application').click()
        page.wait_for_url(origin + '/')
        expect(page.locator('body')).to_contain_text('"ok": true')
        assert 'code=' not in page.url
        cookies = context.cookies(origin)
        proxy_cookie = next(value for value in cookies if value['name'] == '__Host-IsolateApp')
        assert proxy_cookie['secure'] and proxy_cookie['httpOnly'] and proxy_cookie['sameSite'] == 'Lax'
        assert proxy_cookie['domain'] == 'app1.isolate-apps.test'
        assert not any(value['name'] == 'session' for value in cookies)
        page.goto(origin + '/login')
        page.wait_for_url(origin + '/dashboard?next=%2Fapi%2Fv1')
        expect(page.locator('body')).to_contain_text('app_login=current-user')
        result = page.evaluate("""() => new Promise((resolve, reject) => {
          window.applicationSocket = new WebSocket(location.origin.replace('https:', 'wss:') + '/ws', 'chat');
          applicationSocket.onopen = () => applicationSocket.send('browser');
          applicationSocket.onmessage = event => resolve(event.data);
          applicationSocket.onerror = () => reject(new Error('application socket failed'));
        })""")
        assert result == 'echo:browser'
        page.screenshot(path=str(output / 'browser-application.png'), full_page=True)
        # Explicit same-origin app logout closes its existing WebSocket too.
        page.evaluate("""() => fetch('/_isolate/logout', {method:'POST'}).catch(() => {})""")
        page.wait_for_function('applicationSocket.readyState === WebSocket.CLOSED')
        page.goto(origin + '/')
        expect(page.locator('body')).to_contain_text('Application request denied')
        context.close()
        browser.close()
    print('PASS: real browser control-to-app POST, isolated Secure cookies, redirects, WebSocket and logout', flush=True)


async def main(output):
    output.mkdir(parents=True, exist_ok=True)
    fixture = BrowserApplicationsTest()
    await fixture.asyncSetUp()
    http = thread = None
    try:
        tls_site = web.TCPSite(fixture.gateway_runner, '127.0.0.1', 0, ssl_context=fixture.server_tls)
        await tls_site.start()
        port = tls_site._server.sockets[0].getsockname()[1]
        origin = 'https://app1.isolate-apps.test:' + str(port)
        fixture.config['protocols']['targets']['1']['public_origin'] = origin
        fixture.config['gateway']['public_web_url'] = 'https://gateway.control.test:' + str(port)
        fixture.fixture.redis = fixture.store
        app = fixture.fixture.app()
        http = make_server('127.0.0.1', 0, app, threaded=True, request_handler=Quiet,
            ssl_context=(fixture.ca, str(Path(fixture.fixture.directory.name) / 'tls.key')))
        control = 'https://access.control.test:' + str(http.server_port)
        fixture.config['dashboard']['public_url'] = control
        identity = fixture.runtime.authenticate(fixture.fixture.token)
        handle = 'browser-application-owner-12345'
        fixture.store.set('isolate_browser_' + handle, json.dumps({'sub': identity['keycloak_sub'], 'token': fixture.fixture.token}))
        cookie = app.session_interface.get_signing_serializer(app).dumps({'identity': identity,
            'runtime_session': handle, 'csrf_token': 'synthetic-browser-app-csrf'})
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        await asyncio.to_thread(browser_checks, control, origin, cookie, output)
        assert not fixture.sessions.active
    finally:
        if http:
            await asyncio.to_thread(http.shutdown)
            http.server_close()
        await fixture.asyncTearDown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path(tempfile.gettempdir()) / 'isolate-app-verification')
    asyncio.run(main(parser.parse_args().output))
