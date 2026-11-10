"""Headless browser checks against the real Flask/API/WebSocket/SSH workspace.

Identity uses a synthetic locally signed JWT; real IdP login is covered by the
separate HTTPS Keycloak integration. Nothing contacts a deployed environment.
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
sys.path[:0] = [str(ROOT / "shared"), str(ROOT / "tests")]

import asyncssh
from aiohttp import web
from werkzeug.serving import make_server, WSGIRequestHandler
from isolate_gateway import create_web_app
from isolate_runtime import Runtime
from isolate_state import SQLState, StateClient
from isolate_web import create_app
import test_runtime_api_index as fixtures


class Quiet(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


def browser_checks(base, cookie, output, commands, connection_ids):
    from playwright.sync_api import sync_playwright, expect
    errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel="msedge" if os.name == "nt" else None)
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, device_scale_factor=1)
        context.add_cookies([{"name": "session", "value": cookie, "url": base, "httpOnly": True, "sameSite": "Lax"}])
        page = context.new_page()
        page.on("pageerror", lambda error: (errors.append(str(error)), print("UI script error: " + str(error), flush=True)))
        page.on("console", lambda message: print("UI console: " + message.text, flush=True) if message.type in ("error", "warning") else None)
        page.on("dialog", lambda dialog: dialog.accept())
        def connection_response(response):
            if response.url.endswith("/api/v1/connections"):
                if response.status == 201:
                    connection_ids.append(response.json()["connection_id"])
                else:
                    print("Connection API failed: " + str(response.status) + " " + response.text(), flush=True)
            elif '/replay/' in response.url and response.url.endswith('.json'):
                data = response.json() if response.status == 200 else {}
                print("Replay response: status={}, error={}, chunks={}".format(response.status, data.get('error'), len(data.get('chunks', []))), flush=True)
        page.on("response", connection_response)
        page.goto(base + "/workspace?lang=ru")
        expect(page.locator(".workspace-resource")).to_have_count(9)
        page.keyboard.press("Control+k")
        expect(page.locator("#workspace-query")).to_be_focused()
        page.locator("#workspace-query").fill("payments")
        expect(page.locator(".workspace-resource")).to_have_count(3)
        page.locator("#workspace-query").fill("")
        expect(page.locator(".workspace-resource")).to_have_count(9)
        page.locator("[data-resource-favorite]").first.click()
        page.locator('[data-workspace-view="favorites"]').click()
        expect(page.locator(".workspace-resource")).to_have_count(1)
        page.locator('[data-workspace-view="all"]').click()
        expect(page.locator(".workspace-resource")).to_have_count(9)
        page.screenshot(path=str(output / "catalog-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        page.screenshot(path=str(output / "catalog-mobile.png"), full_page=True)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "mobile catalogue overflows"
        page.set_viewport_size({"width": 1440, "height": 1000})
        page.goto(base + "/workspace/admin?lang=ru")
        expect(page.locator(".workspace-admin-card").first).to_be_visible()
        page.screenshot(path=str(output / "administration.png"), full_page=True)
        page.goto(base + "/me/terminal/1?lang=ru")
        try:
            expect(page.locator('.tw-pane[data-state="connected"]')).to_have_count(1, timeout=10000)
        except Exception:
            print("Terminal states: " + str(page.locator('.tw-pane-status').all_text_contents()), flush=True)
            page.screenshot(path=str(output / "terminal-error.png"), full_page=True)
            raise
        terminal = page.locator(".xterm-helper-textarea").first
        terminal.press("w")
        terminal.type("hoami")
        terminal.press("Enter")
        page.wait_for_function("document.querySelector('.tw-pane[data-state=connected]') !== null")
        page.locator('[data-action="search"]').click()
        page.locator("#tw-search-input").fill("support")
        expect(page.locator("#tw-search-count")).not_to_have_text("Нет совпадений")
        page.locator('[data-action="hide-search"]').click()
        page.locator('[data-action="split-columns"]').click()
        page.locator(".tw-resource-choice").first.click()
        expect(page.locator('.tw-pane[data-state="connected"]')).to_have_count(2)
        before = len(commands)
        page.locator(".xterm-helper-textarea").first.evaluate(r"""element => {
          const data = new DataTransfer(); data.setData('text/plain', 'first-command\nsecond-command\n');
          element.dispatchEvent(new ClipboardEvent('paste', {clipboardData:data, bubbles:true, cancelable:true}));
        }""")
        expect(page.locator("#tw-paste-dialog")).to_be_visible()
        assert len(commands) == before, "paste reached SSH before confirmation"
        page.screenshot(path=str(output / "paste-confirmation.png"), full_page=True)
        page.locator('#tw-paste-dialog button[value="confirm"]').click()
        page.locator('[data-action="settings"]').click()
        page.locator('#tw-settings-form [name="font_size"]').fill("18")
        page.locator('#tw-settings-form button[type="submit"]').click()
        expect(page.locator("#tw-notice")).to_have_text("Настройки сохранены.")
        page.screenshot(path=str(output / "terminal-split.png"), full_page=True)
        page.keyboard.press("Control+Shift+t")
        expect(page.locator("#tw-resource-dialog")).to_be_visible()
        page.locator(".tw-resource-choice").first.click()
        expect(page.locator("#tw-tabs .tw-tab")).to_have_count(2)
        page.screenshot(path=str(output / "terminal-tabs.png"), full_page=True)
        page.goto(base + "/workspace?lang=ru")
        page.locator('[data-workspace-view="recent"]').click()
        expect(page.locator(".workspace-resource")).not_to_have_count(0)
        assert connection_ids, "no actual connection was created"
        page.goto(base + "/replay/" + connection_ids[0] + "?lang=ru")
        expect(page.locator("#tr-state")).to_have_text("Запись готова")
        page.locator("#tr-bookmark-label").fill("Проверка целевой учётки")
        page.locator('#tr-bookmark-form button[type="submit"]').click()
        expect(page.locator("#tr-bookmark-list")).to_contain_text("Проверка целевой учётки")
        page.reload()
        expect(page.locator("#tr-bookmark-list")).to_contain_text("Проверка целевой учётки")
        page.locator("#tr-play").click()
        page.locator("#tr-pause").click()
        page.screenshot(path=str(output / "replay-bookmarks.png"), full_page=True)
        page.goto(base + '/workspace/access/1?protocol=ssh&lang=ru')
        expect(page.locator('h1')).to_contain_text('Объяснение доступа')
        expect(page.locator('body')).to_contain_text('first')
        page.screenshot(path=str(output / 'access-explanation.png'), full_page=True)
        page.goto(base + '/policy/impact?grant_id=1')
        page.locator('[name="grant"]').fill(json.dumps({'allowed_actions': ['ssh', 'runbook']}))
        page.get_by_role('button', name='Preview impact').click()
        expect(page.get_by_role('heading', name='Preview result')).to_be_visible()
        page.screenshot(path=str(output / 'policy-impact.png'), full_page=True)
        page.goto(base + '/workspace/governance')
        review = page.locator('form').filter(has=page.locator('[name="operation"][value="create_review"]'))
        review.locator('[name="project"]').select_option('payments')
        review.locator('[name="reason"]').fill('Scheduled browser owner review')
        review.locator('[name="confirm"]').check()
        review.get_by_role('button', name='Start review').click()
        expect(page.get_by_role('heading', name='Owner reviews')).to_be_visible()
        decision = page.locator('form').filter(has=page.locator('[name="operation"][value="review"]')).first
        decision.locator('[name="reason"]').fill('Owner verified current rule without extending expiry')
        decision.locator('[name="confirm"]').check()
        decision.get_by_role('button', name='Record decision').click()
        expect(page.locator('body')).to_contain_text('completed')
        page.screenshot(path=str(output / 'access-lifecycle.png'), full_page=True)
        page.set_viewport_size({'width': 390, 'height': 844})
        page.screenshot(path=str(output / 'access-lifecycle-mobile.png'), full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'lifecycle page overflows mobile'
        page.set_viewport_size({'width': 1440, 'height': 1000})
        page.goto(base + '/operations/campaigns')
        page.locator('[name="runbook_id"]').select_option('uptime')
        page.locator('[name="host_ids"]').fill('1,2')
        page.get_by_role('button', name='Review plan').click()
        expect(page.get_by_role('heading', name='Review campaign')).to_be_visible()
        page.screenshot(path=str(output / 'canary-review.png'), full_page=True)
        page.locator('[name="confirm"]').check()
        page.get_by_role('button', name='Start canary').click()
        expect(page.get_by_role('heading', name='Campaign uptime')).to_be_visible()
        page.locator('[name="confirm"]').check()
        page.get_by_role('button', name='Stop campaign').click()
        expect(page.locator('body')).to_contain_text('cancelled')
        page.get_by_role('link', name='Investigate campaign').click()
        expect(page.locator('.investigation-event')).not_to_have_count(0)
        page.screenshot(path=str(output / 'investigation.png'), full_page=True)
        assert not errors, errors
        context.close()
        browser.close()
    assert "whoami" in commands and "first-command" in commands and "second-command" in commands, commands
    print("PASS: catalogue filters/favorites/recent, responsive layout, real Web SSH, tabs/split/search/settings, paste guard, persisted replay bookmarks")
    print('PASS: browser access explanation, policy impact, owner review, canary confirmation/cancellation and correlated investigation')


async def main(output):
    output.mkdir(parents=True, exist_ok=True)
    fixture = fixtures.RuntimeTest()
    fixture.setUp()
    config = fixture.config
    fixture.claims['scope'] = 'isolate.runbook isolate.execute'
    fixture.token = fixture.sign(fixture.claims)
    work = Path(fixture.directory.name)
    options = {"backend": "sqlite", "sqlite_path": str(work / "state.db")}
    SQLState(options).initialize()
    store = StateClient(fixture.redis, options)
    config["state"] = options
    config["dashboard"].update(admin_groups=["Support"], locale="ru", refresh_seconds=0)
    from isolate_audit_index import AuditIndex
    config['audit_index'].update(enabled=True, driver='sqlite', path=str(work / 'audit.sqlite'))
    AuditIndex(config['audit_index']).initialize()
    config['logging']['sinks'] = [dict(config['audit_index'], type='sql')]
    campaign_key = work / 'campaign-key'
    campaign_key.write_bytes(b'isolated-ui-campaign-key-with-at-least-32-bytes')
    campaign_key.chmod(0o600)
    config['identity_security']['delegation']['enabled'] = True
    config['command_execution'].update(enabled=True, allowed_groups=['Support'], signing_key_file=str(campaign_key), jobs_path=str(work / 'jobs'))
    config['runbooks']['enabled'] = True
    config['runbooks']['read_only']['allowed_groups'] = ['Support']
    config['campaigns']['enabled'] = True
    host_key, client_key = asyncssh.generate_private_key("ssh-ed25519"), asyncssh.generate_private_key("ssh-ed25519")
    client_path = work / "client-key"
    client_key.write_private_key(str(client_path))
    client_path.chmod(0o600)
    commands, connection_ids = [], []
    class Target(asyncssh.SSHServer):
        def begin_auth(self, username): return True
        def public_key_auth_supported(self): return True
        def validate_public_key(self, username, key): return username == "support" and key == client_key.convert_to_public()
    async def process(remote):
        remote.stdout.write("Isolate test target ready\r\n")
        pending = ""
        while True:
            try:
                data = await remote.stdin.read(4096)
            except asyncssh.TerminalSizeChanged:
                continue
            if not data:
                break
            # Simulate a real PTY's ICRNL processing for xterm's Enter key.
            pending += data.replace("\r\n", "\n").replace("\r", "\n")
            while "\n" in pending:
                line, pending = pending.split("\n", 1)
                command = line.strip()
                commands.append(command)
                remote.stdout.write(("support" if command == "whoami" else "completed: " + command) + "\r\n")
        remote.exit(0)
    target = await asyncssh.create_server(Target, "127.0.0.1", 0, server_host_keys=[host_key],
        process_factory=process, encoding="utf-8", config=[], line_editor=False)
    known = work / "known-hosts"
    known.write_bytes(("[127.0.0.1]:{} ".format(target.get_port())).encode() + host_key.export_public_key())
    config["gateway"].update(known_hosts=str(known), recheck_interval=.2)
    config["credentials"] = {"default": "ui", "known_hosts": str(known), "targets": {},
        "providers": {"ui": {"type": "file", "private_key_file": str(client_path)}}}
    for i, project, name in ((1, "payments", "payments-api"), (2, "payments", "payments-database"),
                              (3, "platform", "build-dashboard"), (4, "platform", "metrics-cluster"), (5, "analytics", "mysql-analytics")):
        store.set("server_" + str(i), json.dumps({"server_id": str(i), "project_name": project, "server_name": name,
            "server_ip": "127.0.0.1", "server_port": target.get_port(), "resource_owner": "Platform Engineering",
            "environment": "Staging", "tags": {"team": project, "region": "eu-west"}}))
    store.set("grant_1", json.dumps({"subject": "group", "name": "Support", "project": "*", "remote_user": "support", "sudo_mode": "none", "allowed_actions": ["ssh", "http", "kubernetes", "postgresql", "mysql", "runbook"]}))
    store.set('offset_grant_id', 1)
    service_token = work / "kubernetes-token"
    service_token.write_text("synthetic-unused-fixture-token")
    service_token.chmod(0o600)
    config["protocols"].update(enabled=True, targets={
        "2": {"protocol": "postgresql", "project": "payments", "upstream": "postgresql://database.example", "database_native_auth": True},
        "3": {"protocol": "http", "project": "platform", "upstream": "https://dashboard.example"},
        "4": {"protocol": "kubernetes", "project": "platform", "upstream": "https://cluster.example", "impersonation": True,
            "bearer_token_file": str(service_token), "allowed_paths": ["/api/*"]},
        "5": {"protocol": "mysql", "project": "analytics", "upstream": "mysql://mysql.example", "database_native_auth": True}})
    fixture.redis = store
    patcher = __import__('unittest.mock', fromlist=['patch']).patch("isolate_web.redis_client", return_value=store)
    patcher.start()
    app = create_app(config)
    app.config.update(TESTING=True, SECRET_KEY="ui-test-synthetic-signing-secret")
    http = make_server("127.0.0.1", 0, app, threaded=True, request_handler=Quiet)
    base = "http://127.0.0.1:" + str(http.server_port)
    config["dashboard"]["public_url"] = base
    config["gateway"]["allowed_origins"] = [base]
    runtime = Runtime(config, store)
    gateway = web.AppRunner(create_web_app(runtime), access_log=None)
    await gateway.setup()
    site = web.TCPSite(gateway, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    config["gateway"]["public_web_url"] = "ws://127.0.0.1:" + str(port)
    identity = runtime.authenticate(fixture.token)
    store.set("isolate_browser_ui-test", json.dumps({"sub": identity["keycloak_sub"], "token": fixture.token}))
    cookie = app.session_interface.get_signing_serializer(app).dumps({"identity": identity, "runtime_session": "ui-test", "csrf_token": "ui-test-csrf"})
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        await asyncio.to_thread(browser_checks, base, cookie, output, commands, connection_ids)
    finally:
        await asyncio.to_thread(http.shutdown)
        http.server_close()
        await gateway.cleanup()
        target.close()
        await target.wait_closed()
        patcher.stop()
        fixture.doCleanups()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(tempfile.gettempdir()) / "isolate-ui-verification")
    args = parser.parse_args()
    asyncio.run(main(args.output))
