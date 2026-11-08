# Workspace browser integration

This test starts a loopback Flask application, SQLite authority, fake disposable
Redis, a real WebSocket gateway and a real SSH target. JWT signature verification
uses a synthetic locally signed identity. Real HTTPS Keycloak authorization-code
login and ordinary OpenSSH browser sign-in are tested separately by the gateway
Compose suite. No production service or account is contacted.

```bash
python -m pip install -r tests/integration/ui/requirements.txt
python -m playwright install --with-deps chromium
python tests/integration/ui/ui_integration.py --output /tmp/isolate-ui-verification
```

On Windows the test uses installed Microsoft Edge in headless mode, so installing
the Chromium browser is optional. Its application server and target always bind
loopback with ephemeral ports and are stopped afterwards. All data is temporary.

The browser checks real API filtering, favorites and recent resources, desktop
and 390px mobile layout, scoped administration entry, actual SSH input/output,
tabs, split panes, search, saved font settings, paste review before bytes reach
SSH, and persisted owner-scoped replay bookmarks. It records screenshots and
fails on uncaught page errors. The local HTTP/WS transport is a test-only
loopback fixture; deployed browser sessions must use HTTPS/WSS.
