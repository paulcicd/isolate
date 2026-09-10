#!/usr/bin/env python3
"""Authenticated Flask route smoke checks for the Docker demo dashboard."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "shared"))

from isolate_web import create_app


def main():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    with client.session_transaction() as session:
        session["identity"] = {"username": "demo.alice", "groups": ["Demo-DevOps"]}
        session["csrf_token"] = "dashboard-smoke"

    checks = [
        ("/", "Operations Overview"),
        ("/jobs", "Jobs"),
        ("/alerts", "Alert Center"),
        ("/policy/matrix", "Access Matrix"),
        ("/history", "History"),
        ("/inventory", "Inventory"),
        ("/grants", "Grants"),
    ]
    for path, marker in checks:
        response = client.get(path)
        text = response.get_data(as_text=True)
        if response.status_code != 200 or marker not in text:
            raise SystemExit("[failed] {} returned {} or missed {!r}".format(path, response.status_code, marker))
        if 'class="theme-switch"' not in text or "About this page" not in text:
            raise SystemExit("[failed] {} missed dashboard theme or page help controls".format(path))
        print("[ok] dashboard {}".format(path))


if __name__ == "__main__":
    main()
