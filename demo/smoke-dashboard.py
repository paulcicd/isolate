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
        ("/packages", "Access Packages"),
        ("/docs", "Isolate Documentation"),
    ]
    for path, marker in checks:
        response = client.get(path)
        text = response.get_data(as_text=True)
        if response.status_code != 200 or marker not in text:
            raise SystemExit("[failed] {} returned {} or missed {!r}".format(path, response.status_code, marker))
        if 'class="theme-switch"' not in text or "About this page" not in text:
            raise SystemExit("[failed] {} missed dashboard theme or page help controls".format(path))
        print("[ok] dashboard {}".format(path))

    russian = client.get("/docs?lang=ru").get_data(as_text=True)
    if '<html lang="ru">' not in russian or "Документация Isolate" not in russian or "2.1.0-demo" not in russian:
        raise SystemExit("[failed] localized documentation or build metadata is missing")
    print("[ok] dashboard Russian documentation and build metadata")


if __name__ == "__main__":
    main()
