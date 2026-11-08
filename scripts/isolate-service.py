#!/usr/bin/env python3
"""One explicit configuration and entry point for managed Isolate services."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=("dashboard", "gateway", "jobs", "recordings"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", action="store_true", help="check configuration and control-store readiness without starting ingress")
    args = parser.parse_args(argv)
    if not Path(args.config).is_file():
        parser.error("explicit configuration file does not exist")
    # Child workers must inherit exactly this configuration, not shell overrides.
    os.environ["ISOLATE_CONFIG"] = str(Path(args.config).absolute())
    from isolate_config import load_config
    from isolate_health import validate_config, run_health_checks
    config = load_config(args.config, use_env=False)
    section = {"jobs": "command_execution"}.get(args.component, args.component)
    if not config.get(section, {}).get("enabled"):
        parser.error(args.component + " service is disabled")
    validation = validate_config(config, check_paths=True)
    if not validation["valid"]:
        print(json.dumps({"ok": False, "errors": validation["errors"]}), file=sys.stderr)
        return 1
    if args.check:
        report = run_health_checks(config)
        print(json.dumps(report))
        return 0 if report["ok"] else 1
    if args.component == "dashboard":
        from gunicorn.app.base import BaseApplication
        from isolate_web import create_app
        app = create_app(config)
        settings = config["dashboard"]
        class Application(BaseApplication):
            def load_config(self):
                for key, value in {"bind": "{}:{}".format(settings.get("listen_host", "127.0.0.1"), settings.get("listen_port", 8080)),
                    "workers": int(settings.get("workers", 2)), "threads": int(settings.get("threads", 4)),
                    "timeout": 30, "graceful_timeout": 30, "accesslog": None, "errorlog": "-"}.items():
                    self.cfg.set(key, value)
            def load(self):
                return app
        Application().run()
    elif args.component == "gateway":
        from isolate_gateway import serve
        from isolate_runtime import Runtime
        asyncio.run(serve(Runtime(config)))
    elif args.component == "jobs":
        from isolate_jobs import run_worker
        from isolate_redis import create_redis_client
        run_worker(config, create_redis_client(config))
    else:
        from isolate_recordings import RecordingArchive
        archive = RecordingArchive(config)
        interval = max(0.2, min(30, float(config["recordings"].get("upload_interval_seconds", 2))))
        while True:
            try:
                archive.flush_once()
            except Exception:
                print("Recording publication failed; private outbox retained", file=sys.stderr)
            time.sleep(interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
