#!/usr/bin/env python3
"""Publish the private recording outbox; never delete archived evidence."""

import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from isolate_config import load_config
from isolate_recordings import RecordingArchive, RecordingError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = load_config(path=args.config)
    archive = RecordingArchive(config)
    if not archive.enabled:
        parser.error("shared recordings are disabled")
    interval = max(0.2, min(30, float(config.get("recordings", {}).get("upload_interval_seconds", 2))))
    while True:
        try:
            result = archive.flush_once()
            if args.once:
                print(json.dumps(result))
                return 1 if result["failed"] else 0
        except Exception:
            # Service logs contain neither S3 response bodies nor credentials.
            print("Recording publication failed; the durable outbox is retained", file=sys.stderr)
            if args.once:
                return 1
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
