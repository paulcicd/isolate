#!/usr/bin/env python3
"""Run Isolate native SSH and Web SSH ingress."""

import argparse
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

from isolate_config import load_config
from isolate_gateway import serve
from isolate_runtime import Runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="Trusted service configuration path")
    args = parser.parse_args()
    config = load_config(path=args.config)
    from isolate_runtime_config import validate_runtime_config
    validation = validate_runtime_config(config, check_paths=True)
    if validation["errors"]:
        parser.error("; ".join(validation["errors"]))
    try:
        asyncio.run(serve(Runtime(config)))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
