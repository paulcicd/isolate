#!/usr/bin/env python3
"""Create private installation configuration and diagnose OIDC and state."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))


def main(argv=None):
    from isolate_identity import IdentityError
    from redis.exceptions import RedisError
    from yaml import YAMLError
    from isolate_config import load_config
    from isolate_setup import installation_config, write_installation, diagnose
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "wizard"):
        command = commands.add_parser(name)
        command.add_argument("--output", required=True)
        command.add_argument("--provider", choices=("keycloak", "oidc"), default="oidc")
        for key in ("issuer", "client-id", "audience", "public-url", "data-root", "dsn-file", "redis-host", "redis-ca", "redis-password-file", "client-secret-file", "admin-group"):
            command.add_argument("--" + key)
        command.add_argument("--provision-keys", action="store_true")
        command.add_argument("--plan", action="store_true")
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--config", required=True)
    doctor.add_argument("--offline", action="store_true")
    bind = commands.add_parser("bind-identity")
    bind.add_argument("--config", required=True)
    bind.add_argument("--actor", required=True)
    bind.add_argument("--reason", required=True)
    bind.add_argument("--reconciled-subjects", action="store_true")
    bind.add_argument("--all-ingress-drained", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command in ("init", "wizard"):
            required = ("issuer", "client_id", "public_url", "data_root", "dsn_file", "redis_host", "redis_ca")
            if args.command == "wizard":
                for key in required + ("admin_group",):
                    if not getattr(args, key):
                        setattr(args, key, input(key.replace("_", " ") + ": ").strip())
            if any(not getattr(args, key) for key in required):
                parser.error("issuer, client-id, public-url, data-root, dsn-file, redis-host and redis-ca are required")
            keys = required + ("provider", "audience", "admin_group", "redis_password_file", "client_secret_file")
            config = installation_config(**{key: getattr(args, key) for key in keys})
            if args.plan:
                print(json.dumps(config, indent=2))
                return 0
            path = write_installation(args.output, config, provision_keys=args.provision_keys)
            print(json.dumps({"config": path, "callback_url": args.public_url.rstrip("/") + "/auth/callback",
                "next": ["Register the callback and PKCE S256 client in your IdP; map groups and roles explicitly",
                         "Provision SQL schema and TLS Redis; populate target known_hosts from a trusted source",
                         "Reconcile grants and bind the configured identity provider before enabling ingress",
                         "Run doctor, then stage and activate a verified release"]}, indent=2))
        else:
            if not Path(args.config).is_file():
                parser.error("explicit configuration file does not exist")
            config = load_config(args.config, use_env=False)
            if args.command == "doctor":
                report = diagnose(config, offline=args.offline)
                print(json.dumps(report, indent=2))
                return 0 if report["ok"] else 1
            from isolate_identity_binding import bind_provider
            from isolate_redis import create_redis_client
            record = bind_provider(config, create_redis_client(config), actor=args.actor, reason=args.reason,
                reconciled=args.reconciled_subjects, drained=args.all_ingress_drained)
            print(json.dumps(record, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError, IdentityError, RedisError, YAMLError) as exc:
        # No exception values: network/SQL exceptions may include credentials.
        print("Setup failed ({}); check private paths and run doctor".format(type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
