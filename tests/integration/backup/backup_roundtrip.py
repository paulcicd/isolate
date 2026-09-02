#!/usr/bin/env python3
"""Round-trip service backup against a real Redis server."""

import os
import sys
import tempfile

from redis import Redis

sys.path.insert(0, "/opt/isolate/shared")

from isolate_backup import create_backup, restore_backup, verify_backup  # noqa: E402


def write_file(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as output_f:
        output_f.write(value)


def main():
    redis = Redis(host=os.environ.get("REDIS_HOST", "redis"), port=6379, db=15)
    redis.flushdb()
    redis.set("server_10042", '{"project_name":"payments-prod"}')
    redis.set("grant_7", '{"remote_user":"support"}')
    redis.set("active_session_ttl", "active", ex=300)
    redis.set("outside_backup_scope", "ignored")

    with tempfile.TemporaryDirectory(prefix="isolate-integration-") as root:
        source = os.path.join(root, "source")
        config_path = os.path.join(source, "configs", "isolate.yml")
        key_path = os.path.join(source, "keys", "id_rsa")
        known_hosts_path = os.path.join(source, "known_hosts")
        write_file(config_path, "schema_version: 2\n")
        write_file(key_path, "TEST PRIVATE KEY\n")
        write_file(known_hosts_path, "target ssh-ed25519 TEST\n")
        config = {
            "data_root": source,
            "logging": {"base_path": os.path.join(source, "logs")},
            "backup": {
                "base_path": os.path.join(root, "backups"),
                "retention_count": 2,
                "include_logs": False,
                "redis_patterns": ["server_*", "grant_*", "active_session_*"],
                "paths": [
                    {"path": os.path.join(source, "configs"), "required": True},
                    {"path": os.path.join(source, "keys"), "required": True},
                    {"path": known_hosts_path, "required": True},
                ],
            },
        }

        created = create_backup(config, redis)
        verified = verify_backup(created["archive"])
        assert verified["valid"], verified["errors"]
        assert verified["sidecar_verified"] is True
        assert created["redis_consistent"] is True
        assert created["redis_key_count"] == 3

        redis.flushdb()
        target = os.path.join(root, "restored")
        restored = restore_backup(
            created["archive"],
            target,
            redis=redis,
            restore_redis=True,
            confirmed=True,
        )
        assert restored["redis"]["restored"] == 3
        assert redis.get("server_10042") == b'{"project_name":"payments-prod"}'
        assert redis.get("grant_7") == b'{"remote_user":"support"}'
        assert 0 < redis.ttl("active_session_ttl") <= 300
        assert redis.get("outside_backup_scope") is None
        restored_config = os.path.join(target, config_path.lstrip(os.path.sep))
        with open(restored_config, "r", encoding="utf-8") as restored_f:
            assert restored_f.read() == "schema_version: 2\n"

    redis.flushdb()
    print("Isolate backup container round-trip: OK")


if __name__ == "__main__":
    main()
