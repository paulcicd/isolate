"""Fence credentials and live sessions across an explicit recovery boundary.

After restoring an older authoritative database, an operator rotates the epoch
before reopening admission. SQL's durability/replication configuration is still
part of the deployment contract; this module cannot detect every lost commit.
"""

import json
import secrets
import time


EPOCH_KEY = "isolate_authority_epoch"


def authority_epoch(store, config):
    if config.get("state", {}).get("backend", "redis") == "redis":
        return None
    value = store.get(EPOCH_KEY)
    if value is None:
        store.set(EPOCH_KEY, secrets.token_hex(32), nx=True)
        value = store.get(EPOCH_KEY)
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("authoritative recovery epoch is missing or invalid")
    return value


def rotate_authority_epoch(store, config, actor, reason):
    if config.get("state", {}).get("backend", "redis") == "redis":
        raise ValueError("recovery fencing requires an authoritative SQL backend")
    if not actor or not reason or len(str(reason)) > 1024:
        raise ValueError("recovery requires an identified actor and reason")
    epoch = secrets.token_hex(32)
    # One SQL transaction publishes the epoch and its audit record. Existing
    # sessions/tickets cannot cross the boundary even if Redis was restored.
    key = "recovery_event_" + secrets.token_hex(16)
    with store.pipeline() as transaction:
        transaction.multi()
        transaction.set(EPOCH_KEY, epoch)
        transaction.set(key, json.dumps({"event": "authority_epoch_rotated", "ts": int(time.time()),
            "actor": str(actor), "reason": str(reason), "epoch": epoch}, sort_keys=True))
        transaction.execute()
    return epoch
