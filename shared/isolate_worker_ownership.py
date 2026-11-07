"""Durable job claims and owner-token lock release for multiple workers.

A claim is intentionally not a lease: losing a worker leaves an unknown remote
outcome and must never cause the same job ID to be executed automatically again.
Redis persistence/restore semantics remain part of the deployment's durability
contract. This does not promise exactly-once remote command execution.
"""

import json
import secrets
import time


class JobOwnershipError(ValueError):
    pass


def owner_token():
    return secrets.token_hex(32)


def _decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def claim_key(job_id):
    return "job_execution_claim_" + str(job_id)


def release_lock(redis, key, owner):
    if not hasattr(redis, "pipeline"):
        if _decode(redis.get(key)) == owner:
            redis.delete(key)
            return True
        return False
    from redis.exceptions import WatchError
    for _ in range(16):
        with redis.pipeline() as pipe:
            try:
                pipe.watch(key)
                if _decode(pipe.get(key)) != owner:
                    return False
                pipe.multi()
                pipe.delete(key)
                pipe.execute()
                return True
            except WatchError:
                continue
    return False


def claim_job(redis, job_id, owner):
    """Atomically consume execution eligibility and mark the queued job claimed."""
    job_key = "job_" + str(job_id)
    key = claim_key(job_id)
    lock_key = "job_lock_" + str(job_id)

    def inspect(client):
        if _decode(client.get(lock_key)) != owner:
            raise JobOwnershipError("job worker lock was lost before execution")
        raw = client.get(job_key)
        current = json.loads(_decode(raw)) if raw is not None else None
        if (current is None or current.get("status") != "queued" or current.get("cancel_requested")
                or client.get(key) is not None):
            return None
        timestamp = int(time.time())
        current.update(status="claimed", execution_owner=owner, claimed_at=timestamp)
        claim = {"job_id": str(job_id), "owner": owner, "claimed_at": timestamp}
        return current, claim

    if not hasattr(redis, "pipeline"):
        selected = inspect(redis)
        if selected is None:
            return None
        current, claim = selected
        if not redis.set(key, json.dumps(claim, sort_keys=True), nx=True):
            return None
        redis.set(job_key, json.dumps(current, sort_keys=True))
        return current
    from redis.exceptions import WatchError
    for _ in range(16):
        with redis.pipeline() as pipe:
            try:
                pipe.watch(job_key, key, lock_key)
                selected = inspect(pipe)
                if selected is None:
                    return None
                current, claim = selected
                pipe.multi()
                # No EX: reusing an expired lease must not authorize execution.
                pipe.set(key, json.dumps(claim, sort_keys=True))
                pipe.set(job_key, json.dumps(current, sort_keys=True))
                pipe.execute()
                return current
            except WatchError:
                continue
    raise JobOwnershipError("job changed too frequently while claiming execution")


def mutate_job(redis, job_id, change):
    """Merge a change against the latest record with an optimistic transaction."""
    key = "job_" + str(job_id)

    def apply(raw):
        return change(json.loads(_decode(raw)) if raw is not None else None)

    if not hasattr(redis, "pipeline"):
        current = apply(redis.get(key))
        if current is not None:
            redis.set(key, json.dumps(current, sort_keys=True))
        return current
    from redis.exceptions import WatchError
    for _ in range(16):
        with redis.pipeline() as pipe:
            try:
                pipe.watch(key)
                current = apply(pipe.get(key))
                if current is None:
                    return None
                pipe.multi()
                pipe.set(key, json.dumps(current, sort_keys=True))
                pipe.execute()
                return current
            except WatchError:
                continue
    raise JobOwnershipError("job changed too frequently while saving worker state")


def update_owned_job(redis, job_id, owner, updates):
    """Merge worker status while preserving a concurrent cancellation request."""
    def change(current):
        if current is None or current.get("execution_owner") != owner:
            raise JobOwnershipError("job execution ownership changed")
        current.update(updates)
        return current
    return mutate_job(redis, job_id, change)


def mark_recovery_required(redis, job_id, owner):
    """Caller must hold a *new* worker lock after the prior lock was lost."""
    key = "job_" + str(job_id)
    lock_key = "job_lock_" + str(job_id)

    def change(client):
        if _decode(client.get(lock_key)) != owner:
            raise JobOwnershipError("recovery worker lock was lost")
        raw = client.get(key)
        current = json.loads(_decode(raw)) if raw is not None else None
        if current is None:
            return None
        if (current.get("status") not in ("queued", "claimed", "running")
                or current.get("status") == "queued" and client.get(claim_key(job_id)) is None):
            return current
        current.update(status="recovery_required", recovery_required_at=int(time.time()),
                       error="Previous execution claim exists; inspect the remote outcome before submitting a new job")
        return current

    def recovery_claim(record):
        return json.dumps({"job_id": str(job_id), "owner": record.get("execution_owner") or "legacy-unknown",
                           "claimed_at": record.get("claimed_at") or record.get("started_at"),
                           "recovered_at": int(time.time())}, sort_keys=True)

    if not hasattr(redis, "pipeline"):
        current = change(redis)
        if current is not None:
            if current.get("status") == "recovery_required":
                redis.set(claim_key(job_id), recovery_claim(current), nx=True)
            redis.set(key, json.dumps(current, sort_keys=True))
        return current
    from redis.exceptions import WatchError
    for _ in range(16):
        with redis.pipeline() as pipe:
            try:
                pipe.watch(key, claim_key(job_id), lock_key)
                current = change(pipe)
                if current is None:
                    return None
                pipe.multi()
                if current.get("status") == "recovery_required":
                    pipe.set(claim_key(job_id), recovery_claim(current), nx=True)
                pipe.set(key, json.dumps(current, sort_keys=True))
                pipe.execute()
                return current
            except WatchError:
                continue
    raise JobOwnershipError("job recovery state changed too frequently")
