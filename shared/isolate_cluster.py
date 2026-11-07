"""Redis ownership primitives for sessions shared by several gateway nodes.

Ownership is never reconstructed from a process ID. Losing Redis or a lease
closes the local connection; another node must not resume an unknown SSH stream.
These primitives require one authoritative Redis deployment (not multi-master).
"""

import json
import secrets
import time


class OwnershipError(ValueError):
    pass


def take_once(redis, key):
    """GETDEL is atomic, including when several ingress nodes race."""
    return redis.getdel(key)


class Lease:
    def __init__(self, redis, key, ttl=30, owner=None):
        self.redis, self.key = redis, key
        self.ttl = max(5, int(ttl))
        self.owner = owner or secrets.token_hex(32)

    def acquire(self):
        if not self.redis.set(self.key, self.owner, nx=True, ex=self.ttl):
            raise OwnershipError("session already belongs to another gateway")
        return self

    def renew(self):
        # WATCH prevents a delayed owner from extending its successor's lease.
        from redis.exceptions import WatchError
        for _ in range(8):
            with self.redis.pipeline() as pipe:
                try:
                    pipe.watch(self.key)
                    current = pipe.get(self.key)
                    if isinstance(current, bytes):
                        current = current.decode()
                    if current != self.owner:
                        raise OwnershipError("gateway session lease was lost")
                    pipe.multi()
                    pipe.expire(self.key, self.ttl)
                    pipe.execute()
                    return
                except WatchError:
                    continue
        raise OwnershipError("gateway lease renewal contention")

    def release(self):
        from redis.exceptions import WatchError
        for _ in range(8):
            with self.redis.pipeline() as pipe:
                try:
                    pipe.watch(self.key)
                    current = pipe.get(self.key)
                    if isinstance(current, bytes):
                        current = current.decode()
                    if current != self.owner:
                        return False
                    pipe.multi()
                    pipe.delete(self.key)
                    pipe.execute()
                    return True
                except WatchError:
                    continue
        return False


def node_ready(redis, config):
    cluster = config.get("cluster", {})
    return not (cluster.get("draining") or redis.get("isolate_cluster_draining"))


def heartbeat_node(redis, config, node_id, active=0):
    ttl = max(10, int(config.get("cluster", {}).get("node_ttl", 30)))
    record = {"node_id": node_id, "heartbeat_at": int(time.time()),
              "active_sessions": int(active), "ready": node_ready(redis, config)}
    redis.set("isolate_node_" + node_id, json.dumps(record), ex=ttl)
    return record
