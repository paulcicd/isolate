"""Shared, bounded admission counters. They never cache an allow decision."""

import hashlib
import time


class AdmissionDenied(ValueError):
    def __init__(self, retry_after):
        self.retry_after = max(1, int(retry_after))
        super().__init__("connection admission rate exceeded")


def check_admission(store, config, subject=None, peer=None, kind="connection", now=None):
    options = config.get("admission", {})
    if not options.get("enabled"):
        return
    now = int(time.time() if now is None else now)
    window, retry = now // 60, 60 - now % 60
    selectors = [("global", int(options.get("global_per_minute", 1000)))]
    if subject:
        selectors.append(("subject:" + str(subject), int(options.get("per_subject_per_minute", 60))))
    if peer:
        selectors.append(("peer:" + str(peer), int(options.get("per_peer_per_minute", 120))))
    if any(limit <= 0 for _, limit in selectors):
        raise ValueError("admission limits must be positive")
    keys = [("cache_admission_{}_{}_{}".format(kind, window, hashlib.sha256(name.encode()).hexdigest()), limit)
            for name, limit in selectors]
    from redis.exceptions import WatchError
    for _ in range(16):
        with store.pipeline() as pipe:
            try:
                pipe.watch(*(key for key, _ in keys))
                values = [(key, int(pipe.get(key) or 0), limit) for key, limit in keys]
                if any(value >= limit for _, value, limit in values):
                    raise AdmissionDenied(retry)
                pipe.multi()
                for key, value, _ in values:
                    pipe.set(key, value + 1, ex=retry + 5)
                pipe.execute()
                return
            except WatchError:
                continue
    raise AdmissionDenied(retry)
