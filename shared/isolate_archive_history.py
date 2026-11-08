"""History summaries from signed, authority-anchored recording metadata.

Listing a session must not download a whole terminal recording. These are
derived summary events used only by the history renderer; evidence downloads
continue to verify the original signed manifest and every requested chunk.
"""

import json


def archived_history_groups(config, identity, visible, state_client=None):
    if not config.get("recordings", {}).get("enabled"):
        return {}
    from isolate_recordings import RecordingArchive
    from isolate_redis import create_redis_client
    store = state_client if state_client is not None else create_redis_client(config)
    archive = RecordingArchive(config, state_client=store)
    groups = {}
    for key in store.scan_iter(match="recording_head_*"):
        value = store.get(key)
        if value is None:
            continue
        pointer = json.loads(value)
        metadata = pointer.get("metadata") or {}
        # Check cheap authority metadata before any object-store request; then
        # check the verified metadata again before exposing the summary.
        if not visible(metadata):
            continue
        identifier = key.decode() if isinstance(key, bytes) else key
        identifier = identifier.removeprefix("recording_head_")
        description = archive.describe(identifier)
        metadata = description["metadata"]
        if not visible(metadata) or metadata.get("protocol") not in (None, "ssh", "webssh"):
            continue
        start = metadata.get("started_at")
        if start is None:
            continue
        common = {k: v for k, v in metadata.items() if k not in ("ts", "started_at", "ended_at")}
        common.update(connection_id=identifier, session_id=identifier)
        events = [dict(common, event="ssh_start", ts=start)]
        if metadata.get("ended_at") is not None:
            events.append(dict(common, event="ssh_end", ts=metadata["ended_at"]))
        groups[identifier] = events
    return groups
