#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Session details and replay helpers for Isolate audit logs."""

import json
import os
import re

from isolate_history import _load_events, _row_from_events


TIMESTAMP_RE = re.compile(r"(?m)^(\d+\.\d{6})\n")


def _iter_session_files(base_path):
    for current_root, _, files in os.walk(base_path):
        if "session.jsonl" in files:
            yield os.path.join(current_root, "session.jsonl")


def _event_matches(event, connection_id):
    value = str(connection_id)
    return value in (
        str(event.get("connection_id") or ""),
        str(event.get("session_id") or ""),
    )


def find_session(base_path, connection_id):
    for path in _iter_session_files(base_path):
        events = _load_events(path)
        if any(_event_matches(event, connection_id) for event in events):
            return build_session_details(path, events)
    return None


def build_session_details(session_path, events):
    row = _row_from_events(events) or {}
    raw_log_path = row.get("raw_log_path")
    raw_meta_path = raw_log_path + ".meta" if raw_log_path else None
    if raw_meta_path and not os.path.exists(raw_meta_path):
        raw_meta_path = None
    return {
        "session_path": session_path,
        "session_dir": os.path.dirname(session_path),
        "summary": row,
        "events": events,
        "raw_log_path": raw_log_path if raw_log_path and os.path.exists(raw_log_path) else raw_log_path,
        "raw_meta_path": raw_meta_path,
    }


def parse_raw_replay(raw_log_path, max_bytes=None):
    if not raw_log_path or not os.path.exists(raw_log_path):
        return {"duration": 0, "chunks": [], "plain": "", "error": "raw log not found"}
    try:
        with open(raw_log_path, "r", encoding="utf-8", errors="replace") as raw_f:
            text = raw_f.read(max_bytes if max_bytes else -1)
    except OSError as exc:
        return {"duration": 0, "chunks": [], "plain": "", "error": str(exc)}

    matches = list(TIMESTAMP_RE.finditer(text))
    if not matches:
        return {"duration": 0, "chunks": [], "plain": text, "error": "raw log does not contain replay timestamps"}

    chunks = []
    first_ts = None
    for index, match in enumerate(matches):
        try:
            ts = float(match.group(1))
        except ValueError:
            continue
        if first_ts is None:
            first_ts = ts
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        chunks.append({"t": round(ts - first_ts, 6), "data": text[start:end]})
    duration = chunks[-1]["t"] if chunks else 0
    return {"duration": duration, "chunks": chunks, "plain": "".join(chunk["data"] for chunk in chunks), "error": None}


def events_json(events):
    return json.dumps(events, indent=2, sort_keys=True)
