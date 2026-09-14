#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Session details and replay helpers for Isolate audit logs."""

import json
import os
import re

from isolate_history import _load_events, _row_from_events


# The wrapper prefixes every PTY read with a timestamp. A read does not have to
# end with a newline, so the next timestamp can immediately follow its payload.
TIMESTAMP_RE = re.compile(r"(?<![\d.])(\d{4,12}\.\d{6})\r?\n")
OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)
CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def readable_terminal_text(text):
    """Return a best-effort text view while keeping xterm replay authoritative."""
    text = OSC_RE.sub("", str(text or ""))
    text = CSI_RE.sub("", text)
    output = []
    for char in text:
        if char == "\b":
            if output and output[-1] != "\n":
                output.pop()
        elif char == "\r":
            continue
        elif char in ("\n", "\t") or ord(char) >= 32:
            output.append(char)
    return "".join(output)


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
    matched_events = []
    matched_paths = []
    for path in _iter_session_files(base_path):
        events = _load_events(path)
        selected = [event for event in events if _event_matches(event, connection_id)]
        if selected:
            matched_events.extend(selected)
            matched_paths.append((path, any(event.get("raw_log_path") for event in selected)))
    if not matched_events:
        return None
    matched_events.sort(key=lambda event: float(event.get("ts") or 0))
    preferred_path = next((path for path, has_raw in matched_paths if has_raw), matched_paths[0][0])
    return build_session_details(preferred_path, matched_events)


def build_session_details(session_path, events):
    row = _row_from_events(events) or {}
    raw_log_path = _safe_raw_log_path(session_path, row.get("raw_log_path"))
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


def _safe_raw_log_path(session_path, candidate):
    if not candidate:
        return None
    try:
        user_log_dir = os.path.realpath(os.path.dirname(os.path.dirname(session_path)))
        path = os.path.realpath(str(candidate))
        if os.path.commonpath([user_log_dir, path]) != user_log_dir:
            return None
    except (OSError, ValueError):
        return None
    if not path.endswith(".log"):
        return None
    return path


def parse_raw_replay(raw_log_path, max_bytes=None, tail=False):
    if not raw_log_path or not os.path.exists(raw_log_path):
        return {"duration": 0, "chunks": [], "plain": "", "readable": "", "error": "raw log not found"}
    try:
        with open(raw_log_path, "rb") as raw_f:
            if tail and max_bytes:
                size = os.path.getsize(raw_log_path)
                raw_f.seek(max(0, size - int(max_bytes)))
            data = raw_f.read(int(max_bytes)) if max_bytes else raw_f.read()
            text = data.decode("utf-8", errors="replace")
    except OSError as exc:
        return {"duration": 0, "chunks": [], "plain": "", "readable": "", "error": str(exc)}

    matches = list(TIMESTAMP_RE.finditer(text))
    if not matches:
        return {
            "duration": 0,
            "chunks": [],
            "plain": text,
            "readable": readable_terminal_text(text),
            "error": "raw log does not contain replay timestamps",
        }

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
    plain = "".join(chunk["data"] for chunk in chunks)
    return {
        "duration": duration,
        "chunks": chunks,
        "plain": plain,
        "readable": readable_terminal_text(plain),
        "error": None,
    }


def events_json(events):
    return json.dumps(events, indent=2, sort_keys=True)


def tail_raw_text(raw_log_path, max_bytes=262144):
    if not raw_log_path or not os.path.isfile(raw_log_path):
        return {"text": "", "bytes": 0, "truncated": False, "error": "raw log not found"}
    maximum = max(1, int(max_bytes))
    try:
        size = os.path.getsize(raw_log_path)
        with open(raw_log_path, "rb") as raw_f:
            if size > maximum:
                raw_f.seek(size - maximum)
            data = raw_f.read(maximum)
    except OSError as exc:
        return {"text": "", "bytes": 0, "truncated": False, "error": str(exc)}
    return {
        "text": data.decode("utf-8", errors="replace"),
        "bytes": len(data),
        "truncated": size > maximum,
        "error": None,
    }
