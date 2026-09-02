#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safe discovery of expired Isolate session directories."""

import os
import time


def expired_session_dirs(base_path, days, now=None):
    cutoff = float(now if now is not None else time.time()) - (int(days) * 86400)
    base_real = os.path.realpath(base_path)
    if not os.path.isdir(base_real):
        return []
    expired = []
    for username in os.listdir(base_real):
        user_path = os.path.join(base_real, username)
        if not os.path.isdir(user_path) or os.path.islink(user_path):
            continue
        for session_id in os.listdir(user_path):
            session_path = os.path.join(user_path, session_id)
            session_real = os.path.realpath(session_path)
            if not os.path.isdir(session_real) or os.path.islink(session_path):
                continue
            if os.path.commonpath([base_real, session_real]) != base_real:
                continue
            newest = os.path.getmtime(session_real)
            session_log = os.path.join(session_real, "session.jsonl")
            if os.path.isfile(session_log):
                newest = max(newest, os.path.getmtime(session_log))
            if newest < cutoff:
                expired.append(session_real)
    return sorted(expired)
