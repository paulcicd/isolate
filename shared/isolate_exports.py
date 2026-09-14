#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portable JSON and CSV exports for dashboard and CLI data."""

import csv
import io
import json


class ExportError(Exception):
    pass


def flatten_access_matrix(matrix):
    rows = []
    for subject in matrix.get("rows") or []:
        for project in matrix.get("projects") or []:
            cell = (subject.get("cells") or {}).get(project) or {}
            rows.append({
                "subject": subject.get("subject"),
                "name": subject.get("name"),
                "project": project,
                "state": cell.get("state"),
                "allowed_hosts": cell.get("allowed_hosts"),
                "total_hosts": cell.get("total_hosts"),
                "remote_users": cell.get("remote_users") or [],
                "sudo_modes": cell.get("sudo_modes") or [],
                "actions": cell.get("actions") or [],
            })
    return rows


def render_export(rows, output_format="json"):
    rows = [dict(row) for row in rows]
    if output_format == "json":
        return json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False) + "\n", "application/json"
    if output_format != "csv":
        raise ExportError("format must be json or csv")
    columns = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    output = io.StringIO(newline="")
    if columns:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in columns})
    return output.getvalue(), "text/csv"


def _csv_value(value):
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if value is None:
        return ""
    return value
