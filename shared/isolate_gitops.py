#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Optional Git-backed policy synchronization with approval attestations."""

import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
import uuid

from isolate_inventory import list_hosts
from isolate_policy_bundle import (
    PolicyBundleError,
    apply_bundle,
    blast_radius,
    change_count,
    dump_bundle,
    export_bundle,
    load_bundle,
    load_bundle_text,
    plan_bundle,
    validate_bundle,
)


class GitOpsError(Exception):
    pass


SAFE_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
SAFE_REPO_FILE_RE = re.compile(r"^[A-Za-z0-9._/-]{1,240}$")


def _config(config):
    return config.get("policy_as_code", {}) or {}


def _safe_repo_file(value, name):
    value = str(value or "").strip().lstrip("/")
    if not value or SAFE_REPO_FILE_RE.fullmatch(value) is None or ".." in value.split("/"):
        raise GitOpsError("{} is invalid".format(name))
    return value


def _run_git(argv, timeout=60):
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"})
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=int(timeout),
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitOpsError("git command failed: {}".format(exc)) from exc
    if result.returncode != 0:
        raise GitOpsError("git command failed: {}".format((result.stderr or result.stdout).strip()[:1024]))
    return result.stdout


def _prepare_repository(config):
    cfg = _config(config)
    repository = str(cfg.get("repository") or "").strip()
    checkout = os.path.realpath(str(cfg.get("checkout_path") or ""))
    branch = str(cfg.get("branch") or "main").strip()
    if not repository:
        raise GitOpsError("policy_as_code.repository is required")
    if not checkout or not os.path.isabs(checkout):
        raise GitOpsError("policy_as_code.checkout_path must be absolute")
    if SAFE_BRANCH_RE.fullmatch(branch) is None or branch.startswith("-") or ".." in branch.split("/"):
        raise GitOpsError("policy_as_code.branch is invalid")
    git = str(cfg.get("git_binary") or "/usr/bin/git")
    timeout = int(cfg.get("git_timeout", 60))
    if not os.path.isdir(os.path.join(checkout, ".git")):
        os.makedirs(os.path.dirname(checkout), mode=0o700, exist_ok=True)
        _run_git([git, "clone", "--no-checkout", "--filter=blob:none", repository, checkout], timeout=timeout)
    else:
        current_remote = _run_git([git, "-C", checkout, "remote", "get-url", "origin"], timeout=timeout).strip()
        if current_remote != repository:
            raise GitOpsError("configured repository does not match checkout origin")
    _run_git([git, "-C", checkout, "fetch", "--prune", "--depth=1", "origin", branch], timeout=timeout)
    commit = _run_git([git, "-C", checkout, "rev-parse", "FETCH_HEAD"], timeout=timeout).strip()
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", commit) is None:
        raise GitOpsError("fetched commit id is invalid")
    return git, checkout, branch, commit, timeout


def _git_file(git, checkout, commit, path, timeout):
    path = _safe_repo_file(path, "repository file path")
    return _run_git([git, "-C", checkout, "show", "{}:{}".format(commit, path)], timeout=timeout)


def _approval_payload(attestation):
    return json.dumps(
        {key: value for key, value in attestation.items() if key != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sign_approval_attestation(attestation, key):
    record = dict(attestation)
    record["signature"] = hmac.new(key, _approval_payload(record), hashlib.sha256).hexdigest()
    return record


def create_approval_attestation(config, bundle_path, branch, approvals, pr_url=None):
    cfg = _config(config)
    with open(bundle_path, "r", encoding="utf-8") as policy_f:
        policy_text = policy_f.read()
    validation = validate_bundle(load_bundle_text(policy_text, input_format="json" if bundle_path.endswith(".json") else "yaml"))
    if not validation["valid"]:
        raise GitOpsError("cannot approve invalid policy: {}".format("; ".join(validation["errors"])))
    key_path = cfg.get("approval_key_file")
    try:
        with open(key_path, "rb") as key_f:
            key = key_f.read().strip()
    except OSError as exc:
        raise GitOpsError("cannot read policy approval key") from exc
    if len(key) < 32:
        raise GitOpsError("policy approval key is too short")
    approvers = sorted(set(str(value).strip() for value in approvals if str(value).strip()))
    if len(approvers) < int(cfg.get("minimum_approvals", 1)):
        raise GitOpsError("too few policy approvals")
    record = {
        "schema_version": 1,
        "branch": str(branch),
        "policy_sha256": hashlib.sha256(policy_text.encode("utf-8")).hexdigest(),
        "approvals": approvers,
        "issued_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if pr_url:
        record["pr_url"] = str(pr_url)
    return sign_approval_attestation(record, key)


def verify_approval_attestation(config, attestation, commit, branch, policy_sha256=None):
    cfg = _config(config)
    if not cfg.get("require_pr_approval", True):
        return {"required": False, "valid": True, "approvals": []}
    key_path = cfg.get("approval_key_file")
    try:
        with open(key_path, "rb") as key_f:
            key = key_f.read().strip()
    except OSError as exc:
        raise GitOpsError("cannot read policy approval key") from exc
    if len(key) < 32:
        raise GitOpsError("policy approval key is too short")
    if not isinstance(attestation, dict):
        raise GitOpsError("policy approval attestation must be an object")
    expected = hmac.new(key, _approval_payload(attestation), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(attestation.get("signature") or ""), expected):
        raise GitOpsError("policy approval attestation signature is invalid")
    if str(attestation.get("branch") or "") != branch:
        raise GitOpsError("policy approval attestation does not match fetched branch")
    if not policy_sha256 or not hmac.compare_digest(
        str(attestation.get("policy_sha256") or ""), str(policy_sha256)
    ):
        raise GitOpsError("policy approval attestation does not match the policy bundle")
    approvals = sorted(set(str(value) for value in (attestation.get("approvals") or []) if str(value)))
    if len(approvals) < int(cfg.get("minimum_approvals", 1)):
        raise GitOpsError("policy approval attestation has too few approvals")
    return {
        "required": True,
        "valid": True,
        "approvals": approvals,
        "issued_at": attestation.get("issued_at"),
        "commit": commit,
        "policy_sha256": policy_sha256,
    }


def fetch_git_policy(config):
    cfg = _config(config)
    if not cfg.get("enabled", False):
        raise GitOpsError("policy GitOps is disabled")
    if not cfg.get("require_pr_approval", True):
        raise GitOpsError("policy GitOps requires PR approval attestation")
    git, checkout, branch, commit, timeout = _prepare_repository(config)
    bundle_path = _safe_repo_file(cfg.get("git_bundle_path", "policy.yml"), "policy bundle path")
    bundle_text = _git_file(git, checkout, commit, bundle_path, timeout)
    bundle = load_bundle_text(bundle_text, input_format="json" if bundle_path.endswith(".json") else "yaml")
    validation = validate_bundle(bundle)
    if not validation["valid"]:
        raise GitOpsError("policy bundle is invalid: {}".format("; ".join(validation["errors"])))
    attestation_path = _safe_repo_file(
        cfg.get("approval_attestation_path", "policy.approval.json"), "approval attestation path"
    )
    try:
        attestation = json.loads(_git_file(git, checkout, commit, attestation_path, timeout))
    except (ValueError, GitOpsError) as exc:
        raise GitOpsError("cannot load policy approval attestation: {}".format(exc)) from exc
    policy_sha256 = hashlib.sha256(bundle_text.encode("utf-8")).hexdigest()
    approval = verify_approval_attestation(config, attestation, commit, branch, policy_sha256=policy_sha256)
    return {
        "bundle": bundle,
        "commit": commit,
        "branch": branch,
        "repository": cfg.get("repository"),
        "approval": approval,
        "validation": validation,
    }


def save_policy_snapshot(config, redis, source=None):
    cfg = _config(config)
    backup_dir = os.path.realpath(cfg.get("backup_dir") or "/opt/auth/backups")
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    revision_id = "{}-{}".format(stamp, uuid.uuid4().hex[:8])
    path = os.path.join(backup_dir, "policy-revision-{}.yml".format(revision_id))
    with open(path, "x", encoding="utf-8") as snapshot_f:
        snapshot_f.write(dump_bundle(export_bundle(redis), output_format="yaml"))
    if os.name == "posix":
        os.chmod(path, 0o600)
    return {"revision_id": revision_id, "path": path, "source": source}


def list_policy_snapshots(config):
    backup_dir = os.path.realpath(_config(config).get("backup_dir") or "/opt/auth/backups")
    if not os.path.isdir(backup_dir):
        return []
    rows = []
    for name in os.listdir(backup_dir):
        if not re.fullmatch(r"policy-revision-[A-Za-z0-9TZ-]+\.yml", name):
            continue
        path = os.path.join(backup_dir, name)
        rows.append({"revision_id": name[len("policy-revision-"):-4], "path": path, "created_at": int(os.path.getmtime(path))})
    return sorted(rows, key=lambda row: row["created_at"], reverse=True)


def git_policy_status(config, redis):
    fetched = fetch_git_policy(config)
    prune = bool(_config(config).get("prune", False))
    changes = plan_bundle(redis, fetched["bundle"], prune=prune)
    radius = blast_radius(redis, fetched["bundle"], list_hosts(redis), prune=prune)
    return {
        "commit": fetched["commit"],
        "branch": fetched["branch"],
        "repository": fetched["repository"],
        "approval": fetched["approval"],
        "validation": fetched["validation"],
        "drift": change_count(changes) > 0,
        "change_count": change_count(changes),
        "changes": changes,
        "blast_radius": radius,
    }


def sync_git_policy(config, redis, dry_run=True, confirmed=False):
    if not dry_run and _config(config).get("require_confirmation", True) and not confirmed:
        raise GitOpsError("policy sync requires explicit confirmation")
    fetched = fetch_git_policy(config)
    prune = bool(_config(config).get("prune", False))
    changes = plan_bundle(redis, fetched["bundle"], prune=prune)
    radius = blast_radius(redis, fetched["bundle"], list_hosts(redis), prune=prune)
    snapshot = None
    if not dry_run and change_count(changes):
        snapshot = save_policy_snapshot(config, redis, source=fetched["commit"])
        apply_bundle(redis, fetched["bundle"], prune=prune, dry_run=False)
    return {
        "applied": not dry_run,
        "commit": fetched["commit"],
        "approval": fetched["approval"],
        "change_count": change_count(changes),
        "changes": changes,
        "blast_radius": radius,
        "snapshot": snapshot,
    }


def rollback_policy(config, redis, revision_id, confirmed=False):
    if not confirmed:
        raise GitOpsError("policy rollback requires explicit confirmation")
    match = [row for row in list_policy_snapshots(config) if row["revision_id"] == str(revision_id)]
    if not match:
        raise GitOpsError("policy revision was not found")
    bundle = load_bundle(match[0]["path"])
    validation = validate_bundle(bundle)
    if not validation["valid"]:
        raise GitOpsError("rollback snapshot is invalid")
    changes = plan_bundle(redis, bundle, prune=True)
    before = save_policy_snapshot(config, redis, source="rollback-before-{}".format(revision_id))
    apply_bundle(redis, bundle, prune=True, dry_run=False)
    return {"rolled_back": revision_id, "change_count": change_count(changes), "changes": changes, "snapshot": before}
