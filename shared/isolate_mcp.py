#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Keycloak-protected MCP interface for Isolate v2."""

import json
import re
import time
import uuid
from typing import Any

from isolate import load_grants, load_project_sets
from isolate_access import (
    AccessDenied,
    approve_access_request,
    comment_access_request,
    create_access_request,
    deny_access_request,
    get_access_request,
    is_access_admin,
    list_access_requests,
    parse_duration,
    set_notification_status,
)
from isolate_audit import prepare_and_dispatch
from isolate_config import load_config
from isolate_history import read_history
from isolate_identity import IdentityError, normalize_claims, verify_jwt_claims
from isolate_inventory import get_host, list_hosts
from isolate_notifications import NotificationError, notify_access_event
from isolate_policy import PolicyDenied, filter_allowed_hosts, resolve_grant
from isolate_redis import create_redis_client


class MCPAccessDenied(ValueError):
    pass


def token_scopes(claims):
    scopes = claims.get("scope") or claims.get("scp") or []
    if isinstance(scopes, str):
        scopes = scopes.split()
    return sorted(set(str(scope) for scope in scopes if str(scope)))


def mcp_keycloak_config(config):
    keycloak = dict(config.get("keycloak", {}) or {})
    mcp_cfg = config.get("mcp", {}) or {}
    for source, target in (
        ("issuer", "issuer"),
        ("expected_audience", "expected_audience"),
        ("jwks_uri", "jwks_uri"),
        ("jwks_cache_path", "jwks_cache_path"),
        ("jwks_cache_ttl", "jwks_cache_ttl"),
        ("tls_verify", "tls_verify"),
    ):
        if mcp_cfg.get(source) is not None:
            keycloak[target] = mcp_cfg[source]
    keycloak["verify_tokens"] = True
    return keycloak


def _strict_audience_matches(claims, expected_audience):
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    return bool(expected_audience and expected_audience in audiences)


class KeycloakMCPTokenVerifier(object):
    """Official MCP SDK TokenVerifier-compatible Keycloak JWT verifier."""

    def __init__(self, config):
        self.config = config
        self.mcp_config = config.get("mcp", {}) or {}
        self.keycloak_config = mcp_keycloak_config(config)

    def verified_token_data(self, token):
        try:
            claims = verify_jwt_claims(token, self.keycloak_config)
        except IdentityError:
            return None
        expected = self.keycloak_config.get("expected_audience")
        if not _strict_audience_matches(claims, expected):
            return None
        return {
            "token": token,
            "client_id": str(claims.get("azp") or claims.get("client_id") or "keycloak"),
            "scopes": token_scopes(claims),
            "expires_at": int(claims["exp"]) if claims.get("exp") is not None else None,
            "resource": self.mcp_config.get("public_url"),
            "subject": claims.get("sub"),
            "claims": claims,
        }

    async def verify_token(self, token):
        data = self.verified_token_data(token)
        if data is None:
            return None
        from mcp.server.auth.provider import AccessToken

        return AccessToken(**data)


class IsolateMCPService(object):
    """Transport-independent MCP operations with existing Isolate policy enforcement."""

    def __init__(self, config, redis):
        self.config = config
        self.redis = redis
        self.mcp_config = config.get("mcp", {}) or {}

    def _audit(self, tool, identity, outcome, started_at, details=None):
        record = {
            "event": "mcp_tool_call",
            "request_id": str(uuid.uuid4()),
            "ts": time.time(),
            "username": identity.get("username"),
            "keycloak_sub": identity.get("keycloak_sub"),
            "tool": tool,
            "outcome": outcome,
            "duration_ms": round((time.monotonic() - started_at) * 1000, 3),
            "source": "isolate-mcp",
        }
        record.update(details or {})
        prepare_and_dispatch(record, self.config.get("logging", {}))

    def _policy_state(self):
        return load_grants(self.redis), load_project_sets(self.redis)

    def _policy_defaults(self):
        return {**self.config.get("policy", {}), **self.config.get("ssh", {})}

    def _has_scope(self, scopes, name):
        return bool(name and name in set(scopes or []))

    def _is_access_admin(self, identity, scopes):
        approval_scope = self.mcp_config.get("approval_scope", "isolate.approve")
        admin_groups = self.config.get("access", {}).get("admin_groups") or []
        return self._has_scope(scopes, approval_scope) and is_access_admin(identity, admin_groups)

    def _require_access_admin(self, identity, scopes):
        if not self._is_access_admin(identity, scopes):
            raise MCPAccessDenied("access administration requires both an admin group and the configured approval scope")

    def _require_self_service(self, scopes):
        scope = self.mcp_config.get("self_service_scope", "isolate.self-service")
        if not self._has_scope(scopes, scope):
            raise MCPAccessDenied("required scope is missing: {}".format(scope))

    def _require_confirmation(self, confirm):
        if self.mcp_config.get("require_mutation_confirmation", True) and confirm is not True:
            raise MCPAccessDenied("explicit confirm=true is required for this mutation")

    def _can_view_request(self, identity, scopes, record):
        return bool(
            record
            and (
                record.get("requester") == identity.get("username")
                or self._is_access_admin(identity, scopes)
            )
        )

    def _notify_access(self, event_name, record, actor, extra=None):
        warning = None
        try:
            notification = notify_access_event(self.config, event_name, record, actor=actor, extra=extra)
            set_notification_status(self.redis, record["id"], notification)
        except NotificationError as exc:
            warning = str(exc)
            set_notification_status(self.redis, record["id"], {"ok": False, "errors": [warning], "sent": []})
        return get_access_request(self.redis, record["id"]) or record, warning

    def _validate_request_target(self, record):
        project = _required_text(record.get("project"), "project", 128)
        host_id = _optional_text(record.get("host"), "host", 64)
        if host_id:
            host = get_host(self.redis, host_id)
            if host is None or host.get("project_name") != project:
                raise AccessDenied("requested host no longer belongs to the requested project")
        elif not list_hosts(self.redis, project=project):
            raise AccessDenied("requested project no longer exists")

    def _acquire_decision_lock(self, request_id):
        key = "access_request_lock_{}".format(request_id)
        token = str(uuid.uuid4())
        try:
            acquired = self.redis.set(key, token, nx=True, ex=30)
        except TypeError as exc:
            raise AccessDenied("Redis client does not support atomic access decision locks") from exc
        if not acquired:
            raise AccessDenied("another decision for this request is already in progress")

    @staticmethod
    def _is_self_approval(identity, record):
        subject = identity.get("keycloak_sub")
        requester_subject = record.get("requester_sub")
        if subject and requester_subject:
            return subject == requester_subject
        return identity.get("username") == record.get("requester")

    def identity_whoami(self, identity, scopes, expires_at):
        started = time.monotonic()
        result = {
            "username": identity.get("username"),
            "email": identity.get("email"),
            "keycloak_sub": identity.get("keycloak_sub"),
            "groups": identity.get("groups"),
            "roles": identity.get("roles"),
            "scopes": scopes,
            "expires_at": expires_at,
        }
        self._audit("identity_whoami", identity, "allowed", started)
        return result

    def inventory_search(self, identity, query=None, project=None, limit=None):
        started = time.monotonic()
        try:
            query = _optional_text(query, "query", 256)
            project = _optional_text(project, "project", 128)
            maximum = int(self.mcp_config.get("max_results", 100))
            limit = min(max(int(limit or 50), 1), maximum)
            grants, project_sets = self._policy_state()
            hosts = list_hosts(self.redis, project=project, query=query)
            allowed = filter_allowed_hosts(
                identity,
                hosts,
                grants=grants,
                project_sets=project_sets,
                defaults=self._policy_defaults(),
            )[:limit]
            result = {"hosts": allowed, "count": len(allowed), "limit": limit}
            self._audit("inventory_search", identity, "allowed", started, {"project": project, "result_count": len(allowed)})
            return result
        except Exception:
            self._audit("inventory_search", identity, "error", started, {"project": project})
            raise

    def inventory_projects(self, identity):
        started = time.monotonic()
        try:
            grants, project_sets = self._policy_state()
            hosts = filter_allowed_hosts(
                identity,
                list_hosts(self.redis),
                grants=grants,
                project_sets=project_sets,
                defaults=self._policy_defaults(),
            )
            projects = sorted(set(host.get("project_name") for host in hosts if host.get("project_name")))
            self._audit("inventory_projects", identity, "allowed", started, {"result_count": len(projects)})
            return {"projects": projects, "count": len(projects)}
        except Exception:
            self._audit("inventory_projects", identity, "error", started)
            raise

    def host_get(self, identity, server_id):
        started = time.monotonic()
        server_id = _required_text(server_id, "server_id", 64)
        try:
            host = get_host(self.redis, server_id)
            if host is None:
                raise MCPAccessDenied("host was not found or is not allowed")
            grants, project_sets = self._policy_state()
            resolve_grant(
                identity,
                project=host.get("project_name"),
                host=host,
                grants=grants,
                project_sets=project_sets,
                defaults=self._policy_defaults(),
            )
            self._audit("host_get", identity, "allowed", started, {"host_id": server_id, "project": host.get("project_name")})
            return host
        except (PolicyDenied, MCPAccessDenied):
            self._audit("host_get", identity, "denied", started, {"host_id": server_id})
            raise MCPAccessDenied("host was not found or is not allowed")
        except Exception:
            self._audit("host_get", identity, "error", started, {"host_id": server_id})
            raise

    def grant_explain(self, identity, project=None, host_id=None):
        started = time.monotonic()
        project = _optional_text(project, "project", 128)
        host_id = _optional_text(host_id, "host_id", 64)
        if not project and not host_id:
            raise ValueError("project or host_id is required")
        host = get_host(self.redis, host_id) if host_id else None
        if host_id and host is None:
            raise MCPAccessDenied("host was not found or is not allowed")
        project = project or (host or {}).get("project_name")
        try:
            decision = resolve_grant(
                identity,
                project=project,
                host=host,
                grants=load_grants(self.redis),
                project_sets=load_project_sets(self.redis),
                defaults=self._policy_defaults(),
            )
            matched = decision.get("matched_rule") or {}
            result = {
                "allowed": True,
                "project": project,
                "host": host,
                "remote_user": decision.get("remote_user"),
                "sudo_mode": decision.get("sudo_mode"),
                "allowed_actions": decision.get("allowed_actions"),
                "matched_grant": {
                    "id": matched.get("id"),
                    "subject": matched.get("subject"),
                    "name": matched.get("name"),
                    "host": matched.get("host") or matched.get("host_id") or matched.get("server_id"),
                    "project": matched.get("project"),
                    "project_glob": matched.get("project_glob"),
                    "project_set": matched.get("project_set"),
                    "temporary": bool(matched.get("temporary")),
                    "expires_at": matched.get("expires_at"),
                },
            }
            self._audit("grant_explain", identity, "allowed", started, {"host_id": host_id, "project": project})
            return result
        except PolicyDenied as exc:
            result = {
                "allowed": False,
                "project": project,
                "host_id": host_id,
                "reason": str(exc),
                "suggested_request": "isolate access request --project {}{} --reason <reason>".format(
                    project or "<project>",
                    " --host {}".format(host_id) if host_id else "",
                ),
            }
            self._audit("grant_explain", identity, "denied", started, {"host_id": host_id, "project": project})
            return result

    def history_search(self, identity, query=None, project=None, host=None, limit=None):
        started = time.monotonic()
        query = _optional_text(query, "query", 256)
        project = _optional_text(project, "project", 128)
        host = _optional_text(host, "host", 128)
        history_cfg = self.config.get("history", {}) or {}
        maximum = min(int(history_cfg.get("max_limit", 100)), int(self.mcp_config.get("max_results", 100)))
        limit = min(max(int(limit or history_cfg.get("default_limit", 10)), 1), maximum)
        try:
            rows = read_history(
                self.config["logging"]["base_path"],
                identity,
                query=query,
                user=identity.get("username"),
                project=project,
                host=host,
                limit=limit,
                admin_groups=[],
            )
            self._audit("history_search", identity, "allowed", started, {"project": project, "host_id": host, "result_count": len(rows)})
            return {"connections": rows, "count": len(rows), "limit": limit}
        except Exception:
            self._audit("history_search", identity, "error", started, {"project": project, "host_id": host})
            raise

    def access_request_create(self, identity, project, reason, host=None, remote_user=None, sudo_mode=None, ticket=None, template=None):
        started = time.monotonic()
        project = _required_text(project, "project", 128)
        reason = _required_text(reason, "reason", 2048)
        host = _optional_text(host, "host", 64)
        remote_user = _optional_text(remote_user, "remote_user", 64)
        sudo_mode = _optional_text(sudo_mode, "sudo_mode", 32)
        ticket = _optional_text(ticket, "ticket", 128)
        template = _optional_text(template, "template", 128)
        if remote_user and re.match(r"^[a-z_][a-z0-9_-]{0,63}$", remote_user) is None:
            raise ValueError("remote_user validation failed")
        if sudo_mode and sudo_mode not in ("none", "sudo-i"):
            raise ValueError("sudo_mode must be none or sudo-i")
        hosts = list_hosts(self.redis, project=project)
        if host:
            selected = get_host(self.redis, host)
            if selected is None or selected.get("project_name") != project:
                raise ValueError("host does not belong to the requested project")
        elif not hosts:
            raise ValueError("project does not exist")
        try:
            record = create_access_request(
                self.redis,
                identity,
                project=project,
                host=host,
                remote_user=remote_user,
                sudo_mode=sudo_mode,
                reason=reason,
                ticket=ticket,
                template=template,
                config=self.config,
            )
            warning = None
            try:
                record, warning = self._notify_access("access_request_created", record, identity)
            except NotificationError as exc:  # pragma: no cover - handled by _notify_access
                warning = str(exc)
            result = {"request": record, "notification_warning": warning}
            self._audit("access_request_create", identity, "created", started, {"access_request_id": record["id"], "project": project, "host_id": host})
            return result
        except AccessDenied:
            self._audit("access_request_create", identity, "denied", started, {"project": project, "host_id": host})
            raise
        except Exception:
            self._audit("access_request_create", identity, "error", started, {"project": project, "host_id": host})
            raise

    def access_request_list(self, identity, scopes, status=None, user=None, project=None, ticket=None, limit=None):
        started = time.monotonic()
        status = _optional_text(status, "status", 16)
        user = _optional_text(user, "user", 128)
        project = _optional_text(project, "project", 128)
        ticket = _optional_text(ticket, "ticket", 128)
        if status and status not in ("pending", "approved", "denied"):
            raise ValueError("status must be pending, approved, or denied")
        admin = self._is_access_admin(identity, scopes)
        if not admin:
            try:
                self._require_self_service(scopes)
                if user and user != identity.get("username"):
                    raise MCPAccessDenied("other users' access requests are visible only to access admins")
            except MCPAccessDenied:
                self._audit("access_request_list", identity, "denied", started, {"admin_view": False})
                raise
            user = identity.get("username")
        maximum = int(self.mcp_config.get("max_results", 100))
        limit = min(max(int(limit or 50), 1), maximum)
        try:
            records = list_access_requests(
                self.redis,
                status=status,
                user=user,
                project=project,
                ticket=ticket,
            )[:limit]
            self._audit("access_request_list", identity, "allowed", started, {"result_count": len(records), "admin_view": admin})
            return {"requests": records, "count": len(records), "limit": limit, "admin_view": admin}
        except Exception:
            self._audit("access_request_list", identity, "error", started, {"admin_view": admin})
            raise

    def access_request_show(self, identity, scopes, request_id):
        started = time.monotonic()
        request_id = _required_text(request_id, "request_id", 64)
        record = get_access_request(self.redis, request_id)
        if not self._can_view_request(identity, scopes, record):
            self._audit("access_request_show", identity, "denied", started, {"access_request_id": request_id})
            raise MCPAccessDenied("access request was not found or is not visible")
        self._audit("access_request_show", identity, "allowed", started, {"access_request_id": request_id})
        return {"request": record}

    def access_request_comment(self, identity, scopes, request_id, text):
        started = time.monotonic()
        request_id = _required_text(request_id, "request_id", 64)
        text = _required_text(text, "text", 2048)
        record = get_access_request(self.redis, request_id)
        if not self._can_view_request(identity, scopes, record):
            self._audit("access_request_comment", identity, "denied", started, {"access_request_id": request_id})
            raise MCPAccessDenied("access request was not found or is not visible")
        if not self._is_access_admin(identity, scopes):
            try:
                self._require_self_service(scopes)
            except MCPAccessDenied:
                self._audit("access_request_comment", identity, "denied", started, {"access_request_id": request_id})
                raise
        try:
            record = comment_access_request(self.redis, request_id, identity, text)
            self._audit("access_request_comment", identity, "updated", started, {"access_request_id": request_id})
            return {"request": record}
        except Exception:
            self._audit("access_request_comment", identity, "error", started, {"access_request_id": request_id})
            raise

    def access_request_approve(
        self,
        identity,
        scopes,
        request_id,
        ttl=None,
        remote_user=None,
        sudo_mode=None,
        comment=None,
        confirm=False,
    ):
        started = time.monotonic()
        request_id = _required_text(request_id, "request_id", 64)
        try:
            self._require_access_admin(identity, scopes)
            self._require_confirmation(confirm)
            record = get_access_request(self.redis, request_id)
            if record is None:
                raise MCPAccessDenied("access request was not found")
            if self.mcp_config.get("prevent_self_approval", True) and self._is_self_approval(identity, record):
                raise MCPAccessDenied("self-approval is disabled")
            self._validate_request_target(record)
            access_cfg = self.config.get("access", {}) or {}
            ttl_seconds = parse_duration(ttl, default=access_cfg.get("default_ttl", "2h"))
            max_ttl = parse_duration(access_cfg.get("max_ttl", "24h"))
            if ttl_seconds <= 0:
                raise AccessDenied("ttl must be greater than zero")
            if ttl_seconds > max_ttl:
                raise AccessDenied("ttl exceeds configured maximum")
            selected_user = _optional_text(remote_user, "remote_user", 64) or record.get("remote_user")
            selected_sudo = _optional_text(sudo_mode, "sudo_mode", 32) or record.get("sudo_mode") or "none"
            comment = _optional_text(comment, "comment", 2048)
            if not selected_user or re.match(r"^[a-z_][a-z0-9_-]{0,63}$", selected_user) is None:
                raise AccessDenied("a valid remote_user is required before approval")
            if selected_sudo not in ("none", "sudo-i"):
                raise AccessDenied("sudo_mode must be none or sudo-i")
            self._acquire_decision_lock(request_id)
            record, grant = approve_access_request(
                self.redis,
                request_id,
                identity,
                ttl_seconds,
                remote_user=selected_user,
                sudo_mode=selected_sudo,
                max_ttl=max_ttl,
                comment=comment,
            )
            record, warning = self._notify_access("access_request_approved", record, identity, extra={"grant": grant})
            self._audit("access_request_approve", identity, "approved", started, {"access_request_id": request_id, "grant_id": record.get("grant_id")})
            return {"request": record, "grant": grant, "notification_warning": warning}
        except (AccessDenied, MCPAccessDenied):
            self._audit("access_request_approve", identity, "denied", started, {"access_request_id": request_id})
            raise
        except Exception:
            self._audit("access_request_approve", identity, "error", started, {"access_request_id": request_id})
            raise

    def access_request_deny(self, identity, scopes, request_id, reason, comment=None, confirm=False):
        started = time.monotonic()
        request_id = _required_text(request_id, "request_id", 64)
        reason = _required_text(reason, "reason", 2048)
        comment = _optional_text(comment, "comment", 2048)
        try:
            self._require_access_admin(identity, scopes)
            self._require_confirmation(confirm)
            record = get_access_request(self.redis, request_id)
            if record is None:
                raise MCPAccessDenied("access request was not found")
            if self.mcp_config.get("prevent_self_approval", True) and self._is_self_approval(identity, record):
                raise MCPAccessDenied("self-denial is disabled")
            self._acquire_decision_lock(request_id)
            record = deny_access_request(self.redis, request_id, identity, reason=reason, comment=comment)
            record, warning = self._notify_access("access_request_denied", record, identity)
            self._audit("access_request_deny", identity, "denied_request", started, {"access_request_id": request_id})
            return {"request": record, "notification_warning": warning}
        except (AccessDenied, MCPAccessDenied):
            self._audit("access_request_deny", identity, "denied", started, {"access_request_id": request_id})
            raise
        except Exception:
            self._audit("access_request_deny", identity, "error", started, {"access_request_id": request_id})
            raise


def _required_text(value, name, maximum):
    result = str(value or "").strip()
    if not result:
        raise ValueError("{} is required".format(name))
    if len(result) > maximum:
        raise ValueError("{} is too long".format(name))
    return result


def _optional_text(value, name, maximum):
    if value is None:
        return None
    result = str(value).strip()
    if not result:
        return None
    if len(result) > maximum:
        raise ValueError("{} is too long".format(name))
    return result


def _request_token():
    from mcp.server.auth.middleware.auth_context import get_access_token

    token = get_access_token()
    if token is None or not token.claims:
        raise MCPAccessDenied("authenticated Keycloak identity is required")
    return token


def _request_identity():
    return normalize_claims(_request_token().claims)


def create_mcp_server(config=None, redis=None):
    from mcp.server import MCPServer
    from mcp.server.auth.settings import AuthSettings
    from pydantic import AnyHttpUrl
    from starlette.responses import JSONResponse

    config = config or load_config()
    mcp_cfg = config.get("mcp", {}) or {}
    issuer = mcp_keycloak_config(config).get("issuer")
    public_url = mcp_cfg.get("public_url")
    if not issuer or not public_url:
        raise RuntimeError("mcp.issuer/keycloak.issuer and mcp.public_url are required")
    service = IsolateMCPService(config, redis or create_redis_client(config))
    server = MCPServer(
        "Isolate Bastion Platform v2",
        description="Policy-aware inventory, history, and temporary access for Isolate v2",
        token_verifier=KeycloakMCPTokenVerifier(config),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(issuer),
            resource_server_url=AnyHttpUrl(public_url),
            required_scopes=list(mcp_cfg.get("required_scopes") or ["isolate.read"]),
        ),
    )

    @server.tool(structured_output=True)
    def identity_whoami() -> dict[str, Any]:
        """Return the verified Keycloak identity and MCP scopes for this request."""
        token = _request_token()
        identity = normalize_claims(token.claims)
        return service.identity_whoami(identity, token.scopes, token.expires_at)

    @server.tool(structured_output=True)
    def inventory_search(query: str | None = None, project: str | None = None, limit: int = 50) -> dict[str, Any]:
        """Search only hosts the authenticated user may access through Isolate grants."""
        return service.inventory_search(_request_identity(), query=query, project=project, limit=limit)

    @server.tool(structured_output=True)
    def host_get(server_id: str) -> dict[str, Any]:
        """Read one host when it is visible to the authenticated user."""
        return service.host_get(_request_identity(), server_id)

    @server.tool(structured_output=True)
    def grant_explain(project: str | None = None, host_id: str | None = None) -> dict[str, Any]:
        """Explain the current user's effective grant for a project or host."""
        return service.grant_explain(_request_identity(), project=project, host_id=host_id)

    @server.tool(structured_output=True)
    def history_search(query: str | None = None, project: str | None = None, host: str | None = None, limit: int = 10) -> dict[str, Any]:
        """Search the authenticated user's own Isolate connection history."""
        return service.history_search(_request_identity(), query=query, project=project, host=host, limit=limit)

    @server.tool(structured_output=True)
    def access_request_create(
        project: str,
        reason: str,
        host: str | None = None,
        remote_user: str | None = None,
        sudo_mode: str | None = None,
        ticket: str | None = None,
        template: str | None = None,
    ) -> dict[str, Any]:
        """Create a pending break-glass request; this never grants access by itself."""
        token = _request_token()
        identity = normalize_claims(token.claims)
        scope_check_started = time.monotonic()
        try:
            service._require_self_service(token.scopes)
        except MCPAccessDenied:
            service._audit("access_request_create", identity, "denied", scope_check_started, {"project": project, "host_id": host})
            raise
        return service.access_request_create(
            identity,
            project=project,
            reason=reason,
            host=host,
            remote_user=remote_user,
            sudo_mode=sudo_mode,
            ticket=ticket,
            template=template,
        )

    @server.tool(structured_output=True)
    def access_request_list(
        status: str | None = None,
        user: str | None = None,
        project: str | None = None,
        ticket: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List own requests, or all matching requests for callers with admin group and approval scope."""
        token = _request_token()
        return service.access_request_list(
            normalize_claims(token.claims),
            token.scopes,
            status=status,
            user=user,
            project=project,
            ticket=ticket,
            limit=limit,
        )

    @server.tool(structured_output=True)
    def access_request_show(request_id: str) -> dict[str, Any]:
        """Read one request when it belongs to the caller or the caller is an access admin."""
        token = _request_token()
        return service.access_request_show(normalize_claims(token.claims), token.scopes, request_id)

    @server.tool(structured_output=True)
    def access_request_comment(request_id: str, text: str) -> dict[str, Any]:
        """Append an attributed comment to an access request visible to the caller."""
        token = _request_token()
        return service.access_request_comment(normalize_claims(token.claims), token.scopes, request_id, text)

    @server.tool(structured_output=True)
    def access_request_approve(
        request_id: str,
        confirm: bool = False,
        ttl: str | None = None,
        remote_user: str | None = None,
        sudo_mode: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Approve a pending request and create a temporary grant. Requires admin group, approval scope, and confirm=true."""
        token = _request_token()
        return service.access_request_approve(
            normalize_claims(token.claims),
            token.scopes,
            request_id,
            ttl=ttl,
            remote_user=remote_user,
            sudo_mode=sudo_mode,
            comment=comment,
            confirm=confirm,
        )

    @server.tool(structured_output=True)
    def access_request_deny(
        request_id: str,
        reason: str,
        confirm: bool = False,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Deny a pending request. Requires admin group, approval scope, and confirm=true."""
        token = _request_token()
        return service.access_request_deny(
            normalize_claims(token.claims),
            token.scopes,
            request_id,
            reason=reason,
            comment=comment,
            confirm=confirm,
        )

    @server.resource("isolate://inventory/projects", mime_type="application/json")
    def inventory_projects_resource() -> str:
        """Projects containing at least one host visible to the current identity."""
        return json.dumps(service.inventory_projects(_request_identity()), sort_keys=True)

    @server.resource("isolate://inventory/hosts/{server_id}", mime_type="application/json")
    def inventory_host_resource(server_id: str) -> str:
        """Policy-filtered host inventory record."""
        return json.dumps(service.host_get(_request_identity(), server_id), sort_keys=True)

    @server.custom_route("/health", methods=["GET"])
    async def health(_request):
        try:
            service.redis.ping()
            return JSONResponse({"status": "ok"})
        except Exception:
            return JSONResponse({"status": "unhealthy"}, status_code=503)

    return server


def create_app():
    from mcp.server.transport_security import TransportSecuritySettings

    config = load_config()
    mcp_cfg = config.get("mcp", {}) or {}
    return create_mcp_server(config).streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        max_request_body_size=int(mcp_cfg.get("max_request_body_size", 1048576)),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(mcp_cfg.get("allowed_hosts") or []),
            allowed_origins=list(mcp_cfg.get("allowed_origins") or []),
        ),
        host=mcp_cfg.get("listen_host", "127.0.0.1"),
    )


if __name__ == "__main__":
    from mcp.server.transport_security import TransportSecuritySettings

    runtime_config = load_config()
    runtime_mcp = runtime_config.get("mcp", {}) or {}
    create_mcp_server(runtime_config).run(
        transport="streamable-http",
        host=runtime_mcp.get("listen_host", "127.0.0.1"),
        port=int(runtime_mcp.get("listen_port", 8090)),
        stateless_http=True,
        json_response=True,
        max_request_body_size=int(runtime_mcp.get("max_request_body_size", 1048576)),
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(runtime_mcp.get("allowed_hosts") or []),
            allowed_origins=list(runtime_mcp.get("allowed_origins") or []),
        ),
    )
