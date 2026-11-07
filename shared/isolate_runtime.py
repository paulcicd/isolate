"""Authenticated session control shared by native SSH, Web SSH and protocols.

Redis remains authoritative for inventory, grants and one-time approvals. A
ticket contains no caller-controlled route or Unix identity. It is consumed
once across every node, then the signed identity and current policy are checked
again before connecting and throughout the session.
"""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import time
import threading
import uuid
from urllib.parse import urlsplit

from isolate_cluster import Lease, OwnershipError, heartbeat_node, node_ready, take_once
from isolate_connection_auth import ConnectionDenied, policy_for_host
from isolate_identity import IdentityError, normalize_claims, verify_jwt_claims
from isolate_inventory import get_host, is_host_in_maintenance, list_hosts
from isolate_logging import SessionLogger
from isolate_policy import PolicyDenied, resolve_grant
from isolate_redis import create_redis_client
from isolate_session_approvals import (cancel_session_approval, close_session_approval,
    consume_session_approval, get_session_approval, request_session_approval,
    session_approval_required, validate_session_approval)
from isolate_sessions import (mark_session_end, mark_session_start,
    termination_requested, touch_session)


class RuntimeDenied(ConnectionDenied):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Runtime:
    def __init__(self, config, redis=None):
        self.config = config
        self.redis = redis if redis is not None else create_redis_client(config)
        self.node_id = str(config.get("cluster", {}).get("node_id") or socket.gethostname())

    def authenticate(self, token):
        kc = self.config.get("keycloak", {})
        issuer = urlsplit(str(kc.get("issuer") or ""))
        if (issuer.scheme != "https" or not issuer.hostname or issuer.username or issuer.password
                or issuer.query or issuer.fragment or not (kc.get("expected_audience") or kc.get("client_id"))
                or not kc.get("verify_tokens", True) or not kc.get("tls_verify", True)):
            raise RuntimeDenied("verified Keycloak identity and TLS are required")
        claims = verify_jwt_claims(token, kc)
        identity = normalize_claims(claims)
        if (not identity.get("keycloak_sub") or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", str(identity.get("username") or ""))
                or identity["username"] in (".", "..")):
            raise RuntimeDenied("invalid identity subject or username")
        from isolate_identity_security import assert_identity_active
        assert_identity_active(self.redis, self.config, identity, token=token)
        return identity

    def authorize(self, token, host_id, protocol="ssh", source_ip=None):
        identity = self.authenticate(token)
        return self.authorize_identity(identity, host_id, protocol, token=token, source_ip=source_ip)

    def authorize_identity(self, identity, host_id, protocol="ssh", token=None, source_ip=None):
        if protocol not in ("ssh", "webssh", "http", "kubernetes", "postgresql", "mysql"):
            raise RuntimeDenied("unsupported protocol")
        if not self.config.get("connection_authorization", {}).get("connections_enabled", True):
            raise RuntimeDenied("new connections are disabled")
        if not str(host_id).isdigit():
            raise RuntimeDenied("an inventory host ID is required")
        host = get_host(self.redis, host_id)
        if not host:
            raise RuntimeDenied("target not found")
        ipaddress.ip_address(host["server_ip"])
        if protocol in ("ssh", "webssh"):
            if not self.config.get("gateway", {}).get("enabled", False):
                raise RuntimeDenied("gateway is disabled")
            decision = policy_for_host(self.redis, self.config, identity, host)
            ports = self.config.get("connection_authorization", {}).get("allowed_target_ports") or []
            if ports and int(host.get("server_port") or 22) not in ports:
                raise RuntimeDenied("target port is not permitted")
            # An upstream jump needs its own credential/approval context. Legacy
            # wrapper remains available until that workflow is explicitly added.
            if host.get("proxy_id"):
                raise RuntimeDenied("gateway proxy hops are not configured; use the legacy wrapper")
            target_revision = None
        else:
            from isolate import load_grants, load_project_sets
            from isolate_protocols import resolve_target
            target_revision = _digest(resolve_target(self.config, host, protocol))
            bypass = set(self.config.get("maintenance", {}).get("bypass_groups") or [])
            if is_host_in_maintenance(host) and not bypass.intersection(identity.get("groups") or []):
                raise RuntimeDenied("target is in maintenance")
            decision = resolve_grant(identity, project=host["project_name"], host=host,
                grants=load_grants(self.redis), project_sets=load_project_sets(self.redis),
                defaults={**self.config.get("policy", {}), **self.config.get("ssh", {})}, action=protocol)
        if decision.get("sudo_mode") not in ("none", "sudo-i"):
            raise RuntimeDenied("unsupported sudo mode")
        from isolate_identity_security import assert_identity_active
        assert_identity_active(self.redis, self.config, identity, token=token, host=host, decision=decision)
        deadline = min(int(identity["exp"]), int(time.time()) + int(self.config.get("connection_authorization", {}).get("max_session_seconds", 28800)))
        expires = decision["matched_rule"].get("expires_at")
        if expires:
            deadline = min(deadline, int(expires))
        return {"identity": identity, "host": host, "decision": decision, "proxy": None,
                "connection_id": uuid.uuid4().hex,
                "_output_lock": threading.Lock(),
                "deadline": deadline, "token": token, "protocol": protocol, "source_ip": source_ip,
                "target_revision": target_revision,
                "authorization_revision": _digest({"ip": host["server_ip"], "port": host.get("server_port"),
                    "project": host["project_name"], "proxy": host.get("proxy_id"), "decision": decision,
                    "credentials": self.config.get("credentials", {}), "ssh_config": self.config.get("ssh", {})})}

    def resources(self, token, query=None, project=None):
        identity = self.authenticate(token)
        result = []
        for host in list_hosts(self.redis, query=query, project=project):
            try:
                # Listing SSH resources continues to work with gateway disabled.
                decision = policy_for_host(self.redis, self.config, identity, host)
            except (ConnectionDenied, PolicyDenied):
                continue
            fields = ("server_id", "server_name", "server_ip", "server_port", "project_name", "server_services",
                "server_services_display", "server_note", "server_vip", "server_vip_marker", "maintenance_enabled",
                "maintenance_until", "maintenance_reason", "maintenance_marker", "tags", "tags_display",
                "resource_owner", "environment", "privileged_access_provider", "privileged_access_url", "privileged_access_hint")
            row = {k: host[k] for k in fields if k in host}
            row["effective_access"] = {"remote_user": decision["remote_user"], "sudo_mode": decision["sudo_mode"]}
            result.append(row)
        return result

    def create_ticket(self, token, host_id, protocol="ssh", source_ip=None):
        if not node_ready(self.redis, self.config):
            raise RuntimeDenied("gateway is draining")
        context = self.authorize(token, host_id, protocol, source_ip)
        context["connection_id"] = uuid.uuid4().hex
        ticket = secrets.token_urlsafe(48)
        ttl = min(120, max(10, int(self.config.get("api", {}).get("ticket_ttl", 60))))
        record = {"token": token, "host_id": str(host_id), "protocol": protocol,
                  "source_ip": source_ip if self.config.get("api", {}).get("bind_ticket_ip", False) else None,
                  "connection_id": context["connection_id"], "expires_at": min(context["deadline"], int(time.time()) + ttl)}
        # Only the hash of the opaque password is stored. Bearer tokens in this
        # short-lived record are server-only; Redis must have private ACL/TLS.
        self.redis.set("isolate_ticket_" + hashlib.sha256(ticket.encode()).hexdigest(), json.dumps(record), ex=ttl)
        return {"ticket": ticket, "connection_id": context["connection_id"], "host_id": str(host_id),
                "protocol": protocol, "expires_at": record["expires_at"],
                "approval_required": session_approval_required(self.config, context["host"], context["decision"])}

    def consume_ticket(self, ticket, protocol="ssh", source_ip=None):
        if not node_ready(self.redis, self.config):
            raise RuntimeDenied("gateway is draining")
        if not isinstance(ticket, str) or not 32 <= len(ticket) <= 256:
            raise RuntimeDenied("invalid connection ticket")
        raw = take_once(self.redis, "isolate_ticket_" + hashlib.sha256(ticket.encode()).hexdigest())
        if raw is None:
            raise RuntimeDenied("connection ticket expired or already used")
        record = json.loads(raw)
        if (record["expires_at"] <= time.time() or record["protocol"] != protocol
                or (record.get("source_ip") and source_ip != record["source_ip"])):
            raise RuntimeDenied("connection ticket context differs")
        context = self.authorize(record["token"], record["host_id"], protocol, source_ip)
        context["connection_id"] = record["connection_id"]
        context["deadline"] = min(context["deadline"], int(context["identity"]["exp"]))
        return context

    def prepare(self, context):
        lease = Lease(self.redis, "isolate_session_owner_" + context["connection_id"],
                      self.config.get("cluster", {}).get("lease_ttl", 30)).acquire()
        context["_lease"] = lease
        try:
            approval = request_session_approval(self.redis, self.config, context["identity"], context["host"],
                context["decision"], context["connection_id"], source_ip=context.get("source_ip"))
            if approval:
                context["session_approval_id"] = approval["id"]
                while True:
                    self._recheck_policy(context)
                    lease.renew()
                    latest = get_session_approval(self.redis, approval["id"], config=self.config)
                    if not latest or latest["status"] not in ("pending", "approved"):
                        raise RuntimeDenied("session approval was denied, cancelled or expired")
                    if latest["status"] == "approved":
                        consumed = consume_session_approval(self.redis, self.config, approval["id"], context["identity"],
                            context["host"], context["decision"], context["connection_id"], source_ip=context.get("source_ip"))
                        context["deadline"] = min(context["deadline"], int(consumed["session_expires_at"]))
                        context["_approval_consumed"] = True
                        break
                    time.sleep(max(0.2, min(2, float(self.config.get("session_approval", {}).get("poll_interval_seconds", 2)))))
            self._recheck_policy(context)
            return context
        except BaseException:
            self.finish(context)
            raise

    def _recheck_policy(self, context):
        cancelled = context.get("_cancel_event")
        if context.get("_closed") or (cancelled is not None and cancelled.is_set()) or time.time() >= context["deadline"]:
            raise RuntimeDenied("session authorization expired")
        fresh = self.authorize(context["token"], context["host"]["server_id"], context["protocol"], context.get("source_ip"))
        if (fresh["authorization_revision"] != context["authorization_revision"]
                or fresh["target_revision"] != context["target_revision"]):
            raise RuntimeDenied("session route, credentials or policy changed")
        context["deadline"] = min(context["deadline"], fresh["deadline"])

    def start(self, context):
        if context.get("_started"):
            raise RuntimeDenied("session already started")
        self.recheck(context)
        host, decision = context["host"], context["decision"]
        logger = SessionLogger(self.config["logging"]["base_path"], context["identity"],
            session_id=context["connection_id"], logging_config=self.config.get("logging", {}))
        context["_logger"] = logger
        metadata = {"username": context["identity"]["username"], "keycloak_sub": context["identity"]["keycloak_sub"],
            "project": host["project_name"], "host_id": host["server_id"], "target_host": host["server_ip"],
            "remote_user": decision["remote_user"], "sudo_mode": decision["sudo_mode"],
            "protocol": context["protocol"], "source_ip": context.get("source_ip"), "owner_node": self.node_id,
            "audit_profile": "terminal-recording" if context["protocol"] in ("ssh", "webssh") else "connection",
            "session_approval_id": context.get("session_approval_id"), "expires_at": context["deadline"]}
        context["_raw_log_path"] = os.path.join(logger.session_dir, "terminal.log")
        logger.event_durable("ssh_start" if context["protocol"] in ("ssh", "webssh") else "protocol_start",
                             connection_id=context["connection_id"], raw_log_path=context["_raw_log_path"], **metadata)
        mark_session_start(self.redis, context["connection_id"], metadata)
        context["_started"] = True
        heartbeat_node(self.redis, self.config, self.node_id)
        return context

    def recheck(self, context):
        self._recheck_policy(context)
        lease = context.get("_lease")
        if lease is None:
            raise RuntimeDenied("session ownership is missing")
        lease.renew()
        if termination_requested(self.redis, context["connection_id"]):
            raise RuntimeDenied("session was terminated by an administrator")
        approval_id = context.get("session_approval_id")
        if context.get("_approval_consumed"):
            record = validate_session_approval(self.redis, self.config, approval_id, context["identity"], context["host"],
                context["decision"], context["connection_id"], source_ip=context.get("source_ip"))
            context["deadline"] = min(context["deadline"], int(record["session_expires_at"]))
        elif session_approval_required(self.config, context["host"], context["decision"]):
            raise RuntimeDenied("session now requires administrator approval")
        if context.get("_started"):
            touch_session(self.redis, context["connection_id"])

    def record_output(self, context, data):
        # The raw timestamp format is understood by existing replay and live
        # views. It is a terminal recording, never a semantic command stream.
        with context["_output_lock"]:
            self._record_output(context, data)

    def _record_output(self, context, data):
        logger = context.get("_logger")
        if logger:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(context["_raw_log_path"], flags, 0o660)
            try:
                payload = memoryview(("{:.6f}\n".format(time.time())).encode() + data)
                while payload:
                    count = os.write(fd, payload)
                    if count <= 0:
                        raise OSError("short terminal recording write")
                    payload = payload[count:]
            finally:
                os.close(fd)

    def finish(self, context, exit_code=None):
        if context.get("_closed"):
            return
        context["_closed"] = True
        try:
            if context.get("_started"):
                mark_session_end(self.redis, context["connection_id"], exit_code)
                context["_logger"].event("ssh_end" if context["protocol"] in ("ssh", "webssh") else "protocol_end",
                    connection_id=context["connection_id"], project=context["host"]["project_name"],
                    host_id=context["host"]["server_id"], protocol=context["protocol"], exit_code=exit_code,
                    audit_profile=context.get("audit_profile"), protocol_request=context.get("protocol_request"),
                    protocol_stats=context.get("protocol_stats"))
            if context.get("session_approval_id"):
                if context.get("_approval_consumed"):
                    close_session_approval(self.redis, context["session_approval_id"])
                else:
                    cancel_session_approval(self.redis, self.config, context["session_approval_id"], context["identity"])
        finally:
            lease = context.get("_lease")
            if lease:
                lease.release()
