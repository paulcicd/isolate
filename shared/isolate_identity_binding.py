"""Durable, explicit IdP selection protects existing group and subject grants."""
import hashlib
import json
import secrets
import time

from isolate_identity import IdentityError

BINDING_KEY = "isolate_identity_provider_binding"


def provider_binding(config):
    from isolate_oidc import identity_provider_config
    provider = identity_provider_config(config)
    identity = {"issuer": provider.get("issuer"), "provider": provider["provider"],
                "subject_namespace": "issuer-sub-v1" if provider["provider"] == "oidc" else "legacy-sub",
                "claim_mapping": provider.get("claim_mapping") or {}}
    identity["fingerprint"] = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return identity


def ensure_provider_binding(config, store):
    expected = provider_binding(config)
    raw = store.get(BINDING_KEY)
    if not raw and expected["provider"] == "keycloak":
        # Existing deployments retain their identity semantics on upgrade.
        store.set(BINDING_KEY, json.dumps(dict(expected, bound_at=int(time.time()), actor="legacy-upgrade")), nx=True)
        raw = store.get(BINDING_KEY)
    try:
        actual = json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        actual = {}
    if not isinstance(actual, dict) or actual.get("fingerprint") != expected["fingerprint"]:
        raise IdentityError("Identity provider is not bound to this control store; run isolate-setup bind-identity after reconciling existing grants")
    return actual


def bind_provider(config, store, *, actor, reason, reconciled=False, drained=False):
    if not isinstance(actor, str) or not actor.strip() or not isinstance(reason, str) or not reason.strip():
        raise IdentityError("an operator and reason are required")
    from redis.exceptions import WatchError
    expected = provider_binding(config)
    for _ in range(5):
        with store.pipeline() as pipe:
            try:
                pipe.watch(BINDING_KEY)
                raw = pipe.get(BINDING_KEY)
                old = json.loads(raw) if raw else None
                if old and old.get("fingerprint") == expected["fingerprint"]:
                    return old
                # An unbound store can still contain pre-upgrade group grants.
                if not reconciled or not drained:
                    raise IdentityError("binding requires --reconciled-subjects and --all-ingress-drained, including the first generic OIDC binding")
                record = dict(expected, bound_at=int(time.time()), actor=actor[:256], reason=reason[:1024],
                              previous_fingerprint=(old or {}).get("fingerprint"))
                pipe.multi()
                pipe.set(BINDING_KEY, json.dumps(record))
                pipe.set("identity_binding_event_" + secrets.token_hex(16), json.dumps(record))
                pipe.set("isolate_authority_epoch", secrets.token_hex(32))
                pipe.execute()
                return record
            except WatchError:
                continue
    raise IdentityError("identity binding changed concurrently; retry after stopping all ingress")
