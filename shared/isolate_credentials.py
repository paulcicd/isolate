"""Server-owned SSH credentials with per-connection secret material cleanup.

Provider selection and secret references come exclusively from trusted runtime
configuration. Inventory/request fields never select a Vault endpoint, path,
local key, or signing role. Target OS accounts and their sudo rights are not
created or changed by this module.
"""

import contextlib
import json
import os
import re
import ssl
import stat
import tempfile
import time
from urllib import error, parse, request


class CredentialError(ValueError):
    pass


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a Vault token to another origin or replay a signing POST.
        return None


def _read_file(path, secret=False, maximum=1048576):
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        raise CredentialError("an absolute credential file path is required")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if os.path.islink(path) or not stat.S_ISREG(info.st_mode):
                raise CredentialError("credential files must be regular files")
            if os.name == "posix":
                allowed = {0, os.geteuid()}
                if info.st_uid not in allowed or info.st_mode & (0o077 if secret else 0o022):
                    raise CredentialError("unsafe credential file ownership or permissions")
            result = source.read(maximum + 1)
            if not result or len(result) > maximum:
                raise CredentialError("credential file is empty or too large")
            return result
    except CredentialError:
        raise
    except OSError as exc:
        raise CredentialError("cannot read credential file") from exc


def _write_secret(directory, filename, data):
    path = os.path.join(directory, filename)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
    return path


def _validate_private_key(data):
    try:
        from cryptography.hazmat.primitives import serialization
        try:
            return serialization.load_ssh_private_key(data, password=None)
        except ValueError:
            return serialization.load_pem_private_key(data, password=None)
    except Exception as exc:
        raise CredentialError("SSH private key is invalid or encrypted") from exc


def _public_bytes(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)


def _validate_certificate(data, private_key, username, provider, key_id=None, now=None):
    try:
        from cryptography.hazmat.primitives.serialization import (
            SSHCertificate, SSHCertificateType, load_ssh_public_identity,
            load_ssh_public_key,
        )
        certificate = load_ssh_public_identity(data)
        if not isinstance(certificate, SSHCertificate) or certificate.type != SSHCertificateType.USER:
            raise ValueError("not a user certificate")
        certificate.verify_cert_signature()
        if _public_bytes(certificate.public_key()) != _public_bytes(private_key.public_key()):
            raise ValueError("key mismatch")
        if not username or username.encode() not in certificate.valid_principals:
            raise ValueError("principal mismatch")
        now = int(time.time() if now is None else now)
        if certificate.valid_after > now or certificate.valid_before <= now:
            raise ValueError("certificate not currently valid")
        ca_path = provider.get("ca_public_key_file")
        if ca_path:
            ca_key = load_ssh_public_key(_read_file(ca_path))
            if _public_bytes(certificate.signature_key()) != _public_bytes(ca_key):
                raise ValueError("CA mismatch")
        if key_id is not None:
            if certificate.key_id != key_id.encode():
                raise ValueError("key ID mismatch")
            ttl = int(provider.get("ttl_seconds", 300))
            if certificate.valid_before > now + ttl + 30:
                raise ValueError("certificate exceeds requested lifetime")
        return certificate
    except CredentialError:
        raise
    except Exception as exc:
        raise CredentialError("SSH certificate failed validation") from exc


def _vault_path(provider, suffix):
    components = suffix.split("/")
    if (any(not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", piece) or piece in (".", "..")
            for piece in components)
            or suffix not in (provider.get("allowed_paths") or [])):
        raise CredentialError("Vault path is not explicitly allowed")
    return suffix


def _vault_request(provider, path, payload=None):
    address = str(provider.get("address") or "").rstrip("/")
    parsed = parse.urlsplit(address)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")
            or provider.get("tls_verify", True) is not True):
        raise CredentialError("Vault/OpenBao requires a verified HTTPS origin")
    try:
        token = _read_file(provider.get("token_file"), secret=True, maximum=16384).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise CredentialError("invalid Vault token file") from exc
    if not token or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise CredentialError("invalid Vault token file")
    headers = {"X-Vault-Token": token, "Accept": "application/json", "Content-Type": "application/json"}
    namespace = provider.get("namespace")
    if namespace:
        if not isinstance(namespace, str) or any(ord(char) < 32 or ord(char) > 126 for char in namespace):
            raise CredentialError("invalid Vault namespace")
        headers["X-Vault-Namespace"] = namespace
    context = ssl.create_default_context(cafile=provider.get("ca_file"))
    opener = request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())
    req = request.Request(address + "/v1/" + _vault_path(provider, path),
                          data=None if payload is None else json.dumps(payload).encode(), headers=headers)
    try:
        timeout = max(1, min(60, float(provider.get("timeout_seconds", 5))))
        with opener.open(req, timeout=timeout) as response:
            data = response.read(1048577)
        if len(data) > 1048576:
            raise CredentialError("Vault response is too large")
        result = json.loads(data)
        if not isinstance(result, dict) or not isinstance(result.get("data"), dict):
            raise CredentialError("Vault response is invalid")
        return result["data"]
    except CredentialError:
        raise
    except (error.URLError, OSError, ValueError) as exc:
        # Do not expose HTTP response bodies, URLs, paths, or bearer tokens.
        raise CredentialError("Vault credential request failed") from exc


def _provider(config, host):
    options = config.get("credentials") or {}
    providers = options.get("providers") or {}
    selected = (options.get("targets") or {}).get(str(host.get("server_id")), options.get("default", "legacy"))
    if selected == "legacy" and selected not in providers:
        return options, {"type": "openssh"}
    provider = providers.get(selected)
    if not isinstance(provider, dict):
        raise CredentialError("target credential provider is not configured")
    return options, provider


@contextlib.contextmanager
def ssh_credentials(config, host, identity, connection_id):
    """Yield AsyncSSH connect options; keep the context open until disconnect.

    ``host.remote_user`` must be set by the caller from its policy decision.
    Legacy providers let AsyncSSH read IdentityFile from the existing trusted
    OpenSSH config. Other providers return explicit client_keys/client_certs.
    SSH-agent forwarding is never used. The caller still pins the endpoint and
    username from policy and disables forwarding/subsystems as appropriate.
    """
    options, provider = _provider(config, host)
    known_hosts = (provider.get("known_hosts") or options.get("known_hosts")
                   or (config.get("ssh") or {}).get("known_hosts")
                   or (config.get("gateway") or {}).get("known_hosts")
                   or os.path.join(config.get("data_root", "/opt/auth"), "known_hosts"))
    _read_file(known_hosts)
    result = {"known_hosts": known_hosts, "agent_path": None}
    kind = provider.get("type", "openssh")
    username = host.get("remote_user") or host.get("server_user")
    if kind == "openssh":
        path = provider.get("config_path") or (config.get("ssh") or {}).get("config_path")
        _read_file(path)
        result["config"] = [path]
        yield result
        return
    if kind == "file":
        path = provider.get("private_key_file")
        private = _validate_private_key(_read_file(path, secret=True))
        result.update(config=None, client_keys=[path])
        certificate_path = provider.get("certificate_file")
        if certificate_path:
            _validate_certificate(_read_file(certificate_path), private, username, provider)
            result["client_certs"] = [certificate_path]
        yield result
        return
    if kind not in ("vault-kv", "vault-ssh"):
        raise CredentialError("unsupported SSH credential provider")
    # Secret files are never shared between connections, and are removed even
    # when a connection fails or is cancelled by an administrator.
    with tempfile.TemporaryDirectory(prefix="isolate-ssh-", dir=options.get("temporary_directory")) as directory:
        os.chmod(directory, 0o700)
        result["config"] = None
        if kind == "vault-kv":
            mount, path = provider.get("mount", "secret"), provider.get("path", "")
            secret = _vault_request(provider, "{}/data/{}".format(mount, path)).get("data")
            field = provider.get("field", "private_key")
            if not isinstance(secret, dict) or not isinstance(secret.get(field), str):
                raise CredentialError("Vault private key field is missing")
            material = secret[field].encode()
            _validate_private_key(material)
            result["client_keys"] = [_write_secret(directory, "key", material)]
        else:
            if (not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", username)
                    or not identity.get("keycloak_sub") or not connection_id):
                raise CredentialError("a policy-selected SSH account and verified session identity are required")
            # A pinned signing CA is mandatory even though the Vault transport
            # also has TLS authentication. Wrong role/signing configuration
            # must not silently produce a usable credential.
            _read_file(provider.get("ca_public_key_file"))
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private = Ed25519PrivateKey.generate()
            material = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                            serialization.NoEncryption())
            key_path = _write_secret(directory, "key", material)
            key_id = "isolate:{}:{}".format(identity["keycloak_sub"], connection_id)
            if len(key_id) > 512 or any(ord(char) < 33 or ord(char) > 126 for char in key_id):
                raise CredentialError("invalid SSH certificate attribution identity")
            ttl = int(provider.get("ttl_seconds", 300))
            if not 30 <= ttl <= 3600:
                raise CredentialError("SSH certificate TTL must be between 30 and 3600 seconds")
            payload = {"public_key": _public_bytes(private.public_key()).decode(), "cert_type": "user",
                       "valid_principals": username, "key_id": key_id, "ttl": "{}s".format(ttl)}
            path = "{}/sign/{}".format(provider.get("mount", "ssh"), provider.get("role", ""))
            signed = _vault_request(provider, path, payload).get("signed_key")
            if not isinstance(signed, str):
                raise CredentialError("Vault did not return an SSH certificate")
            _validate_certificate(signed.encode(), private, username, provider, key_id)
            result["client_keys"] = [key_path]
            result["client_certs"] = [_write_secret(directory, "key-cert.pub", signed.encode())]
        yield result
