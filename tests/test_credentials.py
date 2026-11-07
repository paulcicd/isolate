"""Credential provider isolation and SSH certificate validation tests."""

import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import SSHCertificateBuilder, SSHCertificateType
import isolate_credentials as credentials


def private_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())


def public_bytes(key):
    return key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)


class CredentialTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = self.directory.name
        self.key = Ed25519PrivateKey.generate()
        self.ca = Ed25519PrivateKey.generate()
        self.key_path = self.write("key", private_bytes(self.key), secret=True)
        self.ca_path = self.write("ca.pub", public_bytes(self.ca.public_key()))
        self.known_hosts = self.write("known_hosts", b"# centrally pinned target host keys\n")
        self.ssh_config = self.write("ssh_config", ("Host *\n IdentityFile {}\n".format(self.key_path)).encode())
        self.host = {"server_id": "10001", "remote_user": "support"}
        self.identity = {"keycloak_sub": "alice-sub"}
        self.config = {"data_root": self.root, "ssh": {"config_path": self.ssh_config},
                       "credentials": {"known_hosts": self.known_hosts}}

    def write(self, name, data, secret=False):
        path = os.path.join(self.root, name)
        with open(path, "wb") as output:
            output.write(data)
        os.chmod(path, 0o600 if secret else 0o644)
        return path

    def provider(self, kind, **options):
        provider = {"type": kind, **options}
        self.config["credentials"].update(default="primary", providers={"primary": provider})
        return provider

    def context(self):
        return credentials.ssh_credentials(self.config, self.host, self.identity, "connection-1")

    def test_legacy_openssh_config_and_target_key_selection_remain_server_owned(self):
        self.host.update(credential_provider="attacker", private_key_file="/bad", known_hosts=None)
        with self.context() as options:
            self.assertEqual(options["config"], [self.ssh_config])
            self.assertEqual(options["known_hosts"], self.known_hosts)
            self.assertIsNone(options["agent_path"])
        self.provider("file", private_key_file=self.key_path)
        with self.context() as options:
            self.assertEqual(options["client_keys"], [self.key_path])
            self.assertIsNone(options["config"])
        self.config["credentials"]["targets"] = {"10001": "missing"}
        with self.assertRaises(credentials.CredentialError):
            with self.context():
                pass

    def test_missing_host_key_trust_and_invalid_secret_files_fail_closed(self):
        self.config["credentials"]["known_hosts"] = os.path.join(self.root, "missing")
        with self.assertRaises(credentials.CredentialError):
            with self.context():
                pass
        self.config["credentials"]["known_hosts"] = self.known_hosts
        self.provider("file", private_key_file=self.write("bad-key", b"not a key", secret=True))
        with self.assertRaisesRegex(credentials.CredentialError, "private key"):
            with self.context():
                pass

    def test_vault_key_is_validated_isolated_and_removed_on_failure(self):
        self.provider("vault-kv", mount="secret", path="isolate/key", allowed_paths=["secret/data/isolate/key"])
        with mock.patch.object(credentials, "_vault_request", return_value={"data": {"private_key": private_bytes(self.key).decode()}}) as call:
            with self.context() as options:
                key_path = options["client_keys"][0]
                self.assertNotEqual(key_path, self.key_path)
                self.assertTrue(os.path.isfile(key_path))
                if os.name == "posix":
                    self.assertEqual(os.stat(key_path).st_mode & 0o777, 0o600)
                    self.assertEqual(os.stat(os.path.dirname(key_path)).st_mode & 0o777, 0o700)
            self.assertFalse(os.path.exists(key_path))
            with self.assertRaisesRegex(RuntimeError, "disconnect"):
                with self.context() as options:
                    other = options["client_keys"][0]
                    raise RuntimeError("disconnect")
            self.assertFalse(os.path.exists(other))
            self.assertEqual(call.call_args.args[1], "secret/data/isolate/key")

    def signer(self, provider, path, payload):
        key = serialization.load_ssh_public_key(payload["public_key"].encode())
        now = int(time.time())
        certificate = (SSHCertificateBuilder().public_key(key).serial(1).type(SSHCertificateType.USER)
                       .key_id(payload["key_id"].encode()).valid_principals([payload["valid_principals"].encode()])
                       .valid_after(now - 1).valid_before(now + 250).sign(self.ca))
        return {"signed_key": certificate.public_bytes().decode()}

    def test_vault_certificate_uses_fresh_key_bound_to_identity_session_and_principal(self):
        self.provider("vault-ssh", mount="ssh", role="operators", allowed_paths=["ssh/sign/operators"],
                      ca_public_key_file=self.ca_path, ttl_seconds=300)
        with mock.patch.object(credentials, "_vault_request", side_effect=self.signer) as call:
            with self.context() as options:
                key_path, cert_path = options["client_keys"][0], options["client_certs"][0]
                self.assertTrue(os.path.isfile(cert_path))
                with open(key_path, "rb") as source:
                    self.assertNotEqual(source.read(), private_bytes(self.key))
                payload = call.call_args.args[2]
                self.assertEqual(payload["valid_principals"], "support")
                self.assertEqual(payload["key_id"], "isolate:alice-sub:connection-1")
                self.assertEqual(payload["ttl"], "300s")
                self.assertEqual(call.call_args.args[1], "ssh/sign/operators")
            self.assertFalse(os.path.exists(key_path))
            self.assertFalse(os.path.exists(cert_path))

    def test_certificate_wrong_ca_principal_key_id_lifetime_and_key_are_rejected(self):
        provider = self.provider("vault-ssh", ca_public_key_file=self.ca_path)
        now = int(time.time())
        for change in ("ca", "principal", "id", "lifetime", "key", "expired", "future"):
            ca = Ed25519PrivateKey.generate() if change == "ca" else self.ca
            key = Ed25519PrivateKey.generate() if change == "key" else self.key
            certificate = (SSHCertificateBuilder().public_key(key.public_key()).serial(1).type(SSHCertificateType.USER)
                           .key_id(b"other" if change == "id" else b"isolate:alice-sub:connection-1")
                           .valid_principals([b"root" if change == "principal" else b"support"])
                           .valid_after(now + 1 if change == "future" else now - 10)
                           .valid_before(now - 1 if change == "expired" else now + (600 if change == "lifetime" else 250))
                           .sign(ca))
            with self.subTest(change=change), self.assertRaises(credentials.CredentialError):
                credentials._validate_certificate(certificate.public_bytes(), self.key, "support", provider,
                                                  "isolate:alice-sub:connection-1", now)

    def test_vault_only_accepts_verified_https_and_explicit_safe_paths(self):
        token = self.write("token", b"vault-token", secret=True)
        provider = {"address": "https://vault.example", "token_file": token, "allowed_paths": ["ssh/sign/operators"]}
        for path in ("ssh/sign/other", "ssh/../token", "ssh/sign/%2Foperators", "ssh//operators"):
            with self.subTest(path=path), self.assertRaises(credentials.CredentialError):
                credentials._vault_path(provider, path)
        for address in ("http://vault.example", "https://user:pass@vault.example", "https://vault.example/prefix"):
            with self.subTest(address=address), self.assertRaises(credentials.CredentialError):
                credentials._vault_request(dict(provider, address=address), "ssh/sign/operators")
        with mock.patch.object(credentials.request, "build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b'{"data":{"signed_key":"certificate"}}'
            result = credentials._vault_request(provider, "ssh/sign/operators", {"ttl": "300s"})
            self.assertEqual(result, {"signed_key": "certificate"})
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, "https://vault.example/v1/ssh/sign/operators")
            self.assertEqual(req.get_header("X-vault-token"), "vault-token")
            self.assertEqual(req.get_method(), "POST")
        redirect = credentials._NoRedirect()
        self.assertIsNone(redirect.redirect_request(None, None, 302, "", {}, "https://attacker.example"))


if __name__ == "__main__":
    unittest.main()
