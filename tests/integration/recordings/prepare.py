"""Generate an isolated CA and a verified MinIO HTTPS endpoint."""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    fixtures = Path("/fixtures")
    certificates = fixtures / "minio-certs"
    certificates.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolate recording test CA")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(key, hashes.SHA256()))
    (fixtures / "ca.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "minio")])
    leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("minio")]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(key, hashes.SHA256()))
    (certificates / "public.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private = certificates / "private.key"
    private.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)
    print("Generated isolated test CA and MinIO leaf; HTTPS verification remains enabled", flush=True)


if __name__ == "__main__":
    main()
