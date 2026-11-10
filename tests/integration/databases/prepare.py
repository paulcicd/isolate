"""Create synthetic, one-day certificates and fixture passwords only."""
import datetime
import ipaddress
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

root = Path('/fixtures')
root.mkdir(exist_ok=True)
root.chmod(0o755)
# Compose may rerun this completed service while the databases retain their TLS
# contexts. Never replace its CA underneath already running database servers.
if (root / '.prepared').exists():
    raise SystemExit(0)
now = datetime.datetime.now(datetime.timezone.utc)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Isolate database fixture CA')])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
    .sign(ca_key, hashes.SHA256()))
(root / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
(root / 'ca.pem').chmod(0o644)
for name, owner, hosts in [('postgres', 70, ['postgres']), ('mysql', 999, ['mysql']), ('frontend', 0, ['localhost', 'db.test'])]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in hosts] + [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
        .sign(ca_key, hashes.SHA256()))
    path = root / (name + '.key')
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    os.chown(path, owner, owner)
    (root / (name + '.pem')).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (root / (name + '.pem')).chmod(0o644)
for name, password in [('postgres-password', 'isolated-postgres-upstream-password'), ('mysql-password', 'isolated-mysql-upstream-password')]:
    path = root / name
    path.write_text(password + '\n')
    path.chmod(0o600)
(root / 'pg_hba.conf').write_text('local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\n')
(root / 'pg_hba.conf').chmod(0o644)
(root / '.prepared').touch()
print('Synthetic database TLS fixtures prepared')
