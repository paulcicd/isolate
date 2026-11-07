"""Generate a test-only CA, HTTPS leafs and an isolated Keycloak realm."""

import datetime
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    directory = Path('/fixtures')
    directory.mkdir(exist_ok=True)
    if all((directory / name).is_file() for name in ('ca.pem', 'keycloak.pem', 'keycloak.key',
            'runner.pem', 'runner.key', 'isolate-integration-realm.json')):
        print('Reusing this isolated test volume\'s CA and realm', flush=True)
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Isolate integration test CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(key, hashes.SHA256()))
    (directory / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for hostname in ('keycloak', 'runner'):
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca.subject)
                .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(key, hashes.SHA256()))
        (directory / (hostname + '.pem')).write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        private_path = directory / (hostname + '.key')
        private_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
        os.chown(private_path, 1000, 0)
        os.chmod(private_path, 0o600)
    realm = {
        'realm': 'isolate-integration', 'enabled': True, 'sslRequired': 'all',
        'registrationAllowed': False, 'accessTokenLifespan': 600,
        'groups': [{'name': 'Integration-Operators'}],
        'clients': [{
            'clientId': 'isolate-integration', 'enabled': True, 'protocol': 'openid-connect',
            'publicClient': False, 'secret': 'isolated-integration-client-secret',
            'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
            'implicitFlowEnabled': False, 'serviceAccountsEnabled': False,
            'redirectUris': ['https://runner:9443/*'], 'webOrigins': ['https://runner:9443'],
            'frontchannelLogout': False,
            'attributes': {'oauth2.device.authorization.grant.enabled': 'true',
                'post.logout.redirect.uris': '+',
                'backchannel.logout.url': 'https://runner:9443/auth/backchannel-logout',
                'backchannel.logout.session.required': 'true'},
            'protocolMappers': [{'name': 'groups', 'protocol': 'openid-connect',
                'protocolMapper': 'oidc-group-membership-mapper', 'consentRequired': False,
                'config': {'full.path': 'false', 'claim.name': 'groups', 'id.token.claim': 'true',
                           'access.token.claim': 'true', 'userinfo.token.claim': 'true'}}],
        }],
        'users': [{'username': 'alice', 'enabled': True, 'emailVerified': True,
            'firstName': 'Alice', 'lastName': 'Integration', 'email': 'alice@integration.invalid',
            'credentials': [{'type': 'password', 'value': 'isolated-integration-user-password', 'temporary': False}],
            'groups': ['/Integration-Operators']}],
    }
    (directory / 'isolate-integration-realm.json').write_text(json.dumps(realm), encoding='utf-8')
    print('Generated isolated test CA and realm; user password grant is disabled', flush=True)


if __name__ == '__main__':
    main()
