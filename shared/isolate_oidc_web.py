"""Authlib adapter using only validated discovery and bounded HTTPS requests."""
from isolate_identity import IdentityError


def configure_browser_provider(remote, provider):
    import os
    import tempfile
    from authlib.integrations.requests_client import OAuth2Session
    from isolate_oidc import discover_provider, read_client_secret, validate_endpoint, _protected_file
    metadata = dict(discover_provider(provider))
    if not metadata.get("authorization_endpoint") or not metadata.get("token_endpoint"):
        raise IdentityError("OIDC provider does not support browser authorization code login")
    if "S256" not in metadata.get("code_challenge_methods_supported", []):
        raise IdentityError("OIDC browser login requires advertised PKCE S256 support")
    algorithms = [alg for alg in metadata.get("id_token_signing_alg_values_supported", ["RS256"])
                  if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")]
    if not algorithms:
        raise IdentityError("OIDC provider does not advertise supported asymmetric ID-token signing")
    metadata["id_token_signing_alg_values_supported"] = algorithms
    metadata.pop("jwks", None)

    class StrictOIDCSession(OAuth2Session):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.trust_env = False
            self._isolate_ca = None
            ca = provider.get("ca_file") or provider.get("ca_bundle")
            if ca:
                material = _protected_file(ca, 1048576)
                descriptor, self._isolate_ca = tempfile.mkstemp(prefix="isolate-oidc-ca-", suffix=".pem")
                with os.fdopen(descriptor, "wb") as output:
                    output.write(material)

        def close(self):
            try:
                super().close()
            finally:
                if self._isolate_ca:
                    os.unlink(self._isolate_ca)
                    self._isolate_ca = None

        def request(self, method, url, **kwargs):
            validate_endpoint(provider, url)
            kwargs.update(allow_redirects=False, stream=True,
                          verify=self._isolate_ca or True,
                          timeout=(float(provider.get("http_connect_timeout", 2)), float(provider.get("http_read_timeout", 3))))
            response = super().request(method, url, **kwargs)
            if 300 <= response.status_code < 400:
                response.close()
                raise IdentityError("OIDC redirects are not allowed")
            try:
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 2097152:
                        raise IdentityError("OIDC response exceeds the allowed size")
                response._content = bytes(content)
                response._content_consumed = True
                return response
            finally:
                response.close()

    remote.client_cls = StrictOIDCSession
    remote.client_secret = read_client_secret(provider)
    remote.server_metadata_url = None
    remote.server_metadata.clear()
    remote.server_metadata.update(metadata)
    remote.client_kwargs["code_challenge_method"] = "S256"
    remote.client_kwargs["token_endpoint_auth_method"] = provider.get("token_endpoint_auth_method", "client_secret_basic" if remote.client_secret else "none")
    return metadata
