"""Offline bearer authenticator retaining only configured SHA-256 token hashes."""

from __future__ import annotations

import hashlib
import hmac

from labcourt.contracts.m8_api import (
    M8ApiCredentialCatalogAuthorityV1,
    M8ApiPrincipalV1,
)
from labcourt.ports.m8_api_authentication import (
    M8AuthenticationError,
    M8AuthenticationFailureCode,
)

_MAX_AUTHORIZATION_HEADER_BYTES = 4096


class M8HashedBearerAuthenticator:
    """Authenticate an exact bearer secret without retaining or logging plaintext."""

    def __init__(self, catalog: M8ApiCredentialCatalogAuthorityV1) -> None:
        if not isinstance(catalog, M8ApiCredentialCatalogAuthorityV1):
            raise TypeError("M8 API requires a typed credential catalog")
        self._catalog = catalog

    def authenticate(self, authorization_header: str | None) -> M8ApiPrincipalV1:
        if authorization_header is None:
            raise M8AuthenticationError(M8AuthenticationFailureCode.AUTHENTICATION_REQUIRED)
        if not isinstance(authorization_header, str):
            raise M8AuthenticationError(M8AuthenticationFailureCode.INVALID_CREDENTIAL)
        try:
            encoded = authorization_header.encode("ascii")
        except UnicodeEncodeError as error:
            raise M8AuthenticationError(M8AuthenticationFailureCode.INVALID_CREDENTIAL) from error
        prefix = b"Bearer "
        if (
            len(encoded) <= len(prefix)
            or len(encoded) > _MAX_AUTHORIZATION_HEADER_BYTES
            or not encoded.startswith(prefix)
        ):
            raise M8AuthenticationError(M8AuthenticationFailureCode.INVALID_CREDENTIAL)
        token = encoded[len(prefix) :]
        if any(byte <= 32 or byte >= 127 for byte in token):
            raise M8AuthenticationError(M8AuthenticationFailureCode.INVALID_CREDENTIAL)
        supplied_hash = hashlib.sha256(token).hexdigest()
        matched = None
        for credential in self._catalog.credentials:
            if hmac.compare_digest(supplied_hash, credential.bearer_token_sha256):
                matched = credential
        if matched is None or not matched.active:
            raise M8AuthenticationError(M8AuthenticationFailureCode.INVALID_CREDENTIAL)
        return M8ApiPrincipalV1(
            actor_id=matched.actor_id,
            credential_id=matched.credential_id,
            credential_authority_id=matched.credential_authority_id,
            credential_catalog_id=self._catalog.credential_catalog_id,
            authentication_manifest_id=self._catalog.authentication_manifest_id,
        )


__all__ = ["M8HashedBearerAuthenticator"]
