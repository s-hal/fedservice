"""Deterministic key resolution helpers for Federation JWT verification."""

from abc import ABC
from abc import abstractmethod
from typing import Mapping
from typing import Optional
from typing import Tuple

from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.profile import FederationJwtProfile


class KeyResolver(ABC):
    """Deterministic key lookup interface for Federation JWT verification."""

    @abstractmethod
    def resolve(
        self,
        *,
        profile: FederationJwtProfile,
        protected_header: Mapping[str, object],
        untrusted_payload: Mapping[str, object],
        parsed_jwt: object,
        context: Optional[object],
    ) -> Tuple[object, ...]:
        """Return candidate verification keys for the supplied token context."""


class KeyJarResolver(KeyResolver):
    """Resolve candidates through a pre-populated KeyJar-like object.

    Candidate selection is delegated to
    ``keyjar.get_jwt_verify_keys(parsed_jwt)``. This resolver does not inspect
    key objects directly or apply local ``kid`` filtering.
    """

    def __init__(self, keyjar: object):
        self._keyjar = keyjar

    def resolve(
        self,
        *,
        profile: FederationJwtProfile,
        protected_header: Mapping[str, object],
        untrusted_payload: Mapping[str, object],
        parsed_jwt: object,
        context: Optional[object],
    ) -> Tuple[object, ...]:
        try:
            keys = self._keyjar.get_jwt_verify_keys(parsed_jwt)
        except Exception as err:
            raise FederationJwtKeyResolutionError(
                "KeyJar failed to resolve verification keys."
            ) from err

        return tuple(keys or ())


class StaticKeyJarResolver(KeyJarResolver):
    """Resolver for a pre-populated static KeyJar-like object."""


class StaticKeyResolver(StaticKeyJarResolver):
    """Compatibility alias for StaticKeyJarResolver."""
