"""Deterministic key resolution helpers for Federation JWT verification."""

from abc import ABC
from abc import abstractmethod
from typing import Iterable
from typing import Mapping
from typing import Optional
from typing import Tuple

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
        context: Optional[object],
    ) -> Tuple[object, ...]:
        """Return candidate verification keys for the supplied token context."""


class StaticKeyResolver(KeyResolver):
    """Resolve candidate keys from an immutable local key sequence."""

    def __init__(self, keys: Iterable[object]):
        self._keys = tuple(keys)

    def resolve(
        self,
        *,
        profile: FederationJwtProfile,
        protected_header: Mapping[str, object],
        untrusted_payload: Mapping[str, object],
        context: Optional[object],
    ) -> Tuple[object, ...]:
        kid = protected_header.get("kid")
        if not isinstance(kid, str) or not kid:
            return ()

        return tuple(
            key for key in self._keys
            if _key_id(key) == kid
        )


def _key_id(key: object) -> Optional[str]:
    """Extract a key identifier from local key-like objects."""
    kid = getattr(key, "kid", None)
    if isinstance(kid, str) and kid:
        return kid

    if isinstance(key, Mapping):
        kid = key.get("kid")
        if isinstance(kid, str) and kid:
            return kid

    serialize = getattr(key, "serialize", None)
    if callable(serialize):
        try:
            serialized = serialize()
        except TypeError:
            serialized = None
        if isinstance(serialized, Mapping):
            kid = serialized.get("kid")
            if isinstance(kid, str) and kid:
                return kid

    return None
