"""Federation JWT profile definitions and profile-specific policy."""

from dataclasses import dataclass
from dataclasses import field
from typing import Callable
from typing import FrozenSet
from typing import Optional
from typing import Tuple
from typing import Type

from idpyoidc.message import Message


@dataclass(frozen=True)
class FederationJwtProfile:
    """Profile policy for a specific Federation JWT protocol object."""

    name: str
    typ: str
    content_type: str
    message_cls: Type[Message]

    required_headers: FrozenSet[str] = frozenset({"alg", "kid", "typ"})
    allowed_algs: FrozenSet[str] = frozenset(
        {
            "RS256",
            "ES256",
            "ES384",
            "ES512",
            "EdDSA",
        }
    )
    forbidden_headers: FrozenSet[str] = frozenset({"jku", "jwk", "x5u", "x5c"})
    allowed_crit_headers: FrozenSet[str] = frozenset()
    payload_validators: Tuple[Callable[..., object], ...] = field(default_factory=tuple)

    def accepts_typ(self, value: Optional[str]) -> bool:
        """Return whether the provided JOSE typ exactly matches this profile."""
        return value == self.typ
