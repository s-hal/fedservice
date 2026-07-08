"""Immutable records for verified Federation JWTs."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping
from typing import Optional

from idpyoidc.message import Message

from fedservice.federation_jwt.profile import FederationJwtProfile


def deep_freeze(value):
    """Recursively convert common mutable containers to immutable containers."""
    if isinstance(value, dict):
        return MappingProxyType(
            {key: deep_freeze(item) for key, item in value.items()}
        )

    if isinstance(value, list):
        return tuple(deep_freeze(item) for item in value)

    if isinstance(value, tuple):
        return tuple(deep_freeze(item) for item in value)

    if isinstance(value, set):
        return frozenset(deep_freeze(item) for item in value)

    return value


@dataclass(frozen=True)
class VerifiedFederationJwt:
    """Immutable record of a verified compact Federation JWT."""

    profile: FederationJwtProfile
    token: str
    token_bytes: bytes
    protected_header: Mapping[str, object]
    payload_json: Mapping[str, object]
    parsed_message: Message
    issuer: Optional[str] = None
    subject: Optional[str] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None

    def raw_token(self) -> str:
        """Return the exact compact JWT string accepted by the verifier."""
        return self.token

    def raw_token_bytes(self) -> bytes:
        """Return the exact compact JWT bytes used internally."""
        return self.token_bytes

    def header(self) -> Mapping[str, object]:
        """Return the recursively frozen protected JOSE header."""
        return self.protected_header

    def claims(self) -> Mapping[str, object]:
        """Return the recursively frozen decoded payload JSON."""
        return self.payload_json

    def message(self) -> Message:
        """Return the parsed message convenience view."""
        return self.parsed_message


def create_verified_federation_jwt(
    profile: FederationJwtProfile,
    token: str,
    token_bytes: bytes,
    protected_header: Mapping[str, object],
    payload_json: Mapping[str, object],
    parsed_message: Message,
    issuer: Optional[str] = None,
    subject: Optional[str] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
) -> VerifiedFederationJwt:
    """Create a verified-token record with recursively frozen JSON views."""
    return VerifiedFederationJwt(
        profile=profile,
        token=token,
        token_bytes=token_bytes,
        protected_header=deep_freeze(dict(protected_header)),
        payload_json=deep_freeze(dict(payload_json)),
        parsed_message=parsed_message,
        issuer=issuer,
        subject=subject,
        issued_at=issued_at,
        expires_at=expires_at,
    )
