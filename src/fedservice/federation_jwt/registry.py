"""Registry helpers for known Federation JWT profiles."""

from types import MappingProxyType
from typing import Dict
from typing import List
from typing import Mapping
from typing import Tuple

from idpyoidc.message import Message

from fedservice.federation_jwt.errors import FederationJwtProfileError
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.message import EntityConfiguration
from fedservice.message import HistoricalKeysResponse
from fedservice.message import JWKSet
from fedservice.message import ResolveResponse
from fedservice.message import SubordinateStatement
from fedservice.message import TrustMark
from fedservice.message import TrustMarkDelegation
from fedservice.message import TrustMarkStatusResponse


ENTITY_CONFIGURATION = FederationJwtProfile(
    name="entity_configuration",
    typ="entity-statement+jwt",
    content_type="application/entity-statement+jwt",
    message_cls=EntityConfiguration,
)

SUBORDINATE_STATEMENT = FederationJwtProfile(
    name="subordinate_statement",
    typ="entity-statement+jwt",
    content_type="application/entity-statement+jwt",
    message_cls=SubordinateStatement,
)

RESOLVE_RESPONSE = FederationJwtProfile(
    name="resolve_response",
    typ="resolve-response+jwt",
    content_type="application/resolve-response+jwt",
    message_cls=ResolveResponse,
)

TRUST_MARK = FederationJwtProfile(
    name="trust_mark",
    typ="trust-mark+jwt",
    content_type="application/trust-mark+jwt",
    message_cls=TrustMark,
)

# Trust Mark Delegation is not listed in the architecture content-type table;
# this mirrors the profile name and can be adjusted by a future spec-alignment ticket.
TRUST_MARK_DELEGATION = FederationJwtProfile(
    name="trust_mark_delegation",
    typ="trust-mark-delegation+jwt",
    content_type="application/trust-mark-delegation+jwt",
    message_cls=TrustMarkDelegation,
)

TRUST_MARK_STATUS_RESPONSE = FederationJwtProfile(
    name="trust_mark_status_response",
    typ="trust-mark-status-response+jwt",
    content_type="application/trust-mark-status-response+jwt",
    message_cls=TrustMarkStatusResponse,
)

SIGNED_JWK_SET = FederationJwtProfile(
    name="signed_jwk_set",
    typ="jwk-set+jwt",
    content_type="application/jwk-set+jwt",
    message_cls=JWKSet,
)

HISTORICAL_KEYS_RESPONSE = FederationJwtProfile(
    name="historical_keys_response",
    typ="jwk-set+jwt",
    content_type="application/jwk-set+jwt",
    message_cls=HistoricalKeysResponse,
)

# Placeholder until message.py grows a dedicated Explicit Registration Response payload class.
EXPLICIT_REGISTRATION_RESPONSE = FederationJwtProfile(
    name="explicit_registration_response",
    typ="explicit-registration-response+jwt",
    content_type="application/explicit-registration-response+jwt",
    message_cls=Message,
)

ALL_PROFILES: Tuple[FederationJwtProfile, ...] = (
    ENTITY_CONFIGURATION,
    SUBORDINATE_STATEMENT,
    RESOLVE_RESPONSE,
    TRUST_MARK,
    TRUST_MARK_DELEGATION,
    TRUST_MARK_STATUS_RESPONSE,
    SIGNED_JWK_SET,
    HISTORICAL_KEYS_RESPONSE,
    EXPLICIT_REGISTRATION_RESPONSE,
)

PROFILES_BY_NAME: Mapping[str, FederationJwtProfile] = MappingProxyType(
    {profile.name: profile for profile in ALL_PROFILES}
)

_content_type_profiles: Dict[str, List[FederationJwtProfile]] = {}
for profile in ALL_PROFILES:
    _content_type_profiles.setdefault(profile.content_type, []).append(profile)

PROFILES_BY_CONTENT_TYPE: Mapping[
    str,
    Tuple[FederationJwtProfile, ...],
] = MappingProxyType(
    {
        content_type: tuple(profiles)
        for content_type, profiles in _content_type_profiles.items()
    }
)


def get_profile_by_name(name: str) -> FederationJwtProfile:
    """Return the canonical profile for a registry name."""
    try:
        return PROFILES_BY_NAME[name]
    except KeyError as err:
        raise FederationJwtProfileError(
            "Unknown Federation JWT profile name: {}".format(name)
        ) from err


def get_profiles_by_content_type(
    content_type: str,
) -> Tuple[FederationJwtProfile, ...]:
    """Return canonical profiles for a successful response content type."""
    try:
        return PROFILES_BY_CONTENT_TYPE[content_type]
    except KeyError as err:
        raise FederationJwtProfileError(
            "Unknown Federation JWT profile content type: {}".format(content_type)
        ) from err
