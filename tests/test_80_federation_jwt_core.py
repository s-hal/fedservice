"""Core public contracts for Federation JWT profiles and the registry."""

from collections.abc import Mapping
from dataclasses import FrozenInstanceError

from idpyoidc.message import Message
import pytest

from fedservice.federation_jwt import registry
from fedservice.federation_jwt.claims import validate_iat_not_in_future
from fedservice.federation_jwt.claims import validate_subordinate_statement_relationship
from fedservice.federation_jwt.errors import FederationJwtError
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtProfileError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.message import EntityConfiguration
from fedservice.message import ExplicitRegistrationResponse
from fedservice.message import HistoricalKeysResponse
from fedservice.message import JWKSet
from fedservice.message import ResolveResponse
from fedservice.message import SubordinateStatement
from fedservice.message import TrustMark
from fedservice.message import TrustMarkDelegation
from fedservice.message import TrustMarkStatusResponse


PROFILE_CONSTANTS = (
    registry.ENTITY_CONFIGURATION,
    registry.SUBORDINATE_STATEMENT,
    registry.RESOLVE_RESPONSE,
    registry.TRUST_MARK,
    registry.TRUST_MARK_DELEGATION,
    registry.TRUST_MARK_STATUS_RESPONSE,
    registry.SIGNED_JWK_SET,
    registry.HISTORICAL_KEYS_RESPONSE,
    registry.EXPLICIT_REGISTRATION_RESPONSE,
)

EXPECTED_PROFILES = (
    (
        "entity_configuration",
        "entity-statement+jwt",
        "application/entity-statement+jwt",
        EntityConfiguration,
    ),
    (
        "subordinate_statement",
        "entity-statement+jwt",
        "application/entity-statement+jwt",
        SubordinateStatement,
    ),
    (
        "resolve_response",
        "resolve-response+jwt",
        "application/resolve-response+jwt",
        ResolveResponse,
    ),
    (
        "trust_mark",
        "trust-mark+jwt",
        "application/trust-mark+jwt",
        TrustMark,
    ),
    (
        "trust_mark_delegation",
        "trust-mark-delegation+jwt",
        "application/trust-mark-delegation+jwt",
        TrustMarkDelegation,
    ),
    (
        "trust_mark_status_response",
        "trust-mark-status-response+jwt",
        "application/trust-mark-status-response+jwt",
        TrustMarkStatusResponse,
    ),
    (
        "signed_jwk_set",
        "jwk-set+jwt",
        "application/jwk-set+jwt",
        JWKSet,
    ),
    (
        "historical_keys_response",
        "jwk-set+jwt",
        "application/jwk-set+jwt",
        HistoricalKeysResponse,
    ),
    (
        "explicit_registration_response",
        "explicit-registration-response+jwt",
        "application/explicit-registration-response+jwt",
        ExplicitRegistrationResponse,
    ),
)


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def test_profile_carries_protocol_object_values():
    profile = make_profile()

    assert profile.name == "entity_configuration"
    assert profile.typ == "entity-statement+jwt"
    assert profile.content_type == "application/entity-statement+jwt"
    assert profile.message_cls is Message


def test_profile_default_jose_policy():
    profile = make_profile()

    assert profile.required_headers == frozenset({"alg", "kid", "typ"})
    assert profile.allowed_algs == frozenset(
        {"RS256", "ES256", "ES384", "ES512", "EdDSA"}
    )
    assert profile.forbidden_headers == frozenset({"jku", "jwk", "x5u", "x5c"})
    assert profile.allowed_crit_headers == frozenset()
    assert profile.payload_validators == ()


@pytest.mark.parametrize(
    "typ,accepted",
    [
        ("entity-statement+jwt", True),
        (None, False),
        ("trust-mark+jwt", False),
        ("ENTITY-STATEMENT+JWT", False),
    ],
)
def test_profile_accepts_only_exact_typ(typ, accepted):
    assert make_profile().accepts_typ(typ) is accepted


def test_profile_is_immutable():
    profile = make_profile()

    with pytest.raises(FrozenInstanceError):
        profile.typ = "other+jwt"


def test_registry_contains_canonical_profiles_in_public_order():
    assert registry.ALL_PROFILES == PROFILE_CONSTANTS
    assert len({profile.name for profile in registry.ALL_PROFILES}) == len(
        registry.ALL_PROFILES
    )

    for profile, expected in zip(registry.ALL_PROFILES, EXPECTED_PROFILES):
        name, typ, content_type, message_cls = expected
        assert isinstance(profile, FederationJwtProfile)
        assert profile.name == name
        assert profile.typ == typ
        assert profile.content_type == content_type
        assert profile.message_cls is message_cls


def test_profiles_with_shared_wire_values_remain_distinct():
    assert registry.ENTITY_CONFIGURATION is not registry.SUBORDINATE_STATEMENT
    assert registry.ENTITY_CONFIGURATION.typ == registry.SUBORDINATE_STATEMENT.typ
    assert (
        registry.ENTITY_CONFIGURATION.content_type
        == registry.SUBORDINATE_STATEMENT.content_type
    )

    assert registry.SIGNED_JWK_SET is not registry.HISTORICAL_KEYS_RESPONSE
    assert registry.SIGNED_JWK_SET.typ == registry.HISTORICAL_KEYS_RESPONSE.typ
    assert (
        registry.SIGNED_JWK_SET.content_type
        == registry.HISTORICAL_KEYS_RESPONSE.content_type
    )


def test_profile_name_lookup_returns_canonical_objects():
    for profile in registry.ALL_PROFILES:
        assert registry.get_profile_by_name(profile.name) is profile

    with pytest.raises(FederationJwtProfileError, match="missing"):
        registry.get_profile_by_name("missing")


def test_content_type_lookup_returns_canonical_groups():
    assert registry.get_profiles_by_content_type(
        "application/resolve-response+jwt"
    ) == (registry.RESOLVE_RESPONSE,)
    assert registry.get_profiles_by_content_type(
        "application/entity-statement+jwt"
    ) == (registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT)
    assert registry.get_profiles_by_content_type("application/jwk-set+jwt") == (
        registry.SIGNED_JWK_SET,
        registry.HISTORICAL_KEYS_RESPONSE,
    )

    with pytest.raises(FederationJwtProfileError, match=r"application/missing\+jwt"):
        registry.get_profiles_by_content_type("application/missing+jwt")


def test_registry_mappings_are_immutable():
    assert isinstance(registry.ALL_PROFILES, tuple)
    assert isinstance(registry.PROFILES_BY_NAME, Mapping)
    assert isinstance(registry.PROFILES_BY_CONTENT_TYPE, Mapping)
    assert set(registry.PROFILES_BY_NAME) == {
        profile.name for profile in registry.ALL_PROFILES
    }
    for profile in registry.ALL_PROFILES:
        assert registry.PROFILES_BY_NAME[profile.name] is profile
        assert profile in registry.PROFILES_BY_CONTENT_TYPE[profile.content_type]

    with pytest.raises(TypeError):
        registry.PROFILES_BY_NAME["new"] = registry.RESOLVE_RESPONSE
    with pytest.raises(TypeError):
        registry.PROFILES_BY_CONTENT_TYPE["new"] = (registry.RESOLVE_RESPONSE,)


def test_future_iat_validator_is_attached_to_required_profiles():
    required = {
        registry.ENTITY_CONFIGURATION,
        registry.SUBORDINATE_STATEMENT,
        registry.TRUST_MARK,
        registry.TRUST_MARK_DELEGATION,
        registry.EXPLICIT_REGISTRATION_RESPONSE,
    }

    for profile in registry.ALL_PROFILES:
        assert (validate_iat_not_in_future in profile.payload_validators) is (
            profile in required
        )


def test_subordinate_statement_relationship_validator_is_profile_specific():
    assert validate_subordinate_statement_relationship in (
        registry.SUBORDINATE_STATEMENT.payload_validators
    )
    assert validate_subordinate_statement_relationship not in (
        registry.ENTITY_CONFIGURATION.payload_validators
    )


def test_subordinate_statement_relationship_validator_rejects_self_issued_payload():
    validate_subordinate_statement_relationship(
        {"iss": "https://superior.example.org", "sub": "https://subject.example.org"},
        now=0,
        skew=0,
    )

    with pytest.raises(ValueError):
        validate_subordinate_statement_relationship(
            {"iss": "https://entity.example.org", "sub": "https://entity.example.org"},
            now=0,
            skew=0,
        )


def test_federation_jwt_exception_hierarchy():
    assert issubclass(FederationJwtError, ValueError)

    for error_cls in (
        FederationJwtHeaderError,
        FederationJwtSignatureError,
        FederationJwtKeyResolutionError,
        FederationJwtPayloadError,
        FederationJwtProfileError,
    ):
        assert issubclass(error_cls, FederationJwtError)
