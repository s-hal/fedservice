"""Tests for the Federation JWT profile model."""

from dataclasses import FrozenInstanceError

import pytest
from idpyoidc.message import Message

from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt.claims import validate_iat_not_in_future
from fedservice.federation_jwt import registry


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def test_profile_carries_required_fields():
    profile = make_profile()

    assert profile.name == "entity_configuration"
    assert profile.typ == "entity-statement+jwt"
    assert profile.content_type == "application/entity-statement+jwt"
    assert profile.message_cls is Message


def test_profile_default_header_policy_values():
    profile = make_profile()

    assert profile.required_headers == frozenset({"alg", "kid", "typ"})
    assert profile.allowed_crit_headers == frozenset()
    assert profile.allow_b64_false is False


def test_profile_default_algorithm_policy_values():
    profile = make_profile()

    assert profile.allowed_algs == frozenset(
        {
            "RS256",
            "ES256",
            "ES384",
            "ES512",
            "EdDSA",
        }
    )


def test_profile_default_forbidden_headers():
    profile = make_profile()

    assert profile.forbidden_headers == frozenset({"jku", "jwk", "x5u", "x5c"})


def test_profile_default_empty_payload_validators():
    profile = make_profile()

    assert profile.payload_validators == ()
    assert isinstance(profile.payload_validators, tuple)


def test_accepts_typ_accepts_exact_configured_typ():
    profile = make_profile()

    assert profile.accepts_typ("entity-statement+jwt") is True


@pytest.mark.parametrize("typ", [None, "trust-mark+jwt", "ENTITY-STATEMENT+JWT"])
def test_accepts_typ_rejects_none_and_wrong_typ_values(typ):
    profile = make_profile()

    assert profile.accepts_typ(typ) is False


def test_profile_is_immutable():
    profile = make_profile()

    with pytest.raises(FrozenInstanceError):
        profile.typ = "other+jwt"


def test_future_iat_validator_is_attached_only_to_required_profiles():
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
