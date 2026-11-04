"""Configured informational metadata through real EC issuance and verification."""

from copy import deepcopy

import pytest

from fedservice.entity import FederationEntity
from fedservice.federation_jwt import registry
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.verified import deep_freeze
from fedservice.message import FederationEntity as FederationMetadata
from fedservice.utils import build_entity_config
from fedservice.utils import make_federation_entity


OWNER = "https://entity.example.org"
INFORMATIONAL = {
    "organization_name": "Example Organisation",
    "display_name": "Exempel f\u00f6r anv\u00e4ndare",
    "description": "A federation service for research",
    "keywords": ["research", "identity"],
    "contacts": ["Info <info@example.org>"],
    "logo_uri": "https://images.example.org/entity-logo.png",
    "policy_uri": "https://policy.example.org/conditions",
    "information_uri": "https://docs.example.org/entity",
    "organization_uri": "https://organization.example.org/",
    "organization_identifier": "local-federation:organisation-42",
}
LEGACY = {
    "logo_url": "https://legacy.example.org/logo.png",
    "policy_url": "https://legacy.example.org/policy",
    "homepage_uri": "https://legacy.example.org/home",
}


def construct(path, preference=None, owner=OWNER):
    """Exercise both supported configuration paths with generated local keys."""
    options = {
        "entity_id": owner,
        "signing_alg": "ES256",
        "key_config": {"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
        "endpoints": ["entity_configuration", "fetch", "list"],
    }
    if preference is not None:
        options["preference"] = preference
    before = deepcopy(options)
    if path == "direct":
        entity = FederationEntity(**build_entity_config(**options))
    else:
        entity = make_federation_entity(**options)
    assert options == before
    return entity


def published(entity, expected):
    """Check authoritative signed claims and the typed view against explicit values."""
    token = entity.get_endpoint("entity_configuration").process_request({})["response"]
    verified = verify_federation_jwt(registry.ENTITY_CONFIGURATION, token, entity.keyjar)
    assert verified.raw_token() == token
    assert verified.header()["alg"] == "ES256"
    assert not set(INFORMATIONAL).intersection(verified.claims())
    metadata = dict(expected, federation_fetch_endpoint=entity.entity_id + "/fetch",
                    federation_list_endpoint=entity.entity_id + "/list")
    assert verified.claims()["metadata"]["federation_entity"] == deep_freeze(metadata)
    received = verified.message()["metadata"]["federation_entity"]
    assert isinstance(received, FederationMetadata)
    assert received.to_dict() == metadata
    for name in ("fetch", "list"):
        assert received["federation_{}_endpoint".format(name)] == entity.get_endpoint(name).full_path
    assert entity.get_metadata()["federation_entity"] == metadata
    return verified


@pytest.mark.parametrize("path", ["utility", "direct"])
def test_all_configured_informational_values_reach_signed_ec(path):
    preference = deepcopy(INFORMATIONAL)
    before = deepcopy(preference)
    entity = construct(path, preference)
    verified = published(entity, INFORMATIONAL)
    for name in ("contacts", "keywords"):
        assert list(verified.claims()["metadata"]["federation_entity"][name]) == before[name]
        verified.message()["metadata"]["federation_entity"][name].append("local view edit")
    published(entity, INFORMATIONAL)
    assert preference == before


@pytest.mark.parametrize("path", ["utility", "direct"])
@pytest.mark.parametrize("second_preferences", [None, {
    "organization_name": "Independent organisation",
    "contacts": ["Support <support@example.net>"],
}])
def test_informational_omission_and_entity_isolation(path, second_preferences):
    preference = deepcopy(INFORMATIONAL)
    second_preference = deepcopy(second_preferences)
    first = construct(path, preference)
    second = construct(path, second_preference, owner="https://second.example.net")
    published(second, second_preferences or {})
    published(first, INFORMATIONAL)
    published(second, second_preferences or {})
    assert preference == INFORMATIONAL
    assert second_preference == second_preferences


@pytest.mark.parametrize("path", ["utility", "direct"])
@pytest.mark.parametrize("canonical", [False, True])
def test_legacy_names_and_unlisted_preferences_are_not_generated_aliases(path, canonical):
    preference = deepcopy(LEGACY)
    preference["pilot_custom_field"] = "not an extensibility mechanism"
    if canonical:
        preference.update(deepcopy(INFORMATIONAL))
    before = deepcopy(preference)
    published(construct(path, preference), INFORMATIONAL if canonical else {})
    assert preference == before


def test_received_legacy_names_extensions_and_language_tags_remain_unchanged():
    entity = construct("utility")
    payload = published(entity, {}).message().to_dict()
    metadata = dict(LEGACY, **{
        "display_name#sv": "Svenskt visningsnamn",
        "keywords#sv": ["forskning"],
        "extension": {"nested": None},
    })
    payload["metadata"] = {"federation_entity": metadata}
    token = sign_federation_jwt(registry.ENTITY_CONFIGURATION, payload, entity.keyjar,
                                OWNER, "ES256", iat=payload["iat"])
    verified = verify_federation_jwt(registry.ENTITY_CONFIGURATION, token, entity.keyjar)
    assert verified.raw_token() == token
    assert verified.claims()["metadata"]["federation_entity"] == deep_freeze(metadata)
    assert verified.message()["metadata"]["federation_entity"].to_dict() == metadata


def test_received_null_organization_identifier_uses_existing_metadata_rejection():
    entity = construct("utility")
    payload = published(entity, {}).message().to_dict()
    payload["metadata"]["federation_entity"]["organization_identifier"] = None
    token = sign_federation_jwt(registry.ENTITY_CONFIGURATION, payload, entity.keyjar,
                                OWNER, "ES256", iat=payload["iat"])
    with pytest.raises(FederationJwtPayloadError) as caught:
        verify_federation_jwt(registry.ENTITY_CONFIGURATION, token, entity.keyjar)
    assert isinstance(caught.value.__cause__, ValueError)
    assert str(caught.value.__cause__) == (
        "metadata federation_entity parameter organization_identifier must not be null")
