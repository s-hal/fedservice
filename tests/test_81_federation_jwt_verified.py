"""Immutable verified Federation JWT container contracts."""

from dataclasses import FrozenInstanceError
from types import MappingProxyType

from idpyoidc.message import Message
import pytest

from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt.verified import create_verified_federation_jwt
from fedservice.federation_jwt.verified import VerifiedFederationJwt


TOKEN = "aaa.bbb.ccc"
TOKEN_BYTES = b"bytes-preserved-independently"


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def make_verified(construction, protected_header=None, payload_json=None):
    if protected_header is None:
        protected_header = {"alg": "RS256", "kid": "key-1"}
    if payload_json is None:
        payload_json = {"iss": "issuer", "sub": "subject"}

    values = {
        "profile": make_profile(),
        "token": TOKEN,
        "token_bytes": TOKEN_BYTES,
        "protected_header": protected_header,
        "payload_json": payload_json,
        "parsed_message": Message(),
        "issuer": "issuer",
        "subject": "subject",
        "issued_at": 10,
        "expires_at": 20,
    }
    if construction == "factory":
        return create_verified_federation_jwt(**values)
    return VerifiedFederationJwt(**values)


@pytest.mark.parametrize("construction", ["factory", "constructor"])
def test_verified_token_preserves_values_and_accessors(construction):
    verified = make_verified(construction)

    assert isinstance(verified, VerifiedFederationJwt)
    assert verified.token == TOKEN
    assert verified.raw_token() == TOKEN
    assert verified.token_bytes == TOKEN_BYTES
    assert verified.raw_token_bytes() == TOKEN_BYTES
    assert verified.profile.name == "entity_configuration"
    assert verified.header() is verified.protected_header
    assert verified.claims() is verified.payload_json
    assert verified.message() is verified.parsed_message
    assert verified.issuer == "issuer"
    assert verified.subject == "subject"
    assert verified.issued_at == 10
    assert verified.expires_at == 20


@pytest.mark.parametrize("construction", ["factory", "constructor"])
def test_verified_token_is_a_frozen_record_without_reserialization(construction):
    verified = make_verified(construction)

    with pytest.raises(FrozenInstanceError):
        verified.token = "replacement"

    assert not hasattr(verified, "to_jwt")


@pytest.mark.parametrize("construction", ["factory", "constructor"])
def test_header_and_claims_are_recursively_frozen(construction):
    verified = make_verified(
        construction,
        protected_header={
            "alg": "RS256",
            "kid": "key-1",
            "nested": {"name": "header"},
            "items": [{"name": "one"}],
            "tuple_items": ({"name": "two"},),
            "crit": {"one", "two"},
        },
        payload_json={
            "iss": "issuer",
            "metadata": {"contacts": ["ops@example.org"]},
            "items": [{"name": "one"}],
            "tuple_items": ({"name": "two"},),
            "labels": {"one", "two"},
        },
    )

    assert isinstance(verified.header(), MappingProxyType)
    assert isinstance(verified.header()["nested"], MappingProxyType)
    assert isinstance(verified.header()["items"], tuple)
    assert isinstance(verified.header()["items"][0], MappingProxyType)
    assert isinstance(verified.header()["tuple_items"], tuple)
    assert isinstance(verified.header()["tuple_items"][0], MappingProxyType)
    assert verified.header()["crit"] == frozenset({"one", "two"})

    assert isinstance(verified.claims(), MappingProxyType)
    assert isinstance(verified.claims()["metadata"], MappingProxyType)
    assert verified.claims()["metadata"]["contacts"] == ("ops@example.org",)
    assert isinstance(verified.claims()["items"], tuple)
    assert isinstance(verified.claims()["items"][0], MappingProxyType)
    assert isinstance(verified.claims()["tuple_items"], tuple)
    assert isinstance(verified.claims()["tuple_items"][0], MappingProxyType)
    assert verified.claims()["labels"] == frozenset({"one", "two"})

    with pytest.raises(TypeError):
        verified.header()["nested"]["name"] = "replacement"
    with pytest.raises(TypeError):
        verified.claims()["metadata"]["new"] = "value"


@pytest.mark.parametrize("construction", ["factory", "constructor"])
def test_constructor_inputs_are_defensively_frozen(construction):
    protected_header = {
        "alg": "RS256",
        "kid": "key-1",
        "nested": {"value": 1},
        "items": [{"name": "header"}],
    }
    payload_json = {
        "iss": "issuer",
        "nested": {"value": 1},
        "items": [{"name": "payload"}],
    }

    verified = make_verified(
        construction,
        protected_header=protected_header,
        payload_json=payload_json,
    )
    protected_header["nested"]["value"] = 2
    protected_header["items"][0]["name"] = "changed"
    payload_json["nested"]["value"] = 2
    payload_json["items"][0]["name"] = "changed"

    assert verified.header()["nested"]["value"] == 1
    assert verified.header()["items"][0]["name"] == "header"
    assert verified.claims()["nested"]["value"] == 1
    assert verified.claims()["items"][0]["name"] == "payload"
