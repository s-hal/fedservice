"""Tests for immutable verified Federation JWT containers."""

from dataclasses import FrozenInstanceError
from types import MappingProxyType

import pytest
from idpyoidc.message import Message

from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt.verified import VerifiedFederationJwt
from fedservice.federation_jwt.verified import create_verified_federation_jwt


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def make_verified(
    protected_header=None,
    payload_json=None,
    parsed_message=None,
    token="eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIifQ.signature",
    token_bytes=b"raw-token-bytes",
):
    if protected_header is None:
        protected_header = {"alg": "RS256", "kid": "key-1"}
    if payload_json is None:
        payload_json = {"iss": "issuer", "sub": "subject"}
    if parsed_message is None:
        parsed_message = Message()

    return create_verified_federation_jwt(
        profile=make_profile(),
        token=token,
        token_bytes=token_bytes,
        protected_header=protected_header,
        payload_json=payload_json,
        parsed_message=parsed_message,
        issuer="issuer",
        subject="subject",
        issued_at=10,
        expires_at=20,
    )


def make_direct_verified(protected_header=None, payload_json=None):
    if protected_header is None:
        protected_header = {"alg": "RS256", "kid": "key-1"}
    if payload_json is None:
        payload_json = {"iss": "issuer", "sub": "subject"}

    return VerifiedFederationJwt(
        profile=make_profile(),
        token="aaa.bbb.ccc",
        token_bytes=b"aaa.bbb.ccc",
        protected_header=protected_header,
        payload_json=payload_json,
        parsed_message=Message(),
    )


def test_raw_token_preserves_exact_compact_jwt_string():
    token = "aaa.bbb.ccc"

    verified = make_verified(token=token)

    assert verified.token == token
    assert verified.raw_token() == token


def test_raw_token_bytes_preserves_exact_bytes():
    token_bytes = b"not-derived-from-token"

    verified = make_verified(token_bytes=token_bytes)

    assert verified.token_bytes == token_bytes
    assert verified.raw_token_bytes() == token_bytes


def test_accessor_methods_return_container_views():
    message = Message()
    verified = make_verified(parsed_message=message)

    assert verified.header() is verified.protected_header
    assert verified.claims() is verified.payload_json
    assert verified.message() is message


def test_verified_container_is_immutable():
    verified = make_verified()

    with pytest.raises(FrozenInstanceError):
        verified.token = "replacement"


def test_verified_container_does_not_expose_to_jwt():
    verified = make_verified()

    assert not hasattr(VerifiedFederationJwt, "to_jwt")
    assert not hasattr(verified, "to_jwt")


def test_nested_protected_header_dictionaries_are_immutable():
    verified = make_verified(
        protected_header={
            "alg": "RS256",
            "kid": "key-1",
            "nested": {"inner": "value"},
        }
    )

    assert isinstance(verified.header(), MappingProxyType)
    assert isinstance(verified.header()["nested"], MappingProxyType)
    with pytest.raises(TypeError):
        verified.header()["nested"]["inner"] = "replacement"


def test_nested_payload_dictionaries_are_immutable():
    verified = make_verified(
        payload_json={
            "iss": "issuer",
            "metadata": {"federation_entity": {"contacts": ["ops@example.org"]}},
        }
    )

    assert isinstance(verified.claims(), MappingProxyType)
    assert isinstance(verified.claims()["metadata"], MappingProxyType)
    with pytest.raises(TypeError):
        verified.claims()["metadata"]["federation_entity"] = {}


def test_lists_are_converted_to_tuples():
    verified = make_verified(payload_json={"trust_marks": ["one", "two"]})

    assert verified.claims()["trust_marks"] == ("one", "two")
    assert isinstance(verified.claims()["trust_marks"], tuple)


def test_sets_are_converted_to_frozensets():
    verified = make_verified(payload_json={"crit": {"one", "two"}})

    assert verified.claims()["crit"] == frozenset({"one", "two"})
    assert isinstance(verified.claims()["crit"], frozenset)


def test_tuples_are_recursively_frozen():
    verified = make_verified(payload_json={"items": ({"name": "one"},)})

    assert isinstance(verified.claims()["items"], tuple)
    assert isinstance(verified.claims()["items"][0], MappingProxyType)
    with pytest.raises(TypeError):
        verified.claims()["items"][0]["name"] = "replacement"


def test_factory_freezes_constructor_inputs():
    protected_header = {"alg": "RS256", "kid": "key-1", "nested": {"x": 1}}
    payload_json = {"iss": "issuer", "nested": {"x": 1}}

    verified = make_verified(
        protected_header=protected_header,
        payload_json=payload_json,
    )
    protected_header["nested"]["x"] = 2
    payload_json["nested"]["x"] = 2

    assert verified.header()["nested"]["x"] == 1
    assert verified.claims()["nested"]["x"] == 1


def test_factory_still_returns_verified_federation_jwt():
    verified = make_verified()

    assert isinstance(verified, VerifiedFederationJwt)


def test_direct_constructor_freezes_nested_header_dictionaries():
    verified = make_direct_verified(
        protected_header={
            "alg": "RS256",
            "kid": "key-1",
            "nested": {"inner": "value"},
        }
    )

    assert isinstance(verified.header(), MappingProxyType)
    assert isinstance(verified.header()["nested"], MappingProxyType)
    with pytest.raises(TypeError):
        verified.header()["nested"]["inner"] = "replacement"


def test_direct_constructor_freezes_nested_payload_dictionaries():
    verified = make_direct_verified(
        payload_json={
            "iss": "issuer",
            "metadata": {"federation_entity": {"contacts": ["ops@example.org"]}},
        }
    )

    assert isinstance(verified.claims(), MappingProxyType)
    assert isinstance(verified.claims()["metadata"], MappingProxyType)
    with pytest.raises(TypeError):
        verified.claims()["metadata"]["federation_entity"] = {}


def test_direct_constructor_converts_header_and_claim_lists_to_tuples():
    verified = make_direct_verified(
        protected_header={"alg": "RS256", "kid": "key-1", "crit": ["one", "two"]},
        payload_json={"trust_marks": ["one", "two"]},
    )

    assert verified.header()["crit"] == ("one", "two")
    assert isinstance(verified.header()["crit"], tuple)
    assert verified.claims()["trust_marks"] == ("one", "two")
    assert isinstance(verified.claims()["trust_marks"], tuple)


def test_direct_constructor_recursively_freezes_tuples():
    verified = make_direct_verified(
        protected_header={"alg": "RS256", "kid": "key-1", "items": ({"name": "h"},)},
        payload_json={"items": ({"name": "p"},)},
    )

    assert isinstance(verified.header()["items"], tuple)
    assert isinstance(verified.header()["items"][0], MappingProxyType)
    assert isinstance(verified.claims()["items"], tuple)
    assert isinstance(verified.claims()["items"][0], MappingProxyType)
    with pytest.raises(TypeError):
        verified.header()["items"][0]["name"] = "replacement"
    with pytest.raises(TypeError):
        verified.claims()["items"][0]["name"] = "replacement"


def test_direct_constructor_converts_header_and_claim_sets_to_frozensets():
    verified = make_direct_verified(
        protected_header={"alg": "RS256", "kid": "key-1", "crit": {"one", "two"}},
        payload_json={"crit": {"one", "two"}},
    )

    assert verified.header()["crit"] == frozenset({"one", "two"})
    assert isinstance(verified.header()["crit"], frozenset)
    assert verified.claims()["crit"] == frozenset({"one", "two"})
    assert isinstance(verified.claims()["crit"], frozenset)


def test_mutating_direct_constructor_inputs_does_not_affect_verified_object():
    protected_header = {
        "alg": "RS256",
        "kid": "key-1",
        "nested": {"x": 1},
        "items": [{"name": "header"}],
    }
    payload_json = {
        "iss": "issuer",
        "nested": {"x": 1},
        "items": [{"name": "payload"}],
    }

    verified = make_direct_verified(
        protected_header=protected_header,
        payload_json=payload_json,
    )
    protected_header["nested"]["x"] = 2
    protected_header["items"][0]["name"] = "changed"
    payload_json["nested"]["x"] = 2
    payload_json["items"][0]["name"] = "changed"

    assert verified.header()["nested"]["x"] == 1
    assert verified.header()["items"][0]["name"] == "header"
    assert verified.claims()["nested"]["x"] == 1
    assert verified.claims()["items"][0]["name"] == "payload"
