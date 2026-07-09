"""Tests for Resolve Response producer signing."""

import inspect

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from idpyoidc.message import Message

from fedservice.entity.server import resolve as resolve_endpoint
from fedservice.entity.server.resolve import Resolve
from fedservice.entity_statement.create import create_resolve_response
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.key_resolver import KeyJarResolver
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE


ISSUER = "https://resolver.example.org"
SUBJECT = "https://subject.example.org"
TRUST_ANCHOR = "https://trust-anchor.example.org"


def keyjar_with_signing_key():
    key = new_rsa_key(kid="key-1")
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    return key_jar


def resolve_metadata():
    return {"federation_entity": {"contacts": ["ops@example.org"]}}


def trust_chain():
    return ["leaf.jwt", "intermediate.jwt", "anchor.jwt"]


def test_create_resolve_response_emits_resolve_response_typ():
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=keyjar_with_signing_key(),
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
    )

    assert decode_protected_header(token)["typ"] == "resolve-response+jwt"


def test_create_resolve_response_verifies_with_resolve_profile():
    key_jar = keyjar_with_signing_key()
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.profile is RESOLVE_RESPONSE
    assert isinstance(verified.message(), Message)


def test_create_resolve_response_payload_uses_requested_subject():
    key_jar = keyjar_with_signing_key()
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["sub"] == SUBJECT


def test_create_resolve_response_preserves_trust_marks():
    key_jar = keyjar_with_signing_key()
    trust_marks = [
        {
            "trust_mark_type": "https://trust.example.org/mark",
            "trust_mark": "compact.trust.mark",
        }
    ]
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        trust_marks=trust_marks,
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_resolver=KeyJarResolver(key_jar),
    )

    assert verified.claims()["trust_marks"] == tuple(
        {"trust_mark_type": item["trust_mark_type"], "trust_mark": item["trust_mark"]}
        for item in trust_marks
    )


def test_resolve_endpoint_no_longer_uses_entity_configuration_producer():
    source = inspect.getsource(resolve_endpoint)

    assert "create_entity_configuration" not in source
    assert "create_resolve_response" in source


def test_resolve_endpoint_content_type_remains_resolve_response_jwt():
    assert Resolve.response_content_type == "application/resolve-response+jwt"
