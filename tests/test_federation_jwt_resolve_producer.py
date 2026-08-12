"""Tests for Resolve Response producer signing."""

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.message import Message

from fedservice.entity_statement.create import create_resolve_response
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE


ISSUER = "https://resolver.example.org"
SUBJECT = "https://subject.example.org"


def keyjar_with_signing_key():
    key = new_rsa_key(kid="key-1")
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    return key_jar


def resolve_metadata():
    return {"federation_entity": {"contacts": ["ops@example.org"]}}


def trust_chain():
    return ["leaf.jwt", "intermediate.jwt", "anchor.jwt"]


def future_exp():
    return utc_time_sans_frac() + 3600


def test_create_resolve_response_emits_resolve_response_typ():
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=keyjar_with_signing_key(),
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=future_exp(),
    )

    assert jws_factory(token).jwt.headers["typ"] == "resolve-response+jwt"


def test_create_resolve_response_verifies_with_resolve_profile():
    key_jar = keyjar_with_signing_key()
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=future_exp(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
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
        expires_at=future_exp(),
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
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
        expires_at=future_exp(),
        trust_marks=trust_marks,
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["trust_marks"] == tuple(
        {"trust_mark_type": item["trust_mark_type"], "trust_mark": item["trust_mark"]}
        for item in trust_marks
    )


def test_create_resolve_response_uses_absolute_expiration_exactly():
    key_jar = keyjar_with_signing_key()
    expires_at = future_exp()
    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=expires_at,
    )

    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["exp"] == expires_at


def test_create_resolve_response_passes_explicit_iat_with_zero_lifetime(monkeypatch):
    issued_at = utc_time_sans_frac()
    expires_at = issued_at + 3600
    monkeypatch.setattr(
        "fedservice.entity_statement.create.utc_time_sans_frac",
        lambda: issued_at,
    )
    key_jar = keyjar_with_signing_key()

    token = create_resolve_response(
        ISSUER,
        sub=SUBJECT,
        key_jar=key_jar,
        metadata=resolve_metadata(),
        trust_chain=trust_chain(),
        expires_at=expires_at,
    )
    verified = verify_federation_jwt(
        profile=RESOLVE_RESPONSE,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["iat"] == issued_at
    assert verified.claims()["exp"] == expires_at
