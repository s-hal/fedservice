"""Tests for KeyJar-backed Federation JWT signing adapters."""

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
import pytest

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt.signing import sign_federation_jwt_with_keyjar
from idpyoidc.message import Message


ISSUER = "https://issuer.example.org"


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def payload():
    return {
        "iss": ISSUER,
        "sub": ISSUER,
        "iat": 1700000000,
        "exp": 1700000600,
    }


def keyjar_with_keys(*keys):
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, list(keys))
    return key_jar


@pytest.fixture()
def signing_key():
    return new_rsa_key(kid="key-1")


def test_sign_federation_jwt_with_keyjar_signs_compact_jwt(signing_key):
    token = sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=keyjar_with_keys(signing_key),
        issuer=ISSUER,
        alg="RS256",
    )

    assert token.count(".") == 2
    assert decode_protected_header(token)["typ"] == "entity-statement+jwt"


def test_sign_federation_jwt_with_keyjar_honors_explicit_kid(signing_key):
    other_key = new_rsa_key(kid="key-2")
    token = sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=keyjar_with_keys(signing_key, other_key),
        issuer=ISSUER,
        alg="RS256",
        kid="key-2",
    )

    assert decode_protected_header(token)["kid"] == "key-2"


def test_sign_federation_jwt_with_keyjar_is_deterministic(signing_key):
    kwargs = {
        "profile": make_profile(),
        "payload": payload(),
        "key_jar": keyjar_with_keys(signing_key),
        "issuer": ISSUER,
        "alg": "RS256",
    }

    assert sign_federation_jwt_with_keyjar(**kwargs) == sign_federation_jwt_with_keyjar(
        **kwargs
    )


def test_sign_federation_jwt_with_keyjar_missing_key_raises_federation_error():
    with pytest.raises(FederationJwtKeyResolutionError):
        sign_federation_jwt_with_keyjar(
            profile=make_profile(),
            payload=payload(),
            key_jar=KeyJar(),
            issuer=ISSUER,
            alg="RS256",
        )


def test_sign_federation_jwt_with_keyjar_reuses_reserved_header_validation(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt_with_keyjar(
            profile=make_profile(),
            payload=payload(),
            key_jar=keyjar_with_keys(signing_key),
            issuer=ISSUER,
            alg="RS256",
            extra_protected_headers={"typ": "trust-mark+jwt"},
        )


def test_sign_federation_jwt_with_keyjar_does_not_mutate_keyjar(signing_key):
    key_jar = keyjar_with_keys(signing_key)
    owners_before = tuple(key_jar.owners())
    summary_before = key_jar.key_summary(ISSUER)

    sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=key_jar,
        issuer=ISSUER,
        alg="RS256",
    )

    assert tuple(key_jar.owners()) == owners_before
    assert key_jar.key_summary(ISSUER) == summary_before
