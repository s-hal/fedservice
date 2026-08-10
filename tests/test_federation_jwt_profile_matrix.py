"""Registry-backed JOSE profile matrix tests."""

from collections.abc import Mapping
from dataclasses import replace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from idpyoidc.message import Message
import pytest

from fedservice.federation_jwt import registry
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import validate_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.verified import VerifiedFederationJwt


@pytest.fixture()
def signing_key():
    return new_rsa_key(kid="matrix-key")


@pytest.fixture(params=registry.ALL_PROFILES, ids=lambda profile: profile.name)
def profile(request):
    return request.param


def payload_for(profile):
    return {
        "iss": "https://issuer.example.org",
        "sub": "https://subject.example.org",
        "iat": 1000,
        "exp": 1600,
        "profile_name": profile.name,
    }


def neutral_profile(profile):
    return replace(profile, message_cls=Message)


def sign_for_profile(profile, signing_key):
    key_jar = KeyJar()
    key_jar.add_keys("https://issuer.example.org", [signing_key])
    return sign_federation_jwt(
        profile=profile,
        payload=payload_for(profile),
        key_jar=key_jar,
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="matrix-key",
        iat=1000,
    )


def thaw(value):
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


def parsed_header(token):
    parsed_jws = jws_factory(token)
    assert parsed_jws is not None
    return dict(parsed_jws.jwt.headers)


def other_profile_with_different_typ(profile):
    for candidate in registry.ALL_PROFILES:
        if candidate.typ != profile.typ:
            return candidate
    raise AssertionError("registry must contain at least two JOSE typ values")


def test_signing_emits_registry_profile_header(profile, signing_key):
    token = sign_for_profile(profile, signing_key)

    header = parsed_header(token)

    assert isinstance(token, str)
    assert len(token.split(".")) == 3
    assert header["typ"] == profile.typ
    assert header["kid"] == "matrix-key"
    assert header["alg"] == "RS256"


def test_profile_header_validation_accepts_matching_registry_profile(
    profile,
    signing_key,
):
    token = sign_for_profile(profile, signing_key)

    header = validate_protected_header(profile, parsed_header(token))

    assert header["typ"] == profile.typ
    assert header["kid"] == "matrix-key"


def test_verify_federation_jwt_accepts_matching_registry_profile(
    profile,
    signing_key,
):
    verification_profile = neutral_profile(profile)
    token = sign_for_profile(profile, signing_key)
    key_jar = KeyJar()
    key_jar.add_keys("https://issuer.example.org", [signing_key])

    verified = verify_federation_jwt(
        profile=verification_profile,
        token=token,
        key_jar=key_jar,
        now=1100,
    )

    assert isinstance(verified, VerifiedFederationJwt)
    assert verified.raw_token() == token
    assert verified.profile == verification_profile
    assert verified.header()["typ"] == profile.typ
    assert verified.header()["kid"] == "matrix-key"
    assert thaw(verified.claims()) == payload_for(profile)
    assert verified.issuer == "https://issuer.example.org"
    assert verified.subject == "https://subject.example.org"
    assert verified.issued_at == 1000
    assert verified.expires_at == 1600


def test_distinct_typ_profile_mismatch_rejects_before_key_resolution(
    profile,
    signing_key,
):
    token = sign_for_profile(profile, signing_key)
    wrong_profile = neutral_profile(other_profile_with_different_typ(profile))

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            profile=wrong_profile,
            token=token,
            key_jar=object(),
            now=1100,
        )


@pytest.mark.parametrize(
    "left,right",
    [
        (registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT),
        (registry.SIGNED_JWK_SET, registry.HISTORICAL_KEYS_RESPONSE),
    ],
    ids=["entity-statement", "jwk-set"],
)
def test_shared_typ_profile_pairs_are_not_distinguished_by_jose_typ(
    left,
    right,
    signing_key,
):
    token = sign_for_profile(left, signing_key)

    assert left is not right
    assert left.typ == right.typ
    assert validate_protected_header(right, parsed_header(token))["typ"] == right.typ


@pytest.mark.parametrize("header_name", ["typ", "kid", "alg"])
def test_signing_rejects_reserved_header_overrides_for_registry_profiles(
    profile,
    header_name,
):
    overrides = {
        "typ": "wrong+jwt",
        "kid": "other-key",
        "alg": "ES256",
    }

    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=profile,
            payload=payload_for(profile),
            key_jar=object(),
            issuer="https://issuer.example.org",
            alg="RS256",
            kid="matrix-key",
            extra_protected_headers={header_name: overrides[header_name]},
        )
