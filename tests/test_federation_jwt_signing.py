"""Tests for KeyJar-backed Federation JWT signing adapters."""

from cryptojwt import KeyJar
from cryptojwt.jwk.jwk import key_from_jwk_dict
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


def public_key(key):
    return key_from_jwk_dict(key.serialize(private=False))


class CandidateKeyJar:
    def __init__(self, issuer_keys=(), fallback_keys=()):
        self.issuer_keys = list(issuer_keys)
        self.fallback_keys = list(fallback_keys)

    def get_signing_key(self, key_type, issuer_id, kid=None):
        keys = self.issuer_keys if issuer_id == ISSUER else self.fallback_keys
        if kid is None:
            return list(keys)
        return [key for key in keys if key.kid == kid]


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


def test_signing_selects_private_key_when_public_key_is_also_returned():
    private = new_rsa_key(kid="private-key")
    public = public_key(new_rsa_key(kid="public-key"))
    key_jar = CandidateKeyJar(issuer_keys=[public, private])

    token = sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=key_jar,
        issuer=ISSUER,
        alg="RS256",
    )

    assert decode_protected_header(token)["kid"] == "private-key"


def test_private_key_selection_is_independent_of_candidate_order():
    first = new_rsa_key(kid="a-key")
    second = new_rsa_key(kid="z-key")

    tokens = [
        sign_federation_jwt_with_keyjar(
            profile=make_profile(),
            payload=payload(),
            key_jar=CandidateKeyJar(issuer_keys=keys),
            issuer=ISSUER,
            alg="RS256",
        )
        for keys in ([second, first], [first, second])
    ]

    assert [decode_protected_header(token)["kid"] for token in tokens] == [
        "a-key",
        "a-key",
    ]


def test_duplicate_public_and_private_kid_selects_private_representation():
    private = new_rsa_key(kid="shared-key")
    public = public_key(private)
    key_jar = CandidateKeyJar(issuer_keys=[public, private])

    token = sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=key_jar,
        issuer=ISSUER,
        alg="RS256",
        kid="shared-key",
    )

    assert decode_protected_header(token)["kid"] == "shared-key"


def test_explicit_kid_requires_private_material():
    private = new_rsa_key(kid="private-key")
    public = public_key(new_rsa_key(kid="public-key"))
    key_jar = CandidateKeyJar(issuer_keys=[public, private])

    token = sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=key_jar,
        issuer=ISSUER,
        alg="RS256",
        kid="private-key",
    )

    assert decode_protected_header(token)["kid"] == "private-key"
    with pytest.raises(FederationJwtKeyResolutionError):
        sign_federation_jwt_with_keyjar(
            profile=make_profile(),
            payload=payload(),
            key_jar=key_jar,
            issuer=ISSUER,
            alg="RS256",
            kid="public-key",
        )


def test_issuer_private_key_precedes_empty_owner_private_key():
    issuer_key = new_rsa_key(kid="issuer-key")
    fallback_key = new_rsa_key(kid="fallback-key")
    key_jar = CandidateKeyJar(
        issuer_keys=[issuer_key],
        fallback_keys=[fallback_key],
    )

    token = sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=key_jar,
        issuer=ISSUER,
        alg="RS256",
    )

    assert decode_protected_header(token)["kid"] == "issuer-key"


def test_public_issuer_key_does_not_prevent_private_empty_owner_fallback():
    public = public_key(new_rsa_key(kid="issuer-public"))
    fallback = new_rsa_key(kid="fallback-private")
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [public])
    key_jar.add_keys("", [fallback])

    token = sign_federation_jwt_with_keyjar(
        profile=make_profile(),
        payload=payload(),
        key_jar=key_jar,
        issuer=ISSUER,
        alg="RS256",
    )

    assert decode_protected_header(token)["kid"] == "fallback-private"


def test_public_only_keyjar_fails_closed():
    public = public_key(new_rsa_key(kid="public-only"))
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [public])

    with pytest.raises(FederationJwtKeyResolutionError):
        sign_federation_jwt_with_keyjar(
            profile=make_profile(),
            payload=payload(),
            key_jar=key_jar,
            issuer=ISSUER,
            alg="RS256",
        )
