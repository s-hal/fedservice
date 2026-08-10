"""Tests for Cryptojwt-backed Federation JWT signing."""

import socket

from cryptojwt import KeyJar
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jwt import JWT
from idpyoidc.message import Message
import pytest

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.profile import FederationJwtProfile


ISSUER = "https://issuer.example.org"


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def keyjar_with_keys(*keys):
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, list(keys))
    return key_jar


@pytest.fixture()
def signing_key():
    return new_rsa_key(kid="key-1")


def test_sign_federation_jwt_signs_with_normal_keyjar(signing_key):
    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": ISSUER},
        key_jar=keyjar_with_keys(signing_key),
        issuer=ISSUER,
        alg="RS256",
    )

    assert token.count(".") == 2
    assert jws_factory(token).jwt.headers == {
        "alg": "RS256",
        "kid": "key-1",
        "typ": "entity-statement+jwt",
    }


def test_sign_federation_jwt_honors_explicit_kid(signing_key):
    other_key = new_rsa_key(kid="key-2")
    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": ISSUER},
        key_jar=keyjar_with_keys(signing_key, other_key),
        issuer=ISSUER,
        alg="RS256",
        kid="key-2",
    )

    assert jws_factory(token).jwt.headers["kid"] == "key-2"


def test_sign_federation_jwt_passes_profile_headers_and_lifetime_to_pack(
    signing_key, monkeypatch
):
    calls = []
    original_pack = JWT.pack

    def record_pack(self, *args, **kwargs):
        recorded = kwargs.copy()
        recorded["jws_headers"] = dict(kwargs["jws_headers"])
        calls.append((self, recorded))
        return original_pack(self, *args, **kwargs)

    monkeypatch.setattr(JWT, "pack", record_pack)
    sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": ISSUER},
        key_jar=keyjar_with_keys(signing_key),
        issuer=ISSUER,
        alg="RS256",
        kid="key-1",
        lifetime=600,
        iat=1700000000,
        extra_protected_headers={"cty": "application/json"},
    )

    signer, kwargs = calls[0]
    assert signer.iss == ISSUER
    assert signer.lifetime == 600
    assert kwargs["issuer_id"] == ISSUER
    assert kwargs["iat"] == 1700000000
    assert kwargs["jws_headers"] == {
        "typ": "entity-statement+jwt",
        "cty": "application/json",
    }


@pytest.mark.parametrize("header", ["alg", "kid", "typ"])
def test_sign_federation_jwt_rejects_reserved_extra_headers(header, signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": ISSUER},
            key_jar=keyjar_with_keys(signing_key),
            issuer=ISSUER,
            alg="RS256",
            extra_protected_headers={header: "override"},
        )


def test_sign_federation_jwt_rejects_disallowed_algorithm(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": ISSUER},
            key_jar=keyjar_with_keys(signing_key),
            issuer=ISSUER,
            alg="HS256",
        )


def test_sign_federation_jwt_translates_missing_key():
    with pytest.raises(FederationJwtKeyResolutionError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": ISSUER},
            key_jar=KeyJar(),
            issuer=ISSUER,
            alg="RS256",
        )


def test_sign_federation_jwt_translates_unsuitable_key():
    with pytest.raises(FederationJwtKeyResolutionError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": ISSUER},
            key_jar=keyjar_with_keys(new_ec_key("P-256", kid="ec-key")),
            issuer=ISSUER,
            alg="RS256",
        )


def test_sign_federation_jwt_does_not_mutate_inputs(signing_key):
    payload = {"sub": ISSUER, "metadata": {"client_id": "client"}}
    headers = {"cty": "application/json"}
    original_payload = {"sub": ISSUER, "metadata": {"client_id": "client"}}

    sign_federation_jwt(
        profile=make_profile(),
        payload=payload,
        key_jar=keyjar_with_keys(signing_key),
        issuer=ISSUER,
        alg="RS256",
        extra_protected_headers=headers,
    )

    assert payload == original_payload
    assert headers == {"cty": "application/json"}


def test_sign_federation_jwt_does_not_use_network(signing_key, monkeypatch):
    def fail_socket(*args, **kwargs):
        raise AssertionError("signing must not open network sockets")

    monkeypatch.setattr(socket, "socket", fail_socket)
    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": ISSUER},
        key_jar=keyjar_with_keys(signing_key),
        issuer=ISSUER,
        alg="RS256",
    )

    assert jws_factory(token).jwt.headers["kid"] == "key-1"
