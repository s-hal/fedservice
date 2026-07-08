"""Tests for Federation JWT JOSE parsing helpers."""

import base64
import json

import pytest

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import normalize_compact_token


def b64url_json(value):
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode("utf-8")
    )
    return encoded.decode("ascii").rstrip("=")


def b64url_bytes(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def make_token(header=None, payload=b"payload", signature=b"signature"):
    if header is None:
        header = {"alg": "RS256", "kid": "key-1", "typ": "entity-statement+jwt"}

    return ".".join(
        [
            b64url_json(header),
            b64url_bytes(payload),
            b64url_bytes(signature),
        ]
    )


def test_normalize_compact_token_accepts_str():
    token = make_token()

    assert normalize_compact_token(token) == token


def test_normalize_compact_token_accepts_ascii_bytes():
    token = make_token()

    assert normalize_compact_token(token.encode("ascii")) == token


def test_normalize_compact_token_rejects_non_ascii_bytes():
    with pytest.raises(FederationJwtHeaderError):
        normalize_compact_token("aaa.bbb.cccå".encode("utf-8"))


def test_normalize_compact_token_rejects_unsupported_types():
    with pytest.raises(FederationJwtHeaderError):
        normalize_compact_token(object())


def test_decode_protected_header_returns_plain_dict_for_str_token():
    token = make_token(header={"alg": "RS256", "kid": "key-1"})

    header = decode_protected_header(token)

    assert header == {"alg": "RS256", "kid": "key-1"}
    assert type(header) is dict


def test_decode_protected_header_accepts_ascii_bytes_token():
    token = make_token(header={"alg": "RS256"})

    assert decode_protected_header(token.encode("ascii")) == {"alg": "RS256"}


def test_decode_protected_header_does_not_verify_signature():
    token = make_token(
        header={"alg": "RS256", "kid": "key-1"},
        signature=b"deliberately-bogus-signature",
    )

    assert decode_protected_header(token) == {"alg": "RS256", "kid": "key-1"}


def test_decode_protected_header_returns_header_not_payload_data():
    token = make_token(
        header={"alg": "RS256", "kid": "header-kid"},
        payload=json.dumps(
            {"alg": "payload-alg", "kid": "payload-kid"},
            separators=(",", ":"),
        ).encode("utf-8"),
    )

    assert decode_protected_header(token) == {"alg": "RS256", "kid": "header-kid"}


@pytest.mark.parametrize("header", [{"kid": "key-1"}, {"alg": "unknown"}])
def test_decode_protected_header_does_not_apply_profile_policy(header):
    token = make_token(header=header)

    assert decode_protected_header(token) == header


@pytest.mark.parametrize(
    "token",
    [
        "one.two",
        "one.two.three.four",
        "no-dots",
        ".payload.signature",
        "protected..signature",
        "protected.payload.",
        "$$$.payload.signature",
    ],
)
def test_decode_protected_header_rejects_malformed_compact_jws(token):
    with pytest.raises(FederationJwtHeaderError):
        decode_protected_header(token)


def test_decode_protected_header_rejects_non_json_header():
    token = ".".join([b64url_bytes(b"not-json"), "payload", "signature"])

    with pytest.raises(
        FederationJwtHeaderError,
        match="Compact JWS protected header could not be decoded.",
    ):
        decode_protected_header(token)


@pytest.mark.parametrize("header_value", [["alg", "RS256"], "not-an-object", 123, None])
def test_decode_protected_header_rejects_non_object_json(header_value):
    token = ".".join([b64url_json(header_value), "payload", "signature"])

    with pytest.raises(FederationJwtHeaderError):
        decode_protected_header(token)
