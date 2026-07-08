"""Tests for Federation JWT JOSE parsing helpers."""

import base64
import json

import pytest

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.jose import CompactJwsParts
from fedservice.federation_jwt.jose import base64url_decode_segment
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import normalize_compact_token
from fedservice.federation_jwt.jose import split_compact_jws


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


def test_split_compact_jws_returns_three_parts_for_str():
    token = make_token()

    parts = split_compact_jws(token)

    assert isinstance(parts, CompactJwsParts)
    assert "." not in parts.protected
    assert "." not in parts.payload
    assert "." not in parts.signature


def test_split_compact_jws_accepts_ascii_bytes():
    token = make_token()

    parts = split_compact_jws(token.encode("ascii"))

    assert parts == split_compact_jws(token)


@pytest.mark.parametrize("token", ["one.two", "one.two.three.four", "no-dots"])
def test_split_compact_jws_rejects_wrong_part_count(token):
    with pytest.raises(FederationJwtHeaderError):
        split_compact_jws(token)


@pytest.mark.parametrize("token", [".payload.signature", "protected..signature", "protected.payload."])
def test_split_compact_jws_rejects_empty_parts(token):
    with pytest.raises(FederationJwtHeaderError):
        split_compact_jws(token)


def test_base64url_decode_segment_accepts_unpadded_input():
    assert base64url_decode_segment("eyJhbGciOiJSUzI1NiJ9") == b'{"alg":"RS256"}'


@pytest.mark.parametrize("segment", ["$$$", "abcde", "abcd="])
def test_base64url_decode_segment_rejects_invalid_input(segment):
    with pytest.raises(FederationJwtHeaderError):
        base64url_decode_segment(segment)


def test_decode_protected_header_returns_plain_dict():
    token = make_token(header={"alg": "RS256", "kid": "key-1"})

    header = decode_protected_header(token)

    assert header == {"alg": "RS256", "kid": "key-1"}
    assert type(header) is dict


def test_decode_protected_header_accepts_ascii_bytes_token():
    token = make_token(header={"alg": "RS256"})

    assert decode_protected_header(token.encode("ascii")) == {"alg": "RS256"}


def test_decode_protected_header_rejects_invalid_base64url():
    token = "$$$.payload.signature"

    with pytest.raises(FederationJwtHeaderError):
        decode_protected_header(token)


def test_decode_protected_header_rejects_non_json_header():
    token = ".".join([b64url_bytes(b"not-json"), "payload", "signature"])

    with pytest.raises(FederationJwtHeaderError):
        decode_protected_header(token)


@pytest.mark.parametrize("header_value", [["alg", "RS256"], "not-an-object", 123, None])
def test_decode_protected_header_rejects_non_object_json(header_value):
    token = ".".join([b64url_json(header_value), "payload", "signature"])

    with pytest.raises(FederationJwtHeaderError):
        decode_protected_header(token)
