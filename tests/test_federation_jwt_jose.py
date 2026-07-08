"""Tests for Federation JWT JOSE parsing helpers."""

import base64
import json
from collections.abc import Mapping
from dataclasses import replace

from cryptojwt.jwk.rsa import new_rsa_key
from idpyoidc.message import Message
import pytest

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import decode_and_validate_protected_header
from fedservice.federation_jwt.jose import decode_protected_header
from fedservice.federation_jwt.jose import normalize_compact_token
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import validate_protected_header
from fedservice.federation_jwt.profile import FederationJwtProfile


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


def make_profile():
    return FederationJwtProfile(
        name="entity_configuration",
        typ="entity-statement+jwt",
        content_type="application/entity-statement+jwt",
        message_cls=Message,
    )


def valid_header(**overrides):
    header = {"alg": "RS256", "kid": "key-1", "typ": "entity-statement+jwt"}
    header.update(overrides)
    return header


class ChangingExtraHeaders(Mapping):
    def __init__(self):
        self.read_count = 0
        self._current = {"cty": "application/json"}

    def __iter__(self):
        self.read_count += 1
        if self.read_count == 1:
            self._current = {"cty": "application/json"}
        else:
            self._current = {"typ": "trust-mark+jwt"}
        return iter(self._current)

    def __len__(self):
        return len(self._current)

    def __getitem__(self, key):
        return self._current[key]


@pytest.fixture()
def signing_key():
    return new_rsa_key(kid="key-1")


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


def test_validate_protected_header_accepts_valid_header():
    header = valid_header()

    validated = validate_protected_header(make_profile(), header)

    assert validated == header
    assert type(validated) is dict


def test_validate_protected_header_does_not_mutate_input():
    header = valid_header()

    validated = validate_protected_header(make_profile(), header)

    assert validated == header
    assert type(validated) is dict
    assert validated is not header

    validated["kid"] = "changed"

    assert header["kid"] == "key-1"


def test_validate_protected_header_rejects_non_mapping_input():
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), [("alg", "RS256")])


@pytest.mark.parametrize("header_name", ["alg", "kid", "typ"])
def test_validate_protected_header_rejects_missing_required_headers(header_name):
    header = valid_header()
    del header[header_name]

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), header)


def test_validate_protected_header_rejects_non_string_typ():
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(typ=123))


@pytest.mark.parametrize("typ", ["trust-mark+jwt", "ENTITY-STATEMENT+JWT"])
def test_validate_protected_header_rejects_wrong_typ(typ):
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(typ=typ))


@pytest.mark.parametrize("kid", [123, "", None])
def test_validate_protected_header_rejects_invalid_kid(kid):
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(kid=kid))


@pytest.mark.parametrize("alg", [123, "", None])
def test_validate_protected_header_rejects_invalid_alg(alg):
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(alg=alg))


@pytest.mark.parametrize("alg", ["none", "NoNe"])
def test_validate_protected_header_rejects_alg_none(alg):
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(alg=alg))


def test_validate_protected_header_rejects_unsupported_alg():
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(alg="HS256"))


@pytest.mark.parametrize("header_name", ["jku", "jwk", "x5u", "x5c"])
def test_validate_protected_header_rejects_forbidden_headers(header_name):
    header = valid_header(**{header_name: "forbidden"})

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), header)


def test_validate_protected_header_accepts_allowed_crit_entries():
    profile = replace(make_profile(), allowed_crit_headers=frozenset({"exp"}))
    header = valid_header(crit=["exp"], exp="required")

    assert validate_protected_header(profile, header) == header


def test_validate_protected_header_rejects_unsupported_crit_entries():
    header = valid_header(crit=["exp"], exp="required")

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), header)


def test_validate_protected_header_rejects_non_string_crit_entries():
    profile = replace(make_profile(), allowed_crit_headers=frozenset({"exp"}))
    header = valid_header(crit=["exp", 123], exp="required")

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(profile, header)


@pytest.mark.parametrize("crit", ["exp", {"exp"}, 123])
def test_validate_protected_header_rejects_invalid_crit_container(crit):
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(crit=crit))


def test_validate_protected_header_rejects_crit_entries_for_missing_headers():
    profile = replace(make_profile(), allowed_crit_headers=frozenset({"exp"}))
    header = valid_header(crit=["exp"])

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(profile, header)


def test_validate_protected_header_rejects_default_b64_false():
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(b64=False))


def test_validate_protected_header_accepts_b64_false_when_profile_allows_it():
    profile = replace(make_profile(), allow_b64_false=True)
    header = valid_header(b64=False)

    assert validate_protected_header(profile, header) == header


@pytest.mark.parametrize("b64", ["false", 0, None])
def test_validate_protected_header_rejects_non_boolean_b64(b64):
    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(make_profile(), valid_header(b64=b64))


def test_decode_and_validate_protected_header_decodes_and_validates_compact_jws():
    token = make_token(header=valid_header())

    assert decode_and_validate_protected_header(make_profile(), token) == valid_header()


def test_decode_and_validate_protected_header_rejects_invalid_header():
    token = make_token(header=valid_header(typ="trust-mark+jwt"))

    with pytest.raises(FederationJwtHeaderError):
        decode_and_validate_protected_header(make_profile(), token)


def test_sign_federation_jwt_returns_compact_jws_with_profile_header(signing_key):
    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": "https://issuer.example.org"},
        signing_key=signing_key,
        alg="RS256",
        kid="key-1",
    )

    assert isinstance(token, str)
    assert len(token.split(".")) == 3
    assert decode_protected_header(token) == valid_header()


def test_sign_federation_jwt_is_deterministic_for_rs256(signing_key):
    payload = {"sub": "https://issuer.example.org"}
    kwargs = {
        "profile": make_profile(),
        "payload": payload,
        "signing_key": signing_key,
        "alg": "RS256",
        "kid": "key-1",
    }

    assert sign_federation_jwt(**kwargs) == sign_federation_jwt(**kwargs)


def test_sign_federation_jwt_accepts_extra_protected_headers(signing_key):
    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": "https://issuer.example.org"},
        signing_key=signing_key,
        alg="RS256",
        kid="key-1",
        extra_protected_headers={"cty": "application/json"},
    )

    assert decode_protected_header(token) == valid_header(cty="application/json")


def test_sign_federation_jwt_snapshots_extra_protected_headers_once(signing_key):
    extra_headers = ChangingExtraHeaders()

    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": "https://issuer.example.org"},
        signing_key=signing_key,
        alg="RS256",
        kid="key-1",
        extra_protected_headers=extra_headers,
    )

    assert extra_headers.read_count == 1
    assert decode_protected_header(token) == valid_header(cty="application/json")


@pytest.mark.parametrize(
    "extra_headers",
    [
        {"alg": "ES256"},
        {"kid": "other-key"},
        {"typ": "trust-mark+jwt"},
    ],
)
def test_sign_federation_jwt_rejects_reserved_extra_headers_before_signing(
    extra_headers,
):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=object(),
            alg="RS256",
            kid="key-1",
            extra_protected_headers=extra_headers,
        )


def test_sign_federation_jwt_does_not_mutate_inputs(signing_key):
    payload = {"sub": "https://issuer.example.org", "metadata": {"client_id": "c1"}}
    extra_headers = {"cty": "application/json"}
    original_payload = dict(payload)
    original_metadata = dict(payload["metadata"])
    original_extra_headers = dict(extra_headers)

    sign_federation_jwt(
        profile=make_profile(),
        payload=payload,
        signing_key=signing_key,
        alg="RS256",
        kid="key-1",
        extra_protected_headers=extra_headers,
    )

    assert payload == original_payload
    assert payload["metadata"] == original_metadata
    assert extra_headers == original_extra_headers


def test_sign_federation_jwt_rejects_unsupported_alg(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=signing_key,
            alg="HS256",
            kid="key-1",
        )


def test_sign_federation_jwt_rejects_alg_none(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=signing_key,
            alg="none",
            kid="key-1",
        )


@pytest.mark.parametrize("kid", ["", None, 123])
def test_sign_federation_jwt_rejects_invalid_kid(signing_key, kid):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=signing_key,
            alg="RS256",
            kid=kid,
        )


@pytest.mark.parametrize("header_name", ["jku", "jwk", "x5u", "x5c"])
def test_sign_federation_jwt_rejects_forbidden_extra_headers(signing_key, header_name):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=signing_key,
            alg="RS256",
            kid="key-1",
            extra_protected_headers={header_name: "forbidden"},
        )


def test_sign_federation_jwt_rejects_unsupported_crit(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=signing_key,
            alg="RS256",
            kid="key-1",
            extra_protected_headers={"crit": ["exp"], "exp": "required"},
        )


def test_sign_federation_jwt_rejects_b64_false(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=signing_key,
            alg="RS256",
            kid="key-1",
            extra_protected_headers={"b64": False},
        )


def test_sign_federation_jwt_rejects_non_mapping_payload(signing_key):
    with pytest.raises(FederationJwtPayloadError):
        sign_federation_jwt(
            profile=make_profile(),
            payload=[("sub", "https://issuer.example.org")],
            signing_key=signing_key,
            alg="RS256",
            kid="key-1",
        )


def test_sign_federation_jwt_translates_framework_signing_failures():
    with pytest.raises(FederationJwtSignatureError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            signing_key=object(),
            alg="RS256",
            kid="key-1",
        )


def test_sign_federation_jwt_uses_no_network_fetch_or_discovery(
    signing_key,
    monkeypatch,
):
    import socket

    def fail_socket(*args, **kwargs):
        raise AssertionError("signing must not open network sockets")

    monkeypatch.setattr(socket, "socket", fail_socket)

    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": "https://issuer.example.org"},
        signing_key=signing_key,
        alg="RS256",
        kid="key-1",
    )

    assert decode_protected_header(token) == valid_header()
