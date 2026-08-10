"""Tests for Federation JWT JOSE parsing helpers."""

import base64
import json
from collections.abc import Mapping
from dataclasses import replace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jwt import JWT
from idpyoidc.message import Message
import pytest

from fedservice.federation_jwt import jose as federation_jose
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import validate_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt import registry
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.verified import VerifiedFederationJwt
from fedservice.message import EntityStatement


DEFAULT_CRYPTOJWT_SKEW = JWT().skew


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


def parsed_header(token):
    parsed_jws = jws_factory(token)
    assert parsed_jws is not None
    return dict(parsed_jws.jwt.headers)


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


class TrackingMessage(Message):
    verify_calls = 0

    def verify(self, **kwargs):
        type(self).verify_calls += 1
        return super().verify(**kwargs)


class FailingMessage(Message):
    def verify(self, **kwargs):
        raise ValueError("message failed")


@pytest.fixture()
def signing_key():
    return new_rsa_key(kid="key-1")


def verification_payload(now=1000, **overrides):
    payload = {
        "iss": "https://issuer.example.org",
        "sub": "https://subject.example.org",
        "iat": now - 10,
        "exp": now + 600,
        "metadata": {"federation_entity": {"contacts": ["ops@example.org"]}},
    }
    payload.update(overrides)
    return payload


def keyjar_for(signing_key, issuer="https://issuer.example.org"):
    key_jar = KeyJar()
    key_jar.add_keys(issuer, [signing_key])
    return key_jar


def signed_token(signing_key, payload=None, extra_protected_headers=None):
    if payload is None:
        payload = verification_payload()
    return sign_federation_jwt(
        profile=make_profile(),
        payload=payload,
        key_jar=keyjar_for(signing_key, payload["iss"]),
        issuer=payload["iss"],
        alg="RS256",
        kid="key-1",
        iat=payload.get("iat"),
        extra_protected_headers=extra_protected_headers,
    )


def verify_token(signing_key, token, profile=None, now=1000):
    if profile is None:
        profile = make_profile()
    key_jar = keyjar_for(signing_key)
    verified = verify_federation_jwt(
        profile=profile,
        token=token,
        key_jar=key_jar,
        now=now,
    )
    return verified, key_jar


def corrupt_signature(token):
    protected, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    return ".".join([protected, payload, replacement + signature[1:]])


def thaw(value):
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


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


def test_sign_federation_jwt_returns_compact_jws_with_profile_header(signing_key):
    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": "https://issuer.example.org"},
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="key-1",
    )

    assert isinstance(token, str)
    assert len(token.split(".")) == 3
    assert parsed_header(token) == valid_header()


@pytest.mark.parametrize("kid", [None, ""])
def test_sign_federation_jwt_rejects_emitted_token_without_kid(
    signing_key, monkeypatch, kid
):
    emitted_header = {"alg": "RS256", "typ": "entity-statement+jwt"}
    if kid is not None:
        emitted_header["kid"] = kid
    emitted = make_token(
        header=emitted_header,
        payload=json.dumps(verification_payload()).encode("utf-8"),
    )
    monkeypatch.setattr(federation_jose.JWT, "pack", lambda self, **kwargs: emitted)

    with pytest.raises(FederationJwtSignatureError):
        sign_federation_jwt(
            profile=make_profile(),
            payload=verification_payload(),
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="RS256",
        )


def test_sign_federation_jwt_is_deterministic_for_rs256_with_fixed_iat(signing_key):
    payload = {"sub": "https://issuer.example.org"}
    kwargs = {
        "profile": make_profile(),
        "payload": payload,
        "key_jar": keyjar_for(signing_key),
        "issuer": "https://issuer.example.org",
        "alg": "RS256",
        "kid": "key-1",
        "iat": 1700000000,
    }

    assert sign_federation_jwt(**kwargs) == sign_federation_jwt(**kwargs)


def test_sign_federation_jwt_accepts_extra_protected_headers(signing_key):
    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": "https://issuer.example.org"},
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="key-1",
        extra_protected_headers={"cty": "application/json"},
    )

    assert parsed_header(token) == valid_header(cty="application/json")


def test_sign_federation_jwt_snapshots_extra_protected_headers_once(signing_key):
    extra_headers = ChangingExtraHeaders()

    token = sign_federation_jwt(
        profile=make_profile(),
        payload={"sub": "https://issuer.example.org"},
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="key-1",
        extra_protected_headers=extra_headers,
    )

    assert extra_headers.read_count == 1
    assert parsed_header(token) == valid_header(cty="application/json")


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
            key_jar=object(),
            issuer="https://issuer.example.org",
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
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
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
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="HS256",
            kid="key-1",
        )


def test_sign_federation_jwt_rejects_alg_none(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="none",
            kid="key-1",
        )


@pytest.mark.parametrize("kid", ["", 123])
def test_sign_federation_jwt_rejects_invalid_kid(signing_key, kid):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="RS256",
            kid=kid,
        )


@pytest.mark.parametrize("header_name", ["jku", "jwk", "x5u", "x5c"])
def test_sign_federation_jwt_rejects_forbidden_extra_headers(signing_key, header_name):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="RS256",
            kid="key-1",
            extra_protected_headers={header_name: "forbidden"},
        )


def test_sign_federation_jwt_rejects_unsupported_crit(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="RS256",
            kid="key-1",
            extra_protected_headers={"crit": ["exp"], "exp": "required"},
        )


def test_sign_federation_jwt_rejects_b64_false(signing_key):
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="RS256",
            kid="key-1",
            extra_protected_headers={"b64": False},
        )


def test_sign_federation_jwt_rejects_non_mapping_payload(signing_key):
    with pytest.raises(FederationJwtPayloadError):
        sign_federation_jwt(
            profile=make_profile(),
            payload=[("sub", "https://issuer.example.org")],
            key_jar=keyjar_for(signing_key),
            issuer="https://issuer.example.org",
            alg="RS256",
            kid="key-1",
        )


def test_sign_federation_jwt_translates_framework_signing_failures():
    with pytest.raises(FederationJwtSignatureError):
        sign_federation_jwt(
            profile=make_profile(),
            payload={"sub": "https://issuer.example.org"},
            key_jar=object(),
            issuer="https://issuer.example.org",
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
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="key-1",
    )

    assert parsed_header(token) == valid_header()


def test_entity_statement_verify_preserves_expected_issuer_check():
    message = EntityStatement(**verification_payload())

    assert message.verify(iss="https://issuer.example.org") is None
    with pytest.raises(ValueError, match="^Wrong issuer$"):
        message.verify(iss="https://different.example.org")


def test_entity_configuration_verifies_through_canonical_profile(signing_key):
    payload = verification_payload(sub="https://issuer.example.org")
    token = sign_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        payload=payload,
        key_jar=keyjar_for(signing_key),
        issuer=payload["iss"],
        alg="RS256",
        kid="key-1",
        iat=payload["iat"],
    )

    verified = verify_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        token=token,
        key_jar=keyjar_for(signing_key),
        now=1000,
    )

    assert verified.profile is ENTITY_CONFIGURATION
    assert verified.claims()["iss"] == verified.claims()["sub"]
    with pytest.raises(TypeError):
        verified.claims()["metadata"]["federation_entity"]["contacts"] = []


def test_entity_configuration_rejects_mismatched_issuer_after_signature_verification(
    signing_key,
):
    payload = verification_payload()
    token = sign_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        payload=payload,
        key_jar=keyjar_for(signing_key),
        issuer=payload["iss"],
        alg="RS256",
        kid="key-1",
        iat=payload["iat"],
    )
    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(
            profile=ENTITY_CONFIGURATION,
            token=token,
            key_jar=keyjar_for(signing_key),
            now=1000,
        )


def test_verify_federation_jwt_returns_verified_container(signing_key):
    payload = verification_payload()
    token = signed_token(signing_key, payload)

    verified, _key_jar = verify_token(signing_key, token)

    assert isinstance(verified, VerifiedFederationJwt)
    assert verified.raw_token() == token
    assert verified.raw_token_bytes() == token.encode("ascii")
    assert verified.profile == make_profile()
    assert verified.header() == valid_header()
    assert thaw(verified.claims()) == payload
    assert isinstance(verified.message(), Message)
    assert verified.issuer == payload["iss"]
    assert verified.subject == payload["sub"]
    assert verified.issued_at == payload["iat"]
    assert verified.expires_at == payload["exp"]


def test_verify_federation_jwt_accepts_ascii_bytes_token(signing_key):
    token = signed_token(signing_key)
    token_bytes = token.encode("ascii")

    verified, _resolver = verify_token(signing_key, token_bytes)

    assert verified.raw_token() == token
    assert verified.raw_token_bytes() is token_bytes


def test_verify_federation_jwt_freezes_nested_header_and_payload(signing_key):
    token = signed_token(
        signing_key,
        extra_protected_headers={"nested": {"items": ["one"]}},
    )

    verified, _resolver = verify_token(signing_key, token)

    with pytest.raises(TypeError):
        verified.header()["nested"]["items"] = []
    with pytest.raises(TypeError):
        verified.claims()["metadata"]["federation_entity"] = {}
    assert verified.header()["nested"]["items"] == ("one",)
    assert verified.claims()["metadata"]["federation_entity"]["contacts"] == (
        "ops@example.org",
    )


def test_verify_federation_jwt_delegates_to_cryptojwt_unpack(
    signing_key, monkeypatch
):
    token = signed_token(signing_key)
    calls = []
    original_unpack = federation_jose.JWT.unpack

    def record_unpack(self, token, timestamp=None):
        calls.append((self, token, timestamp))
        return original_unpack(self, token, timestamp=timestamp)

    monkeypatch.setattr(federation_jose.JWT, "unpack", record_unpack)
    verified, key_jar = verify_token(signing_key, token)

    jwt, unpacked_token, timestamp = calls[0]
    assert unpacked_token == token
    assert timestamp == 1000
    assert jwt.key_jar is key_jar
    assert jwt.msg_cls is make_profile().message_cls
    assert jwt.skew == DEFAULT_CRYPTOJWT_SKEW
    assert set(jwt.allowed_sign_algs) == set(make_profile().allowed_algs)
    assert thaw(verified.claims()) == verification_payload()


def test_verify_federation_jwt_no_keys_raises_key_resolution_error(signing_key):
    token = signed_token(signing_key)

    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(
            profile=make_profile(),
            token=token,
            key_jar=KeyJar(),
            now=1000,
        )


def test_verify_federation_jwt_unknown_kid_for_known_issuer_raises_key_error(
    signing_key,
):
    token = signed_token(signing_key)
    key_jar = keyjar_for(new_rsa_key(kid="other-key"))

    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(
            profile=make_profile(),
            token=token,
            key_jar=key_jar,
            now=1000,
        )


def test_verify_federation_jwt_bad_signature_raises_signature_error(signing_key):
    token = corrupt_signature(signed_token(signing_key))

    with pytest.raises(FederationJwtSignatureError):
        verify_token(signing_key, token)


def test_verify_federation_jwt_malformed_compact_token_raises_header_error():
    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            profile=make_profile(),
            token="not-a-compact-jws",
            key_jar=KeyJar(),
        )


def test_verify_federation_jwt_unpack_failure_raises_payload_error(
    signing_key, monkeypatch
):
    token = signed_token(signing_key)
    cause = ValueError("unpack failed")

    def fail_unpack(self, token, timestamp=None):
        raise cause

    monkeypatch.setattr(federation_jose.JWT, "unpack", fail_unpack)
    with pytest.raises(FederationJwtPayloadError) as err:
        verify_federation_jwt(
            profile=make_profile(),
            token=token,
            key_jar=keyjar_for(signing_key),
        )

    assert err.value.__cause__ is cause


@pytest.mark.parametrize(
    "header",
    [
        valid_header(typ="trust-mark+jwt"),
        {"alg": "RS256", "kid": "key-1"},
        valid_header(alg="none"),
        {"alg": "RS256", "typ": "entity-statement+jwt"},
        valid_header(crit=["exp"], exp="required"),
        valid_header(b64=False),
    ],
)
def test_verify_federation_jwt_rejects_invalid_profile_headers(header):
    token = make_token(header=header, payload=json.dumps(verification_payload()).encode())

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            profile=make_profile(),
            token=token,
            key_jar=object(),
        )


@pytest.mark.parametrize(
    "claim,accepted_value,rejected_value",
    [
        (
            "exp",
            1000 - DEFAULT_CRYPTOJWT_SKEW + 1,
            1000 - DEFAULT_CRYPTOJWT_SKEW,
        ),
        ("nbf", 1000 + DEFAULT_CRYPTOJWT_SKEW, 1001 + DEFAULT_CRYPTOJWT_SKEW),
    ],
)
def test_verify_federation_jwt_uses_cryptojwt_skew(
    signing_key,
    claim,
    accepted_value,
    rejected_value,
):
    accepted_token = signed_token(
        signing_key,
        verification_payload(**{claim: accepted_value}),
    )
    rejected_token = signed_token(
        signing_key,
        verification_payload(**{claim: rejected_value}),
    )

    verify_token(signing_key, accepted_token, now=1000)
    with pytest.raises(FederationJwtPayloadError):
        verify_token(signing_key, rejected_token, now=1000)


@pytest.mark.parametrize(
    "profile",
    [
        registry.ENTITY_CONFIGURATION,
        registry.SUBORDINATE_STATEMENT,
        registry.TRUST_MARK,
        registry.TRUST_MARK_DELEGATION,
        registry.EXPLICIT_REGISTRATION_RESPONSE,
    ],
    ids=lambda profile: profile.name,
)
def test_required_profiles_reject_future_iat_beyond_verifier_skew(
    profile, signing_key
):
    verification_profile = replace(profile, message_cls=Message)
    accepted_iat = 1000 + DEFAULT_CRYPTOJWT_SKEW
    rejected_iat = accepted_iat + 1
    accepted = sign_federation_jwt(
        profile=profile,
        payload=verification_payload(iat=accepted_iat),
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="key-1",
        iat=accepted_iat,
    )
    rejected = sign_federation_jwt(
        profile=profile,
        payload=verification_payload(iat=rejected_iat),
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="key-1",
        iat=rejected_iat,
    )

    verify_federation_jwt(
        profile=verification_profile,
        token=accepted,
        key_jar=keyjar_for(signing_key),
        now=1000,
    )
    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(
            profile=verification_profile,
            token=rejected,
            key_jar=keyjar_for(signing_key),
            now=1000,
        )


@pytest.mark.parametrize(
    "profile",
    [
        registry.RESOLVE_RESPONSE,
        registry.TRUST_MARK_STATUS_RESPONSE,
        registry.SIGNED_JWK_SET,
        registry.HISTORICAL_KEYS_RESPONSE,
    ],
    ids=lambda profile: profile.name,
)
def test_profiles_without_future_iat_rule_do_not_inherit_it(profile, signing_key):
    verification_profile = replace(profile, message_cls=Message)
    future_iat = 1001 + DEFAULT_CRYPTOJWT_SKEW
    token = sign_federation_jwt(
        profile=profile,
        payload=verification_payload(iat=future_iat),
        key_jar=keyjar_for(signing_key),
        issuer="https://issuer.example.org",
        alg="RS256",
        kid="key-1",
        iat=future_iat,
    )

    verified = verify_federation_jwt(
        profile=verification_profile,
        token=token,
        key_jar=keyjar_for(signing_key),
        now=1000,
    )

    assert verified.issued_at == future_iat


def test_verify_federation_jwt_calls_message_verify(signing_key):
    TrackingMessage.verify_calls = 0
    profile = replace(make_profile(), message_cls=TrackingMessage)
    token = signed_token(signing_key)

    verified, _resolver = verify_token(signing_key, token, profile=profile)

    assert isinstance(verified.message(), TrackingMessage)
    assert TrackingMessage.verify_calls == 1


def test_verify_federation_jwt_message_verify_failure_raises_payload_error(
    signing_key,
):
    profile = replace(make_profile(), message_cls=FailingMessage)
    token = signed_token(signing_key)

    with pytest.raises(FederationJwtPayloadError):
        verify_token(signing_key, token, profile=profile)


def test_verify_federation_jwt_calls_payload_validators_with_time_policy(signing_key):
    calls = []

    def validator(payload, now, skew):
        calls.append((payload, now, skew))

    profile = replace(make_profile(), payload_validators=(validator,))
    token = signed_token(signing_key)

    verified, _resolver = verify_token(signing_key, token, profile=profile)

    assert calls == [(thaw(verified.claims()), 1000, DEFAULT_CRYPTOJWT_SKEW)]


def test_verify_federation_jwt_payload_validator_failure_raises_payload_error(
    signing_key,
):
    def validator(payload, now, skew):
        raise ValueError("validator failed")

    profile = replace(make_profile(), payload_validators=(validator,))
    token = signed_token(signing_key)

    with pytest.raises(FederationJwtPayloadError):
        verify_token(signing_key, token, profile=profile)


def test_verify_federation_jwt_does_not_mutate_inputs_or_keyjar(signing_key):
    token = signed_token(signing_key)
    key_jar = keyjar_for(signing_key)
    jwks_before = key_jar.export_jwks(private=True)

    verify_federation_jwt(
        profile=make_profile(),
        token=token,
        key_jar=key_jar,
        now=1000,
    )

    assert token == signed_token(signing_key)
    assert key_jar.export_jwks(private=True) == jwks_before


def test_verify_federation_jwt_uses_no_network_fetch_or_discovery(
    signing_key,
    monkeypatch,
):
    import socket

    def fail_socket(*args, **kwargs):
        raise AssertionError("verification must not open network sockets")

    monkeypatch.setattr(socket, "socket", fail_socket)
    token = signed_token(signing_key)

    verified, _key_jar = verify_token(signing_key, token)

    assert verified.raw_token() == token
