"""Tests for the Federation JWT JOSE policy boundary."""

import base64
from copy import deepcopy
import json
from dataclasses import replace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jwt import JWT
from idpyoidc.message import Message
import pytest

from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.errors import FederationJwtPayloadError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import validate_protected_header
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.profile import FederationJwtProfile
from fedservice.federation_jwt import registry
from fedservice.federation_jwt.verified import VerifiedFederationJwt


NOW = 1700000000
ISSUER = "https://issuer.example.org"
SUBJECT = "https://subject.example.org"
DEFAULT_CRYPTOJWT_SKEW = JWT().skew


@pytest.fixture()
def signing_key():
    return new_rsa_key(kid="key-1")


def keyjar_for(key):
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER, [key])
    return key_jar


def header(token):
    parsed = jws_factory(token)
    assert parsed is not None
    return dict(parsed.jwt.headers)


def compact_token(protected_header, payload=None, signature=b"signature"):
    if payload is None:
        payload = {"iss": ISSUER, "sub": SUBJECT, "iat": NOW}

    def encode(value):
        if not isinstance(value, bytes):
            value = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    return ".".join((encode(protected_header), encode(payload), encode(signature)))


def replace_protected_header(token, remove=None, **updates):
    parts = token.split(".")
    protected_header = header(token)
    if remove is not None:
        protected_header.pop(remove)
    protected_header.update(updates)
    encoded = base64.urlsafe_b64encode(
        json.dumps(protected_header, separators=(",", ":")).encode("utf-8")
    )
    parts[0] = encoded.decode("ascii").rstrip("=")
    return ".".join(parts)


def payload_for(profile, signing_key):
    common = {"iss": ISSUER, "iat": NOW - 10}
    payloads = {
        registry.ENTITY_CONFIGURATION.name: dict(
            common,
            sub=ISSUER,
            exp=NOW + 600,
            jwks={"keys": [signing_key.serialize(private=False)]},
            metadata={"federation_entity": {}},
        ),
        registry.SUBORDINATE_STATEMENT.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            jwks={"keys": []},
        ),
        registry.RESOLVE_RESPONSE.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            metadata={"federation_entity": {}},
            trust_chain=["header.payload.signature"],
        ),
        registry.TRUST_MARK.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            trust_mark_type="https://marks.example.org/assured",
        ),
        registry.TRUST_MARK_DELEGATION.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            trust_mark_type="https://marks.example.org/assured",
        ),
        registry.TRUST_MARK_STATUS_RESPONSE.name: dict(
            common,
            trust_mark="header.payload.signature",
            status="active",
        ),
        registry.SIGNED_JWK_SET.name: dict(
            common,
            sub=SUBJECT,
            exp=NOW + 600,
            keys=[{"kty": "RSA", "kid": "historical-key"}],
        ),
        registry.HISTORICAL_KEYS_RESPONSE.name: dict(
            common,
            jwks={"keys": []},
        ),
        registry.EXPLICIT_REGISTRATION_RESPONSE.name: dict(
            common,
            client_id="client-id",
            redirect_uris=["https://client.example.org/cb"],
            client_registration_types=["automatic"],
        ),
    }
    return payloads[profile.name]


def sign(profile, key, payload=None, **kwargs):
    if payload is None:
        payload = payload_for(profile, key)
    return sign_federation_jwt(
        profile=profile,
        payload=payload,
        key_jar=keyjar_for(key),
        issuer=ISSUER,
        alg="RS256",
        kid=key.kid,
        iat=payload.get("iat"),
        **kwargs
    )


@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda item: item.name)
def test_every_profile_signs_and_verifies_with_exact_protected_header(
    profile, signing_key
):
    token = sign(profile, signing_key)

    verified = verify_federation_jwt(
        profile=profile,
        token=token,
        key_jar=keyjar_for(signing_key),
        now=NOW,
    )

    assert header(token) == {"alg": "RS256", "kid": "key-1", "typ": profile.typ}
    assert isinstance(verified, VerifiedFederationJwt)
    assert verified.profile is profile
    assert verified.raw_token() == token


@pytest.mark.parametrize("required", ("alg", "kid", "typ"))
def test_header_validation_requires_profile_headers(required):
    protected = {
        "alg": "RS256",
        "kid": "key-1",
        "typ": registry.ENTITY_CONFIGURATION.typ,
    }
    del protected[required]

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(registry.ENTITY_CONFIGURATION, protected)


@pytest.mark.parametrize(
    "change",
    (
        {"typ": "trust-mark+jwt"},
        {"kid": ""},
        {"alg": "none"},
        {"alg": "HS256"},
        {"crit": ["exp"], "exp": "required"},
        {"jku": "https://keys.example.org/jwks.json"},
        {"jwk": {"kty": "RSA"}},
        {"x5u": "https://keys.example.org/cert.pem"},
        {"x5c": ["certificate"]},
    ),
)
def test_header_validation_rejects_values_outside_profile_policy(change):
    protected = {
        "alg": "RS256",
        "kid": "key-1",
        "typ": registry.ENTITY_CONFIGURATION.typ,
    }
    protected.update(change)

    with pytest.raises(FederationJwtHeaderError):
        validate_protected_header(registry.ENTITY_CONFIGURATION, protected)


def test_header_validation_accepts_explicitly_allowed_critical_header():
    profile = replace(
        registry.ENTITY_CONFIGURATION,
        allowed_crit_headers=frozenset({"custom"}),
    )
    protected = {
        "alg": "RS256",
        "kid": "key-1",
        "typ": profile.typ,
        "crit": ["custom"],
        "custom": "required-value",
    }

    assert validate_protected_header(profile, protected) == protected


@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda item: item.name)
@pytest.mark.parametrize("reserved", ("alg", "kid", "typ"))
def test_signing_rejects_caller_override_of_profile_headers(
    profile, reserved, signing_key
):
    with pytest.raises(FederationJwtHeaderError):
        sign(
            profile,
            signing_key,
            extra_protected_headers={reserved: "caller-value"},
        )


@pytest.mark.parametrize(
    "alg,extra_headers",
    (
        ("none", None),
        ("HS256", None),
        ("RS256", {"crit": ["exp"], "exp": "required"}),
        ("RS256", {"jku": "https://keys.example.org/jwks.json"}),
        ("RS256", {"jwk": {"kty": "RSA"}}),
        ("RS256", {"x5u": "https://keys.example.org/cert.pem"}),
        ("RS256", {"x5c": ["certificate"]}),
    ),
)
def test_signing_rejects_headers_outside_profile_policy(
    alg, extra_headers, signing_key
):
    payload = payload_for(registry.ENTITY_CONFIGURATION, signing_key)
    with pytest.raises(FederationJwtHeaderError):
        sign_federation_jwt(
            profile=registry.ENTITY_CONFIGURATION,
            payload=payload,
            key_jar=keyjar_for(signing_key),
            issuer=ISSUER,
            alg=alg,
            kid="key-1",
            iat=payload["iat"],
            extra_protected_headers=extra_headers,
        )


def test_signing_does_not_mutate_caller_mappings(signing_key):
    payload = payload_for(registry.ENTITY_CONFIGURATION, signing_key)
    payload["custom"] = {"items": ["one"]}
    extra_headers = {"cty": "application/json", "custom": {"items": ["one"]}}
    payload_before = deepcopy(payload)
    headers_before = deepcopy(extra_headers)

    sign(
        registry.ENTITY_CONFIGURATION,
        signing_key,
        payload=payload,
        extra_protected_headers=extra_headers,
    )

    assert payload == payload_before
    assert extra_headers == headers_before


@pytest.mark.parametrize("profile", registry.ALL_PROFILES, ids=lambda item: item.name)
def test_verification_rejects_distinct_profile_typ_before_key_resolution(
    profile, signing_key
):
    token = sign(profile, signing_key)
    wrong_profile = next(
        candidate
        for candidate in registry.ALL_PROFILES
        if candidate.typ != profile.typ
    )

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(wrong_profile, token, object(), now=NOW)


@pytest.mark.parametrize(
    "source_profile,target_profile",
    (
        (registry.SUBORDINATE_STATEMENT, registry.ENTITY_CONFIGURATION),
        (registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT),
        (registry.SIGNED_JWK_SET, registry.HISTORICAL_KEYS_RESPONSE),
        (registry.HISTORICAL_KEYS_RESPONSE, registry.SIGNED_JWK_SET),
    ),
    ids=(
        "statement-as-configuration",
        "configuration-as-statement",
        "jwks-as-history",
        "history-as-jwks",
    ),
)
def test_shared_typ_profiles_are_separated_by_payload_schema(
    source_profile, target_profile, signing_key
):
    token = sign(source_profile, signing_key)

    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(
            target_profile,
            token,
            keyjar_for(signing_key),
            now=NOW,
        )


def test_verification_rejects_missing_caller_supplied_local_key(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)

    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            KeyJar(),
            now=NOW,
        )


def test_verification_rejects_missing_kid_before_signature_check(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)
    token = replace_protected_header(token, remove="kid")

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            object(),
            now=NOW,
        )


def test_verification_rejects_unknown_local_kid(signing_key):
    unknown_key = new_rsa_key(kid="unknown-key")
    token = sign(registry.ENTITY_CONFIGURATION, unknown_key)

    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            keyjar_for(signing_key),
            now=NOW,
        )


def test_verification_preserves_exact_ascii_bytes(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)
    token_bytes = token.encode("ascii")

    verified = verify_federation_jwt(
        registry.ENTITY_CONFIGURATION,
        token_bytes,
        keyjar_for(signing_key),
        now=NOW,
    )

    assert verified.raw_token_bytes() == token_bytes
    assert verified.raw_token() == token
    assert verified.profile is registry.ENTITY_CONFIGURATION
    assert verified.claims()["iss"] == ISSUER
    assert verified.claims()["sub"] == ISSUER


def test_verification_rejects_invalid_signature(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)
    untrusted_key = new_rsa_key(kid="key-1")

    with pytest.raises(FederationJwtSignatureError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            keyjar_for(untrusted_key),
            now=NOW,
        )


class FailingMessage(Message):
    def verify(self, **kwargs):
        raise ValueError("schema validation failed")


def test_message_schema_failure_is_a_payload_error(signing_key):
    profile = replace(registry.ENTITY_CONFIGURATION, message_cls=FailingMessage)
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)

    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(profile, token, keyjar_for(signing_key), now=NOW)


def test_profile_semantic_validator_receives_effective_time_and_skew(signing_key):
    calls = []

    def validator(payload, now, skew):
        calls.append((payload["iss"], now, skew))

    profile = FederationJwtProfile(
        name="test",
        typ="test+jwt",
        content_type="application/test+jwt",
        message_cls=Message,
        payload_validators=(validator,),
    )
    payload = {"iss": ISSUER, "sub": SUBJECT, "iat": NOW - 10}
    token = sign(profile, signing_key, payload=payload)

    verify_federation_jwt(profile, token, keyjar_for(signing_key), now=NOW)

    assert calls == [(ISSUER, NOW, DEFAULT_CRYPTOJWT_SKEW)]


@pytest.mark.parametrize(
    "profile",
    tuple(item for item in registry.ALL_PROFILES if item.payload_validators),
    ids=lambda item: item.name,
)
def test_profiles_with_future_iat_policy_honor_cryptojwt_skew(profile, signing_key):
    neutral_profile = replace(profile, message_cls=Message)
    accepted_iat = NOW + DEFAULT_CRYPTOJWT_SKEW
    rejected_iat = accepted_iat + 1
    accepted = sign(
        profile,
        signing_key,
        payload={"iss": ISSUER, "sub": SUBJECT, "iat": accepted_iat},
    )
    rejected = sign(
        profile,
        signing_key,
        payload={"iss": ISSUER, "sub": SUBJECT, "iat": rejected_iat},
    )

    verify_federation_jwt(
        neutral_profile, accepted, keyjar_for(signing_key), now=NOW
    )
    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(
            neutral_profile, rejected, keyjar_for(signing_key), now=NOW
        )


def test_signing_and_verification_work_with_caller_supplied_local_keys(signing_key):
    token = sign(registry.ENTITY_CONFIGURATION, signing_key)

    verified = verify_federation_jwt(
        registry.ENTITY_CONFIGURATION,
        token,
        keyjar_for(signing_key),
        now=NOW,
    )

    assert verified.raw_token() == token


def test_invalid_compact_token_is_a_header_error():
    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            "not-a-compact-jws",
            KeyJar(),
        )


def test_invalid_header_is_rejected_before_signature_verification():
    token = compact_token(
        {"alg": "none", "kid": "key-1", "typ": "entity-statement+jwt"}
    )

    with pytest.raises(FederationJwtHeaderError):
        verify_federation_jwt(
            registry.ENTITY_CONFIGURATION,
            token,
            object(),
            now=NOW,
        )
