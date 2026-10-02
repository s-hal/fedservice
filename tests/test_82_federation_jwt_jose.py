"""Tests for the Federation JWT JOSE policy boundary."""

import base64
from copy import deepcopy
import json
from dataclasses import replace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
from cryptojwt.jws.jws import JWS
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
from fedservice.exception import MetadataPolicyCritError
from fedservice.exception import UnknownCriticalExtension


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
            sub=SUBJECT,
            exp=NOW + 600,
            aud=SUBJECT,
            trust_anchor="https://ta.example.org",
            authority_hints=["https://superior.example.org"],
            metadata={
                "oauth_client": {
                    "client_id": "client-id",
                    "redirect_uris": ["https://client.example.org/cb"],
                }
            },
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


@pytest.fixture(scope="module")
def container_signing_key():
    return new_rsa_key(kid="container-key")


@pytest.mark.parametrize("profile,field", [
    (registry.ENTITY_CONFIGURATION, "iss"),
    (registry.SUBORDINATE_STATEMENT, "iss"),
    (registry.SUBORDINATE_STATEMENT, "sub"),
])
@pytest.mark.parametrize("identifier", [
    "not-an-entity-id", "http://issuer.example.org", "https://issuer.example.org?q=1",
    "https:///path", "https://issuer.example.org?", "https://issuer.example.org#",
    "https://issuer.example.org/#fragment", " https://issuer.example.org",
    "https://iss\nuer.example.org", "https://issuer.example.org/\x00",
])
def test_signed_entity_identifiers_reject_at_schema(profile, field, identifier, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload[field] = identifier
    if profile is registry.ENTITY_CONFIGURATION:
        payload["sub"] = identifier
    keys = KeyJar()
    keys.add_keys(payload["iss"], [container_signing_key])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keys, now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert field in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("identifier", [
    "https://example.org", "https://Example.org:8443/path", "https://example.org/a%2Fb%3Fc%23d",
])
def test_signed_entity_identifiers_preserve_exact_strings(profile, identifier, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["iss"] = identifier
    if profile is registry.ENTITY_CONFIGURATION:
        payload["sub"] = identifier
    keys = KeyJar()
    keys.add_keys(identifier, [container_signing_key])
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    verified = verify_federation_jwt(profile, token, keys, now=NOW)
    assert verified.claims()["iss"] == verified.message()["iss"] == identifier
    assert verified.claims()["sub"] == verified.message()["sub"] == payload["sub"]
    assert verified.raw_token() == token


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints"])
@pytest.mark.parametrize("value", [
    [], ISSUER, None, {}, 12, False, "", [""], [None],
    [12, ISSUER], [ISSUER, 12], [ISSUER, ""], ["bad", ISSUER],
    [ISSUER, "http://invalid.example.org"], [ISSUER + "?"], [ISSUER + "#"],
])
def test_signed_ec_rejects_original_hint_representation(claim, value, container_signing_key):
    profile = registry.ENTITY_CONFIGURATION
    payload = payload_for(profile, container_signing_key)
    payload[claim] = value
    token = sign(profile, container_signing_key, payload)
    decoded = jws_factory(token).jwt.payload()
    assert claim in decoded and decoded[claim] == value
    assert type(decoded[claim]) is type(value)
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert claim in str(error.value.__cause__)


@pytest.mark.parametrize("claims", [(), ("authority_hints",), ("trust_anchor_hints",),
                                    ("authority_hints", "trust_anchor_hints")])
@pytest.mark.parametrize("hints", [["https://ta.example.org"],
                                    ["https://Ta.example.org:8443/a%2Fb", ISSUER,
                                     "https://Ta.example.org:8443/a%2Fb"]])
def test_signed_ec_hint_presence_and_exact_order(claims, hints, container_signing_key):
    profile = registry.ENTITY_CONFIGURATION
    payload = payload_for(profile, container_signing_key)
    payload.update({claim: hints for claim in claims})
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    for claim in ("authority_hints", "trust_anchor_hints"):
        if claim in claims:
            assert verified.claims()[claim] == tuple(hints)
            assert verified.message()[claim] == hints
        else:
            assert claim not in verified.claims()
            assert claim not in verified.message()


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("critical", [None, [], "extension", {}, [12], [""],
                                       ["extension", "extension"], ["missing"],
                                       ["extension", "missing"], ["iss"], ["jwks"],
                                       ["authority_hints"], ["trust_anchor_hints"], ["metadata_policy"]])
@pytest.mark.parametrize("with_extra", [False, True])
def test_signed_payload_crit_rejects_invalid_declarations(
        profile, critical, with_extra, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["crit"] = critical
    if with_extra:
        payload["extension"] = ""
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert "crit" in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("value", ["", [""], None, False, 0, [], {}, "present"])
def test_signed_unsupported_critical_extension_and_noncritical_control(
        profile, value, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["extension"] = value
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.raw_token() == token
    payload["crit"] = ["extension"]
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload() == payload
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, UnknownCriticalExtension)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("claim", ["iat", "exp"])
@pytest.mark.parametrize("value", [str(NOW), "", True, False, None, [], {},
                                    float("nan"), float("inf"), float("-inf")])
def test_signed_numeric_dates_reject_original_invalid_types(profile, claim, value, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload[claim] = value
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    decoded = jws_factory(token).jwt.payload()[claim]
    assert type(decoded) is type(value)
    assert json.dumps(decoded) == json.dumps(value)
    with pytest.raises(FederationJwtPayloadError):
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("iat,exp", [
    (0, NOW + 600), (0.0, NOW + 600.0), (NOW - 10, NOW + 600),
    (float(NOW - 10), float(NOW + 600)), (NOW - 10.25, NOW + 600.75),
])
def test_signed_numeric_dates_preserve_values_types_and_token(profile, iat, exp, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload.update(iat=iat, exp=exp)
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    decoded = jws_factory(token).jwt.payload()
    verified = verify_federation_jwt(profile, token.encode("ascii"), keyjar_for(container_signing_key), now=NOW)
    for claim, value in (("iat", iat), ("exp", exp)):
        assert decoded[claim] == verified.claims()[claim] == verified.message()[claim] == value
        assert type(decoded[claim]) is type(value)
        assert type(verified.claims()[claim]) is type(value)
        assert type(verified.message()[claim]) is type(value)
    assert verified.raw_token() == token
    assert verified.raw_token_bytes() == token.encode("ascii")


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("case,accepted", [
    ("expired-zero", False), ("expired", False), ("future-iat", False),
    ("fractional-expiry-rounding", False), ("fractional-expiry-valid", True),
    ("iat-at-skew", True), ("iat-past-skew", False),
])
def test_numeric_dates_retain_dependency_time_boundaries(profile, case, accepted, container_signing_key):
    skew = JWT().skew
    payload = payload_for(profile, container_signing_key)
    payload["iat"] = NOW - 100
    if case == "expired-zero":
        payload["exp"] = 0
    elif case == "expired":
        payload["exp"] = NOW - skew - 100
    elif case == "future-iat":
        payload["iat"] = NOW + skew + 100
    elif case == "fractional-expiry-rounding":
        # Cryptojwt truncates exp before comparison; this representation fix retains it.
        payload["exp"] = NOW - skew + 0.5
    elif case == "fractional-expiry-valid":
        payload["exp"] = NOW - skew + 1.25
    elif case == "iat-at-skew":
        payload["iat"] = float(NOW + skew)
    else:
        payload["iat"] = NOW + skew + 0.25
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ},
    )
    assert jws_factory(token).jwt.payload() == payload
    if accepted:
        verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
        assert verified.message()["iat"] == payload["iat"]
        assert verified.message()["exp"] == payload["exp"]
    else:
        with pytest.raises(FederationJwtPayloadError):
            verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("value", [
    None, {}, {"keys": {}}, {"keys": [12]}, [], [None], [""], "",
    '{"keys": []}', {"keys": None}, {"keys": 12}, {"keys": "[]"},
])
def test_signed_statement_rejects_malformed_jwks(profile, value, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    payload["jwks"] = value
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload()["jwks"] == value
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert "jwks" in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
def test_signed_statement_requires_jwks(profile, container_signing_key):
    payload = payload_for(profile, container_signing_key)
    del payload["jwks"]
    token = sign(profile, container_signing_key, payload)
    assert "jwks" not in jws_factory(token).jwt.payload()
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert "jwks" in str(error.value.__cause__)


@pytest.mark.parametrize("profile", [registry.ENTITY_CONFIGURATION, registry.SUBORDINATE_STATEMENT])
@pytest.mark.parametrize("kind", ["empty", "public", "extension", "unknown-key"])
def test_signed_statement_valid_jwks_containers(profile, kind, container_signing_key):
    jwks = {"keys": []}
    if kind != "empty":
        jwks["keys"].append(container_signing_key.serialize(private=False))
    if kind == "extension":
        jwks["custom"] = "extension"
    if kind == "unknown-key":
        jwks["keys"].append({"kty": "future-key-type"})
    payload = payload_for(profile, container_signing_key)
    payload["jwks"] = jwks
    token = sign(profile, container_signing_key, payload)
    assert jws_factory(token).jwt.payload()["jwks"] == jwks
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.message().to_dict()["jwks"] == jwks


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


@pytest.mark.parametrize("claim", ["metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint"])
@pytest.mark.parametrize("value", [{}, [], None, False, 0, "", [""], "present"])
def test_signed_entity_configuration_rejects_subordinate_only_claims(signing_key, claim, value):
    profile = registry.ENTITY_CONFIGURATION
    payload = payload_for(profile, signing_key)
    payload[claim] = value
    token = sign(profile, signing_key, payload)
    assert header(token)["typ"] == "entity-statement+jwt"
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile=profile, token=token,
                              key_jar=keyjar_for(signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert claim in str(error.value.__cause__)


@pytest.mark.parametrize("claims", [
    {"constraints": {"max_path_length": 0}},
    {"metadata_policy": {"federation_entity": {"organization_name": {"value": "Name"}}}},
    {"source_endpoint": "https://issuer.example.org/fetch"},
])
def test_signed_subordinate_only_claims_remain_valid(signing_key, claims):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, signing_key)
    payload.update(claims)
    token = sign(profile, signing_key, payload)
    verified = verify_federation_jwt(profile=profile, token=token,
                                     key_jar=keyjar_for(signing_key), now=NOW)
    assert verified.profile is profile
    assert verified.header()["typ"] == registry.ENTITY_CONFIGURATION.typ
    for claim, value in claims.items():
        assert verified.claims()[claim] == value


def test_signed_subordinate_critical_operator_retains_semantic_rejection(signing_key):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, signing_key)
    payload["metadata_policy_crit"] = ["regexp"]
    token = sign(profile, signing_key, payload)
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(profile=profile, token=token,
                              key_jar=keyjar_for(signing_key), now=NOW)
    assert isinstance(error.value.__cause__, MetadataPolicyCritError)


@pytest.fixture(scope="module")
def ec_only_claim_values(container_signing_key):
    mark_payload = payload_for(registry.TRUST_MARK, container_signing_key)
    mark_payload["sub"] = ISSUER
    mark = sign(registry.TRUST_MARK, container_signing_key, mark_payload)
    verified_mark = verify_federation_jwt(registry.TRUST_MARK, mark,
                                          keyjar_for(container_signing_key), now=NOW)
    mark_type = verified_mark.claims()["trust_mark_type"]
    return {
        "authority_hints": ["https://superior.example.org"],
        "trust_anchor_hints": ["https://anchor.example.org"],
        "trust_marks": [{"trust_mark_type": mark_type, "trust_mark": mark}],
        "trust_mark_issuers": {mark_type: [ISSUER]},
        "trust_mark_owners": {mark_type: {
            "sub": ISSUER, "jwks": {"keys": [container_signing_key.serialize(private=False)]},
        }},
    }


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints", "trust_marks",
                                   "trust_mark_issuers", "trust_mark_owners"])
@pytest.mark.parametrize("value", [[], {}, None, False, 0, "", [""], "normal-shape"])
def test_signed_subordinate_rejects_ec_only_claims(
        container_signing_key, ec_only_claim_values, claim, value):
    if value == "normal-shape":
        value = ec_only_claim_values[claim]
    payload = payload_for(registry.SUBORDINATE_STATEMENT, container_signing_key)
    payload[claim] = value
    token = sign(registry.SUBORDINATE_STATEMENT, container_signing_key, payload)
    decoded = jws_factory(token).jwt.payload()
    assert claim in decoded
    assert decoded[claim] == value
    assert decoded["jwks"] == {"keys": []}
    with pytest.raises(FederationJwtPayloadError) as error:
        verify_federation_jwt(registry.SUBORDINATE_STATEMENT, token,
                              keyjar_for(container_signing_key), now=NOW)
    assert isinstance(error.value.__cause__, ValueError)
    assert claim in str(error.value.__cause__)


def test_signed_ec_retains_ec_only_claims(container_signing_key, ec_only_claim_values):
    payload = payload_for(registry.ENTITY_CONFIGURATION, container_signing_key)
    payload.update(ec_only_claim_values)
    token = sign(registry.ENTITY_CONFIGURATION, container_signing_key, payload)
    verified = verify_federation_jwt(registry.ENTITY_CONFIGURATION, token,
                                     keyjar_for(container_signing_key), now=NOW)
    projected = verified.message().to_dict()
    for claim, value in ec_only_claim_values.items():
        actual = projected[claim]
        if isinstance(actual, str):
            actual = json.loads(actual)
        elif claim == "trust_marks":
            actual = [json.loads(entry) if isinstance(entry, str) else entry
                      for entry in actual]
        assert actual == value


@pytest.fixture(scope="module")
def signed_statement_chain(container_signing_key):
    key = container_signing_key
    leaf_payload = payload_for(registry.ENTITY_CONFIGURATION, key)
    leaf_payload.update(iss=SUBJECT, sub=SUBJECT, authority_hints=[ISSUER])
    leaf_keys = KeyJar()
    leaf_keys.add_keys(SUBJECT, [key])
    leaf = sign_federation_jwt(
        registry.ENTITY_CONFIGURATION, leaf_payload, leaf_keys, SUBJECT, "RS256",
        kid=key.kid, iat=leaf_payload["iat"],
    )
    verify_federation_jwt(registry.ENTITY_CONFIGURATION, leaf, leaf_keys, now=NOW)
    parent_payload = payload_for(registry.SUBORDINATE_STATEMENT, key)
    parent_payload["jwks"] = leaf_payload["jwks"]
    parent = sign(registry.SUBORDINATE_STATEMENT, key, parent_payload)
    verify_federation_jwt(registry.SUBORDINATE_STATEMENT, parent, keyjar_for(key), now=NOW)
    anchor = sign(registry.ENTITY_CONFIGURATION, key)
    verify_federation_jwt(registry.ENTITY_CONFIGURATION, anchor, keyjar_for(key), now=NOW)
    return [leaf, parent, anchor]


@pytest.mark.parametrize("names", [
    ("trust_chain",), ("peer_trust_chain",), ("trust_chain", "peer_trust_chain"),
])
@pytest.mark.parametrize("value", [None, [], "", {}, {"not": "a chain"}, "real-chain"])
def test_subordinate_chain_headers_rejected_on_sign_and_receive(
        container_signing_key, signed_statement_chain, names, value):
    if value == "real-chain":
        value = signed_statement_chain
    extra = {name: value for name in names}
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    with pytest.raises(FederationJwtHeaderError, match="forbidden"):
        sign(profile, container_signing_key, payload, extra_protected_headers=extra)

    # Sign independently so the producer's prohibition cannot mask receive-path coverage.
    token = JWS(json.dumps(payload), alg="RS256").sign_compact(
        [container_signing_key], protected=dict(extra, typ=profile.typ),
    )
    for name in names:
        assert name in header(token)
        assert header(token)[name] == value
    assert jws_factory(token).verify_compact(token, [container_signing_key]) == payload
    for keys in (keyjar_for(container_signing_key), KeyJar(), object()):
        with pytest.raises(FederationJwtHeaderError, match="forbidden"):
            verify_federation_jwt(profile, token, keys, now=NOW)


@pytest.mark.parametrize("name", ["jku", "jwk", "x5u", "x5c"])
def test_subordinate_preserves_existing_header_bans(container_signing_key, name):
    profile = registry.SUBORDINATE_STATEMENT
    with pytest.raises(FederationJwtHeaderError, match="forbidden"):
        sign(profile, container_signing_key, extra_protected_headers={name: None})
    token = JWS(json.dumps(payload_for(profile, container_signing_key)), alg="RS256").sign_compact(
        [container_signing_key], protected={"typ": profile.typ, name: None},
    )
    with pytest.raises(FederationJwtHeaderError, match="forbidden"):
        verify_federation_jwt(profile, token, object(), now=NOW)


def test_resolve_preserves_protected_and_payload_trust_chains(
        container_signing_key, signed_statement_chain):
    profile = registry.RESOLVE_RESPONSE
    payload = payload_for(profile, container_signing_key)
    payload["trust_chain"] = signed_statement_chain
    token = sign(profile, container_signing_key, payload,
                 extra_protected_headers={"trust_chain": signed_statement_chain})
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    assert verified.header()["trust_chain"] == tuple(signed_statement_chain)
    assert verified.claims()["trust_chain"] == tuple(signed_statement_chain)
    assert verified.raw_token() == token


def test_subordinate_header_ban_does_not_ban_payload_names(
        container_signing_key, signed_statement_chain):
    profile = registry.SUBORDINATE_STATEMENT
    payload = payload_for(profile, container_signing_key)
    payload.update(trust_chain=signed_statement_chain, peer_trust_chain=signed_statement_chain)
    token = sign(profile, container_signing_key, payload)
    verified = verify_federation_jwt(profile, token, keyjar_for(container_signing_key), now=NOW)
    for name in ("trust_chain", "peer_trust_chain"):
        assert name not in verified.header()
        assert verified.claims()[name] == tuple(signed_statement_chain)


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
