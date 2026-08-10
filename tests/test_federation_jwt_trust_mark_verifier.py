"""Canonical Federation JWT verification in the Trust Mark verifier."""

import base64
import inspect
import json
import time
from types import SimpleNamespace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwt import JWT
import pytest

from fedservice.entity.function import trust_mark_verifier as verifier_module
from fedservice.entity.function.trust_mark_verifier import TrustMarkVerifier
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import TRUST_MARK
from fedservice.federation_jwt.registry import TRUST_MARK_DELEGATION
from fedservice.message import TrustMarkDelegation


TRUST_ANCHOR = "https://trust-anchor.example.org"
TRUST_MARK_OWNER = "https://trust-mark-owner.example.org"
SUBJECT = "https://subject.example.org"
TRUST_MARK_TYPE = "https://example.org/trust-mark"


def signing_material():
    key = new_rsa_key(kid="trust-mark-key")
    key_jar = KeyJar()
    key_jar.add_keys(TRUST_ANCHOR, [key])
    return key, key_jar


def trust_mark_token(key, key_jar, exp_marker="future"):
    now = int(time.time())
    payload = {
        "iss": TRUST_ANCHOR,
        "sub": SUBJECT,
        "iat": now - 120,
        "trust_mark_type": TRUST_MARK_TYPE,
    }
    if exp_marker == "future":
        payload["exp"] = now + 600
    elif exp_marker == "within-skew":
        payload["exp"] = now - max(1, JWT().skew // 2)
    elif exp_marker == "expired":
        payload["exp"] = now - JWT().skew - 60

    return sign_federation_jwt(
        profile=TRUST_MARK,
        payload=payload,
        key_jar=key_jar,
        issuer=TRUST_ANCHOR,
        alg="RS256",
        kid=key.kid,
        iat=payload["iat"],
    )


def trust_mark_verifier(monkeypatch, key_jar, statement=None):
    if statement is None:
        statement = {
            "iss": TRUST_ANCHOR,
            "jwks": key_jar.export_jwks(issuer_id=TRUST_ANCHOR),
            "trust_mark_issuers": {TRUST_MARK_TYPE: []},
        }
    monkeypatch.setattr(
        verifier_module,
        "get_verified_trust_anchor_statement",
        lambda entity, trust_anchor: statement,
    )
    monkeypatch.setattr(
        verifier_module,
        "get_verified_trust_chains",
        lambda *args, **kwargs: pytest.fail(
            "local Trust Mark verification must not fetch"
        ),
    )
    federation_entity = SimpleNamespace(get_attribute=lambda name: key_jar)
    return TrustMarkVerifier(federation_entity=federation_entity)


def delegated_material():
    outer_key, outer_key_jar = signing_material()
    owner_key = new_rsa_key(kid="delegation-key")
    owner_key_jar = KeyJar()
    owner_key_jar.add_keys(TRUST_MARK_OWNER, [owner_key])
    statement = {
        "iss": TRUST_ANCHOR,
        "jwks": outer_key_jar.export_jwks(issuer_id=TRUST_ANCHOR),
        "trust_mark_issuers": {TRUST_MARK_TYPE: []},
        "trust_mark_owners": {
            TRUST_MARK_TYPE: {
                "sub": TRUST_MARK_OWNER,
                "jwks": owner_key_jar.export_jwks(issuer_id=TRUST_MARK_OWNER),
            }
        },
    }
    return outer_key, outer_key_jar, owner_key, owner_key_jar, statement


def delegation_token(owner_key, owner_key_jar, **overrides):
    now = int(time.time())
    payload = {
        "iss": TRUST_MARK_OWNER,
        "sub": TRUST_ANCHOR,
        "trust_mark_type": TRUST_MARK_TYPE,
        "iat": now - 10,
        "exp": now + 600,
    }
    payload.update(overrides)
    return sign_federation_jwt(
        profile=TRUST_MARK_DELEGATION,
        payload=payload,
        key_jar=owner_key_jar,
        issuer=payload["iss"],
        alg="RS256",
        kid=owner_key.kid,
        iat=payload["iat"],
    )


def delegated_trust_mark_token(outer_key, outer_key_jar, delegation=None):
    now = int(time.time())
    payload = {
        "iss": TRUST_ANCHOR,
        "sub": SUBJECT,
        "trust_mark_type": TRUST_MARK_TYPE,
        "iat": now - 10,
        "exp": now + 600,
    }
    if delegation is not None:
        payload["delegation"] = delegation
    return sign_federation_jwt(
        profile=TRUST_MARK,
        payload=payload,
        key_jar=outer_key_jar,
        issuer=TRUST_ANCHOR,
        alg="RS256",
        kid=outer_key.kid,
        iat=payload["iat"],
    )


def replace_protected_header(token, header):
    encoded = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    _protected, payload, signature = token.split(".")
    return ".".join([encoded, payload, signature])


def corrupt_signature(token):
    protected, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    return ".".join([protected, payload, replacement + signature[1:]])


@pytest.mark.parametrize(
    "exp_marker",
    ["future", "within-skew", None],
    ids=["unexpired", "within-skew", "without-exp"],
)
def test_canonical_trust_mark_verification_accepts_valid_lifetimes(
        monkeypatch, exp_marker
):
    key, key_jar = signing_material()
    token = trust_mark_token(key, key_jar, exp_marker=exp_marker)
    verifier = trust_mark_verifier(monkeypatch, key_jar)

    claims = verifier(token, trust_anchor=TRUST_ANCHOR)

    assert claims["iss"] == TRUST_ANCHOR
    assert claims["sub"] == SUBJECT
    assert claims["trust_mark_type"] == TRUST_MARK_TYPE
    assert isinstance(claims["iat"], int)
    if exp_marker is None:
        assert "exp" not in claims


def test_canonical_trust_mark_verification_rejects_expired_token(monkeypatch):
    key, key_jar = signing_material()
    token = trust_mark_token(key, key_jar, exp_marker="expired")
    verifier = trust_mark_verifier(monkeypatch, key_jar)

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None


def test_canonical_trust_mark_verification_rejects_bad_signature(monkeypatch):
    _trusted_key, key_jar = signing_material()
    untrusted_key = new_rsa_key(kid="trust-mark-key")
    untrusted_key_jar = KeyJar()
    untrusted_key_jar.add_keys(TRUST_ANCHOR, [untrusted_key])
    token = trust_mark_token(untrusted_key, untrusted_key_jar)
    verifier = trust_mark_verifier(monkeypatch, key_jar)

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None


def test_final_verification_uses_canonical_profile_and_local_keyjar(
        monkeypatch
):
    key, key_jar = signing_material()
    token = trust_mark_token(key, key_jar)
    verifier = trust_mark_verifier(monkeypatch, key_jar)
    real_verify = verifier_module.verify_federation_jwt
    captured = {}

    def record_verification(**kwargs):
        captured.update(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(
        verifier_module,
        "verify_federation_jwt",
        record_verification,
    )

    claims = verifier(token, trust_anchor=TRUST_ANCHOR)

    assert claims["trust_mark_type"] == TRUST_MARK_TYPE
    assert captured["profile"] is TRUST_MARK
    assert captured["key_jar"] is key_jar


def test_outer_verification_has_no_consumer_side_key_selection_or_import():
    source = inspect.getsource(TrustMarkVerifier.__call__)

    assert "factory(" not in source
    assert "get_jwt_verify_keys" not in source
    assert "import_jwks" not in source


def test_missing_outer_keys_fail_through_canonical_verifier(monkeypatch):
    signing_key, signing_key_jar = signing_material()
    token = trust_mark_token(signing_key, signing_key_jar)
    empty_key_jar = KeyJar()
    statement = {
        "iss": TRUST_ANCHOR,
        "jwks": signing_key_jar.export_jwks(issuer_id=TRUST_ANCHOR),
        "trust_mark_issuers": {TRUST_MARK_TYPE: []},
    }
    verifier = trust_mark_verifier(monkeypatch, empty_key_jar, statement)
    real_verify = verifier_module.verify_federation_jwt
    calls = []

    def record_verification(**kwargs):
        calls.append(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(
        verifier_module,
        "verify_federation_jwt",
        record_verification,
    )

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None
    assert len(calls) == 1
    assert calls[0]["profile"] is TRUST_MARK
    assert calls[0]["key_jar"] is empty_key_jar


def test_malformed_compact_trust_mark_fails_verification(monkeypatch):
    _key, key_jar = signing_material()
    verifier = trust_mark_verifier(monkeypatch, key_jar)

    assert verifier("not-a-compact-jwt", trust_anchor=TRUST_ANCHOR) is None


def test_delegated_trust_mark_uses_canonical_profiles_and_owner_local_keys(
    monkeypatch,
):
    outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = delegation_token(owner_key, owner_key_jar)
    token = delegated_trust_mark_token(outer_key, outer_key_jar, delegation)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)
    real_verify = verifier_module.verify_federation_jwt
    calls = []

    def record_verification(**kwargs):
        calls.append(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(
        verifier_module,
        "verify_federation_jwt",
        record_verification,
    )

    claims = verifier(token, trust_anchor=TRUST_ANCHOR)

    assert claims["delegation"] == delegation
    assert "__delegation" not in claims
    assert [call["profile"] for call in calls] == [
        TRUST_MARK,
        TRUST_MARK_DELEGATION,
    ]
    assert calls[0]["key_jar"] is outer_key_jar
    assert calls[1]["key_jar"] is not outer_key_jar
    owner_jwks = calls[1]["key_jar"].export_jwks(
        issuer_id=TRUST_MARK_OWNER
    )
    assert owner_jwks["keys"][0]["kid"] == owner_key.kid


def test_verify_delegation_preserves_payload_mapping_success_shape(monkeypatch):
    _outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = delegation_token(owner_key, owner_key_jar)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    result = verifier.verify_delegation(
        {
            "trust_mark_type": TRUST_MARK_TYPE,
            "delegation": delegation,
        },
        TRUST_ANCHOR,
        trust_anchor_statement=statement,
    )

    assert type(result) is dict
    assert result["iss"] == TRUST_MARK_OWNER


@pytest.mark.parametrize("missing", ["trust_mark_issuers", "trust_mark_owners"])
def test_verify_delegation_returns_none_for_missing_configuration(
    monkeypatch, missing
):
    _outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = delegation_token(owner_key, owner_key_jar)
    statement.pop(missing)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    result = verifier.verify_delegation(
        {
            "trust_mark_type": TRUST_MARK_TYPE,
            "delegation": delegation,
        },
        TRUST_ANCHOR,
        trust_anchor_statement=statement,
    )

    assert result is None


def test_delegation_issuer_must_match_configured_owner(monkeypatch):
    _outer_key, outer_key_jar, _owner_key, _owner_key_jar, statement = (
        delegated_material()
    )
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)
    outer_claims = {
        "iss": TRUST_ANCHOR,
        "trust_mark_type": TRUST_MARK_TYPE,
        "delegation": "delegation.jwt.value",
    }
    delegation_claims = {
        "iss": "https://wrong-owner.example.org",
        "sub": TRUST_ANCHOR,
        "trust_mark_type": TRUST_MARK_TYPE,
    }

    assert not verifier.check_delegation(
        statement,
        outer_claims,
        verified_delegation=delegation_claims,
    )


def test_invalid_outer_signature_stops_before_delegation_verification(monkeypatch):
    outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = delegation_token(
        owner_key,
        owner_key_jar,
        sub="https://wrong-issuer.example.org",
    )
    token = corrupt_signature(
        delegated_trust_mark_token(outer_key, outer_key_jar, delegation)
    )
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)
    real_verify = verifier_module.verify_federation_jwt
    profiles = []

    def record_verification(**kwargs):
        profiles.append(kwargs["profile"])
        return real_verify(**kwargs)

    monkeypatch.setattr(
        verifier_module,
        "verify_federation_jwt",
        record_verification,
    )

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None
    assert profiles == [TRUST_MARK]


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "RS256", "kid": "delegation-key"},
        {
            "alg": "RS256",
            "kid": "delegation-key",
            "typ": "trust-mark+jwt",
        },
        {"alg": "RS256", "typ": "trust-mark-delegation+jwt"},
    ],
    ids=["missing-typ", "wrong-typ", "missing-kid"],
)
def test_delegation_header_policy_failures_are_rejected(monkeypatch, header):
    outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = replace_protected_header(
        delegation_token(owner_key, owner_key_jar),
        header,
    )
    token = delegated_trust_mark_token(outer_key, outer_key_jar, delegation)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None


def test_delegation_bad_signature_is_rejected(monkeypatch):
    outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = corrupt_signature(delegation_token(owner_key, owner_key_jar))
    token = delegated_trust_mark_token(outer_key, outer_key_jar, delegation)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None


@pytest.mark.parametrize("owner_state", ["unknown-key", "malformed", "missing"])
def test_delegation_owner_key_failures_are_rejected(monkeypatch, owner_state):
    outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = delegation_token(owner_key, owner_key_jar)
    if owner_state == "unknown-key":
        other_key = new_rsa_key(kid="other-key")
        other_key_jar = KeyJar()
        other_key_jar.add_keys(TRUST_MARK_OWNER, [other_key])
        statement["trust_mark_owners"][TRUST_MARK_TYPE]["jwks"] = (
            other_key_jar.export_jwks(issuer_id=TRUST_MARK_OWNER)
        )
    elif owner_state == "malformed":
        statement["trust_mark_owners"][TRUST_MARK_TYPE]["jwks"] = {
            "keys": [{"not": "a-jwk"}]
        }
    else:
        statement["trust_mark_owners"] = {}
    token = delegated_trust_mark_token(outer_key, outer_key_jar, delegation)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None


@pytest.mark.parametrize(
    "claim,value",
    [
        ("sub", "https://wrong-issuer.example.org"),
        ("trust_mark_type", "https://example.org/wrong-mark"),
    ],
)
def test_delegation_cross_object_mismatches_are_rejected(
    monkeypatch, claim, value
):
    outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    delegation = delegation_token(owner_key, owner_key_jar, **{claim: value})
    token = delegated_trust_mark_token(outer_key, outer_key_jar, delegation)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None


def test_declared_owner_without_delegation_is_rejected(monkeypatch):
    outer_key, outer_key_jar, _owner_key, _owner_key_jar, statement = (
        delegated_material()
    )
    token = delegated_trust_mark_token(outer_key, outer_key_jar)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    assert verifier(token, trust_anchor=TRUST_ANCHOR) is None


@pytest.mark.parametrize(
    "claim,value_offset,accepted",
    [
        ("exp", lambda skew: -(max(1, skew // 2)), True),
        ("exp", lambda skew: -skew - 60, False),
        ("iat", lambda skew: max(1, skew // 2), True),
        ("iat", lambda skew: skew + 60, False),
    ],
    ids=["exp-within-skew", "expired", "iat-within-skew", "future-iat"],
)
def test_delegation_time_validation_uses_canonical_verifier(
    monkeypatch, claim, value_offset, accepted
):
    outer_key, outer_key_jar, owner_key, owner_key_jar, statement = (
        delegated_material()
    )
    value = int(time.time()) + value_offset(JWT().skew)
    delegation = delegation_token(owner_key, owner_key_jar, **{claim: value})
    token = delegated_trust_mark_token(outer_key, outer_key_jar, delegation)
    verifier = trust_mark_verifier(monkeypatch, outer_key_jar, statement)

    result = verifier(token, trust_anchor=TRUST_ANCHOR)

    assert (result is not None) is accepted


def test_trust_mark_delegation_schema_does_not_check_expiration():
    delegation = TrustMarkDelegation(
        iss=TRUST_MARK_OWNER,
        sub=TRUST_ANCHOR,
        trust_mark_type=TRUST_MARK_TYPE,
        iat=1,
        exp=1,
    )

    assert delegation.verify() is True
