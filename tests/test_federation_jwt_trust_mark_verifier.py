"""Canonical Federation JWT verification in the Trust Mark verifier."""

import time
from types import SimpleNamespace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
import pytest

from fedservice.entity.function import trust_mark_verifier as verifier_module
from fedservice.entity.function.trust_mark_verifier import TrustMarkVerifier
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import TRUST_MARK


TRUST_ANCHOR = "https://trust-anchor.example.org"
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
    elif exp_marker == "within-leeway":
        payload["exp"] = now - 30
    elif exp_marker == "expired":
        payload["exp"] = now - 120

    return sign_federation_jwt(
        profile=TRUST_MARK,
        payload=payload,
        key_jar=key_jar,
        issuer=TRUST_ANCHOR,
        alg="RS256",
        kid=key.kid,
        iat=payload["iat"],
    )


def trust_mark_verifier(monkeypatch, key_jar):
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


@pytest.mark.parametrize(
    "exp_marker",
    ["future", "within-leeway", None],
    ids=["unexpired", "within-leeway", "without-exp"],
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
    assert captured["key_resolver"]._keyjar is key_jar


def test_malformed_compact_trust_mark_fails_verification(monkeypatch):
    _key, key_jar = signing_material()
    verifier = trust_mark_verifier(monkeypatch, key_jar)

    assert verifier("not-a-compact-jwt", trust_anchor=TRUST_ANCHOR) is None
