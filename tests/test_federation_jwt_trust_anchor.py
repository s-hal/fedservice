"""Canonical Federation JWT verification for trust-anchor statements."""

import inspect
import time
from types import SimpleNamespace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key

from fedservice.entity.function import trust_anchor as trust_anchor_module
from fedservice.entity.function.trust_anchor import get_verified_trust_anchor_statement
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION


TRUST_ANCHOR = "https://trust-anchor.example.org"


def signed_trust_anchor_configuration():
    key = new_rsa_key(kid="trust-anchor-key")
    key_jar = KeyJar()
    key_jar.add_keys(TRUST_ANCHOR, [key])
    now = int(time.time())
    token = sign_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        payload={
            "iss": TRUST_ANCHOR,
            "sub": TRUST_ANCHOR,
            "iat": now - 10,
            "exp": now + 600,
            "metadata": {
                "federation_entity": {
                    "contacts": ["ops@example.org"],
                }
            },
        },
        key_jar=key_jar,
        issuer=TRUST_ANCHOR,
        alg="RS256",
        kid=key.kid,
        iat=now - 10,
    )
    return token, key_jar


def federation_entity(token, key_jar):
    collector = SimpleNamespace(
        get_entity_configuration=lambda entity_id: token,
    )
    return SimpleNamespace(
        function=SimpleNamespace(trust_chain_collector=collector),
        keyjar=key_jar,
    )


def test_trust_anchor_statement_uses_canonical_profile_and_shared_keyjar(
    monkeypatch,
):
    token, key_jar = signed_trust_anchor_configuration()
    entity = federation_entity(token, key_jar)
    real_verify = trust_anchor_module.verify_federation_jwt
    calls = []

    def record_verification(**kwargs):
        calls.append(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(
        trust_anchor_module,
        "verify_federation_jwt",
        record_verification,
    )

    result = get_verified_trust_anchor_statement(entity, TRUST_ANCHOR)

    assert len(calls) == 1
    assert calls[0] == {
        "profile": ENTITY_CONFIGURATION,
        "token": token,
        "key_jar": key_jar,
    }
    assert result["iss"] == TRUST_ANCHOR


def test_trust_anchor_statement_returns_mutable_json_mapping():
    token, key_jar = signed_trust_anchor_configuration()
    entity = federation_entity(token, key_jar)

    result = get_verified_trust_anchor_statement(entity, TRUST_ANCHOR)

    assert type(result) is dict
    assert type(result["metadata"]) is dict
    assert type(result["metadata"]["federation_entity"]) is dict
    assert type(result["metadata"]["federation_entity"]["contacts"]) is list
    result["metadata"]["federation_entity"]["contacts"].append(
        "security@example.org"
    )
    assert result["metadata"]["federation_entity"]["contacts"] == [
        "ops@example.org",
        "security@example.org",
    ]


def test_trust_anchor_helper_has_no_direct_jws_or_key_selection():
    source = inspect.getsource(get_verified_trust_anchor_statement)

    assert "factory(" not in source
    assert "get_jwt_verify_keys" not in source
    assert "verify_compact" not in source
