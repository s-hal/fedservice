"""Profile-aware trust-chain Entity Statement verification tests."""

from cryptojwt import KeyJar
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwt import utc_time_sans_frac
import pytest

from fedservice.entity.function import verifier as verifier_module
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.federation_jwt.verified import deep_freeze


TA = "https://ta.example.org"
INTERMEDIATE = "https://intermediate.example.org"
LEAF = "https://leaf.example.org"


def signing_material(issuer, kid):
    key = new_rsa_key(kid=kid)
    key_jar = KeyJar()
    key_jar.add_keys(issuer, [key])
    return key, key_jar


def public_key(key):
    return key_from_jwk_dict(key.serialize(private=False))


def public_jwks(key_jar, issuer):
    return key_jar.export_jwks(private=False, issuer_id=issuer)


def verifier_with_keyjar(key_jar):
    def upstream_get(item, name=None):
        assert (item, name) == ("attribute", "keyjar")
        return key_jar

    return TrustChainVerifier(upstream_get=upstream_get)


def sign_statement(profile, payload, key_jar, issuer, kid, now):
    return sign_federation_jwt(
        profile=profile,
        payload=payload,
        key_jar=key_jar,
        issuer=issuer,
        alg="RS256",
        kid=kid,
        lifetime=600,
        iat=now,
    )


def real_chain(leaf_jwks=None, superior_leaf_key=None, leaf_material=None):
    ta_key, ta_signing = signing_material(TA, "ta-key")
    _intermediate_key, intermediate_signing = signing_material(
        INTERMEDIATE, "intermediate-key"
    )
    if leaf_material is None:
        leaf_key, leaf_signing = signing_material(LEAF, "leaf-key")
    else:
        leaf_key, leaf_signing = leaf_material
    if superior_leaf_key is None:
        superior_leaf_key = leaf_key

    shared_keyjar = KeyJar()
    shared_keyjar.add_keys(TA, [public_key(ta_key)])
    now = utc_time_sans_frac()
    chain = [
        sign_statement(
            SUBORDINATE_STATEMENT,
            {
                "sub": INTERMEDIATE,
                "jwks": public_jwks(intermediate_signing, INTERMEDIATE),
            },
            ta_signing,
            TA,
            "ta-key",
            now,
        ),
        sign_statement(
            SUBORDINATE_STATEMENT,
            {
                "sub": LEAF,
                "jwks": {
                    "keys": [superior_leaf_key.serialize(private=False)],
                },
            },
            intermediate_signing,
            INTERMEDIATE,
            "intermediate-key",
            now,
        ),
    ]
    leaf_payload = {
        "sub": LEAF,
        "metadata": {
            "federation_entity": {
                "contacts": ["ops@example.org"],
            }
        },
    }
    if leaf_jwks is not None:
        leaf_payload["jwks"] = leaf_jwks
    chain.append(
        sign_statement(
            ENTITY_CONFIGURATION,
            leaf_payload,
            leaf_signing,
            LEAF,
            "leaf-key",
            now,
        )
    )
    return chain, shared_keyjar, leaf_key


class FrozenVerified:
    def __init__(self, claims):
        self._claims = deep_freeze(claims)

    def claims(self):
        return self._claims

    def header(self):
        return {"alg": "RS256", "kid": "test-key"}


def test_profile_selection_uses_chain_position_not_payload_content(monkeypatch):
    intermediate_key, intermediate_signing = signing_material(
        INTERMEDIATE, "intermediate-key"
    )
    claims = [
        {
            "iss": INTERMEDIATE,
            "sub": INTERMEDIATE,
            "iat": 1,
            "exp": 2,
            "jwks": public_jwks(intermediate_signing, INTERMEDIATE),
        },
        {
            "iss": INTERMEDIATE,
            "sub": LEAF,
            "iat": 1,
            "exp": 2,
        },
    ]
    profiles = []

    def record_verification(**kwargs):
        profiles.append(kwargs["profile"])
        return FrozenVerified(claims[len(profiles) - 1])

    monkeypatch.setattr(verifier_module, "verify_federation_jwt", record_verification)

    result = verifier_with_keyjar(KeyJar())._verify_trust_chain(["first", "final"])

    assert result
    assert profiles == [SUBORDINATE_STATEMENT, ENTITY_CONFIGURATION]


def test_real_chain_verifies_with_staged_subject_keys(monkeypatch):
    chain, shared_keyjar, _leaf_key = real_chain()
    real_verify = verifier_module.verify_federation_jwt
    calls = []

    def record_verification(**kwargs):
        calls.append(
            {
                "profile": kwargs["profile"],
                "owners": set(shared_keyjar.owners()),
                "resolver": kwargs["key_resolver"],
            }
        )
        return real_verify(**kwargs)

    monkeypatch.setattr(verifier_module, "verify_federation_jwt", record_verification)

    verified_chain = verifier_with_keyjar(shared_keyjar)._verify_trust_chain(chain)

    assert [call["profile"] for call in calls] == [
        SUBORDINATE_STATEMENT,
        SUBORDINATE_STATEMENT,
        ENTITY_CONFIGURATION,
    ]
    assert INTERMEDIATE not in calls[0]["owners"]
    assert INTERMEDIATE in calls[1]["owners"]
    assert LEAF in calls[2]["owners"]
    assert calls[0]["resolver"] is calls[1]["resolver"] is calls[2]["resolver"]
    assert [payload["iss"] for payload in verified_chain] == [TA, INTERMEDIATE, LEAF]


def test_verified_chain_payloads_are_mutable_json_values():
    chain, shared_keyjar, _leaf_key = real_chain()

    verified_chain = verifier_with_keyjar(shared_keyjar)._verify_trust_chain(chain)
    leaf_payload = verified_chain[-1]

    assert type(leaf_payload) is dict
    assert type(leaf_payload["metadata"]) is dict
    assert type(leaf_payload["metadata"]["federation_entity"]) is dict
    assert type(leaf_payload["metadata"]["federation_entity"]["contacts"]) is list
    leaf_payload["metadata"]["federation_entity"]["contacts"].append(
        "security@example.org"
    )
    assert leaf_payload["metadata"]["federation_entity"]["contacts"][-1] == (
        "security@example.org"
    )


def test_final_entity_configuration_does_not_use_its_embedded_jwks():
    actual_leaf_key, actual_leaf_signing = signing_material(LEAF, "leaf-key")
    wrong_leaf_key = new_rsa_key(kid="leaf-key")
    chain, shared_keyjar, _unused = real_chain(
        leaf_jwks=public_jwks(actual_leaf_signing, LEAF),
        superior_leaf_key=wrong_leaf_key,
        leaf_material=(actual_leaf_key, actual_leaf_signing),
    )

    with pytest.raises(FederationJwtSignatureError):
        verifier_with_keyjar(shared_keyjar)._verify_trust_chain(chain)


def test_non_final_statement_without_jwks_keeps_existing_failure():
    ta_key, ta_signing = signing_material(TA, "ta-key")
    leaf_key, leaf_signing = signing_material(LEAF, "leaf-key")
    shared_keyjar = KeyJar()
    shared_keyjar.add_keys(TA, [public_key(ta_key)])
    now = utc_time_sans_frac()
    chain = [
        sign_statement(
            SUBORDINATE_STATEMENT,
            {"sub": LEAF},
            ta_signing,
            TA,
            "ta-key",
            now,
        ),
        sign_statement(
            ENTITY_CONFIGURATION,
            {"sub": LEAF},
            leaf_signing,
            LEAF,
            "leaf-key",
            now,
        ),
    ]

    with pytest.raises(ValueError, match="^Missing signing JWKS$"):
        verifier_with_keyjar(shared_keyjar)._verify_trust_chain(chain)
