"""Canonical Entity Configuration verification in the List consumer."""

import inspect
import json
import time
from types import SimpleNamespace

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
import pytest

from fedservice.entity.server import list as list_module
from fedservice.entity.server.list import List
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION


SUBORDINATE = "https://subordinate.example.org"
TRUST_MARK_TYPE = "https://trust-mark.example.org"


def signed_entity_configuration():
    key = new_rsa_key(kid="subordinate-key")
    signing_keyjar = KeyJar()
    signing_keyjar.add_keys(SUBORDINATE, [key])
    now = int(time.time())
    payload = {
        "iss": SUBORDINATE,
        "sub": SUBORDINATE,
        "iat": now,
        "exp": now + 600,
        "metadata": {
            "federation_entity": {
                "contacts": ["ops@example.org"],
            }
        },
        "trust_marks": [
            {
                "trust_mark_type": TRUST_MARK_TYPE,
                "trust_mark": "signed-trust-mark",
            }
        ],
    }
    token = sign_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        payload=payload,
        key_jar=signing_keyjar,
        issuer=SUBORDINATE,
        alg="RS256",
        kid=key.kid,
        iat=now,
    )
    public_jwks = signing_keyjar.export_jwks(
        private=False,
        issuer_id=SUBORDINATE,
    )
    return token, payload, public_jwks, key, signing_keyjar


def list_endpoint(token, public_jwks, extended=False):
    subordinate = {
        SUBORDINATE: {
            "entity_type": ["federation_entity"],
            "jwks": public_jwks,
        }
    }
    collector = SimpleNamespace(
        get_entity_configuration=lambda entity_id: token,
    )
    federation_entity = SimpleNamespace(
        function=SimpleNamespace(trust_chain_collector=collector),
    )
    server_entity = SimpleNamespace(
        subordinate=subordinate,
        upstream_get=lambda item: federation_entity,
    )
    federation_entity.server = server_entity
    endpoint = object.__new__(List)
    endpoint.extended = extended
    endpoint.upstream_get = lambda item: server_entity
    return endpoint


def test_collect_subordinates_uses_canonical_profile_and_local_keyjar(monkeypatch):
    token, _payload, public_jwks, _key, _signing_keyjar = (
        signed_entity_configuration()
    )
    endpoint = list_endpoint(token, public_jwks)
    real_verify = list_module.verify_federation_jwt
    calls = []

    def record_verification(**kwargs):
        calls.append(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(
        list_module,
        "verify_federation_jwt",
        record_verification,
    )

    result = endpoint.collect_subordinates()

    assert len(calls) == 1
    assert calls[0]["profile"] is ENTITY_CONFIGURATION
    assert calls[0]["token"] == token
    assert isinstance(calls[0]["key_jar"], KeyJar)
    assert calls[0]["key_jar"].export_jwks(
        private=False,
        issuer_id=SUBORDINATE,
    ) == public_jwks
    assert result[SUBORDINATE]["iss"] == SUBORDINATE


def test_collect_subordinates_returns_mutable_json_and_preserves_filtering():
    token, _payload, public_jwks, _key, _signing_keyjar = (
        signed_entity_configuration()
    )
    endpoint = list_endpoint(token, public_jwks)

    result = endpoint.collect_subordinates()
    configuration = result[SUBORDINATE]

    assert type(configuration) is dict
    assert type(configuration["metadata"]) is dict
    assert type(configuration["metadata"]["federation_entity"]) is dict
    assert type(configuration["trust_marks"]) is list
    configuration["metadata"]["federation_entity"]["contacts"].append(
        "security@example.org"
    )
    assert endpoint.filter(result, trust_marked=True) == [SUBORDINATE]
    assert endpoint.filter(result, trust_mark_type=TRUST_MARK_TYPE) == [
        SUBORDINATE
    ]


def test_extended_list_response_remains_json_serializable():
    token, _payload, public_jwks, _key, _signing_keyjar = (
        signed_entity_configuration()
    )
    endpoint = list_endpoint(token, public_jwks, extended=True)

    response = endpoint.process_request({"trust_marked": True})
    payload = json.loads(response["response_msg"])

    assert payload[SUBORDINATE]["iss"] == SUBORDINATE
    assert payload[SUBORDINATE]["trust_marks"][0]["trust_mark_type"] == (
        TRUST_MARK_TYPE
    )


@pytest.mark.parametrize("typ", [None, "trust-mark+jwt"])
def test_collect_subordinates_rejects_invalid_profile_typ(typ):
    _token, payload, public_jwks, key, signing_keyjar = (
        signed_entity_configuration()
    )
    headers = {} if typ is None else {"typ": typ}
    token = JWT(
        key_jar=signing_keyjar,
        iss=SUBORDINATE,
        lifetime=600,
        sign_alg="RS256",
    ).pack(
        payload=payload,
        kid=key.kid,
        issuer_id=SUBORDINATE,
        iat=payload["iat"],
        jws_headers=headers,
    )
    endpoint = list_endpoint(token, public_jwks)

    with pytest.raises(FederationJwtHeaderError):
        endpoint.collect_subordinates()


def test_collect_subordinates_has_no_direct_cryptojwt_unpack():
    source = inspect.getsource(List.collect_subordinates)

    assert "JWT(" not in source
    assert ".unpack(" not in source
    assert "verify_federation_jwt(" in source
