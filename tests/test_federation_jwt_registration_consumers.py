"""Canonical verification tests for federation registration consumers."""

import base64
import inspect
import json
import time
from types import SimpleNamespace

from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory as jws_factory
import pytest

from fedservice.appclient.oauth2 import registration as oauth_module
from fedservice.appclient.oidc import registration as oidc_module
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.errors import FederationJwtSignatureError
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION


SERVER = "https://server.example.org"
CLIENT = "https://client.example.org"
TRUST_ANCHOR = "https://trust-anchor.example.org"


def signed_registration_response(metadata_type):
    key = new_rsa_key(kid="server-key")
    keyjar = KeyJar()
    keyjar.add_keys(SERVER, [key])
    now = int(time.time())
    token = sign_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        payload={
            "sub": SERVER,
            "metadata": {
                metadata_type: {
                    "client_id": CLIENT,
                    "redirect_uris": ["https://client.example.org/cb"],
                }
            },
            "trust_anchor": TRUST_ANCHOR,
        },
        key_jar=keyjar,
        issuer=SERVER,
        alg="RS256",
        kid=key.kid,
        lifetime=600,
        iat=now,
    )
    return token, keyjar


def replace_protected_header(token, header):
    encoded = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=")
    parts = token.split(".")
    parts[0] = encoded.decode("ascii")
    return ".".join(parts)


def corrupt_signature(token):
    parts = token.split(".")
    replacement = "A" if parts[2][0] != "A" else "B"
    parts[2] = replacement + parts[2][1:]
    return ".".join(parts)


def consumer_service(client_module, context):
    def upstream_get(item, name=None):
        if (item, name) == ("attribute", "entity_id"):
            return CLIENT
        if item == "context":
            return context
        raise AssertionError((item, name))

    if client_module is oauth_module:
        return SimpleNamespace(upstream_get=upstream_get)

    service = object.__new__(oidc_module.Registration)
    service.upstream_get = upstream_get
    return service


def invoke_consumer(
    monkeypatch,
    client_module,
    metadata_type,
    token,
    keyjar,
    metadata_verifier=None,
):
    collector = SimpleNamespace(trust_anchors={TRUST_ANCHOR: {}})
    federation_entity = SimpleNamespace(
        keyjar=keyjar,
        function=SimpleNamespace(trust_chain_collector=collector),
        get_function=lambda name: metadata_verifier,
    )
    context = SimpleNamespace(registration_response=None)
    service = consumer_service(client_module, context)
    chain = SimpleNamespace(
        anchor=TRUST_ANCHOR,
        verified_chain=[
            {
                "metadata": {
                    "original": {"value": True},
                }
            }
        ],
    )
    policy_calls = []

    monkeypatch.setattr(
        client_module,
        "get_federation_entity",
        lambda unit: federation_entity,
    )
    monkeypatch.setattr(
        client_module,
        "get_verified_trust_chains",
        lambda *args, **kwargs: [chain],
    )
    monkeypatch.setattr(
        client_module,
        "apply_policies",
        lambda entity, chains: policy_calls.append((entity, chains)) or chains,
    )

    if client_module is oauth_module:
        result = client_module.parse_federation_registration_response(
            service,
            token,
        )
    else:
        result = service.parse_federation_registration_response(token)

    return SimpleNamespace(
        result=result,
        context=context,
        federation_entity=federation_entity,
        chain=chain,
        policy_calls=policy_calls,
    )


@pytest.mark.parametrize(
    "client_module,metadata_type",
    [
        (oauth_module, "oauth_client"),
        (oidc_module, "openid_relying_party"),
    ],
    ids=["oauth2", "oidc"],
)
def test_registration_consumer_uses_canonical_profile_and_shared_keyjar(
    monkeypatch,
    client_module,
    metadata_type,
):
    token, keyjar = signed_registration_response(metadata_type)
    real_verify = client_module.verify_federation_jwt
    calls = []

    def record_verification(**kwargs):
        calls.append(kwargs)
        return real_verify(**kwargs)

    monkeypatch.setattr(
        client_module,
        "verify_federation_jwt",
        record_verification,
    )

    outcome = invoke_consumer(
        monkeypatch,
        client_module,
        metadata_type,
        token,
        keyjar,
    )

    assert calls == [
        {
            "profile": ENTITY_CONFIGURATION,
            "token": token,
            "key_jar": keyjar,
        }
    ]
    metadata = outcome.result["metadata"]
    assert type(metadata) is dict
    assert type(metadata[metadata_type]) is dict
    assert type(metadata[metadata_type]["redirect_uris"]) is list
    assert metadata[metadata_type]["client_id"] == CLIENT
    assert outcome.context.registration_response is outcome.result
    assert outcome.chain.verified_chain[-1]["metadata"] is metadata
    assert outcome.policy_calls == [
        (outcome.federation_entity, [outcome.chain])
    ]


@pytest.mark.parametrize(
    "client_module,metadata_type",
    [
        (oauth_module, "oauth_client"),
        (oidc_module, "openid_relying_party"),
    ],
    ids=["oauth2", "oidc"],
)
def test_registration_consumer_preserves_raw_metadata_verifier_token(
    monkeypatch,
    client_module,
    metadata_type,
):
    token, keyjar = signed_registration_response(metadata_type)
    verifier_calls = []
    verifier_result = {"verified": "externally"}

    def metadata_verifier(value):
        verifier_calls.append(value)
        return verifier_result

    outcome = invoke_consumer(
        monkeypatch,
        client_module,
        metadata_type,
        token,
        keyjar,
        metadata_verifier=metadata_verifier,
    )

    assert outcome.result is verifier_result
    assert verifier_calls == [token]
    assert outcome.policy_calls == []
    assert outcome.context.registration_response is None


@pytest.mark.parametrize(
    "client_module,metadata_type",
    [
        (oauth_module, "oauth_client"),
        (oidc_module, "openid_relying_party"),
    ],
    ids=["oauth2", "oidc"],
)
@pytest.mark.parametrize(
    "variant,expected_error",
    [
        ("missing-typ", FederationJwtHeaderError),
        ("sibling-typ", FederationJwtHeaderError),
        ("missing-kid", FederationJwtHeaderError),
        ("bad-signature", FederationJwtSignatureError),
    ],
)
def test_registration_consumer_rejects_invalid_jose(
    monkeypatch,
    client_module,
    metadata_type,
    variant,
    expected_error,
):
    token, keyjar = signed_registration_response(metadata_type)
    if variant == "bad-signature":
        token = corrupt_signature(token)
    else:
        header = dict(jws_factory(token).jwt.headers)
        if variant == "missing-typ":
            del header["typ"]
        elif variant == "sibling-typ":
            header["typ"] = "trust-mark+jwt"
        else:
            del header["kid"]
        token = replace_protected_header(token, header)

    with pytest.raises(expected_error):
        invoke_consumer(
            monkeypatch,
            client_module,
            metadata_type,
            token,
            keyjar,
        )


def test_registration_consumers_have_no_direct_cryptojwt_unpack():
    consumers = [
        oauth_module.parse_federation_registration_response,
        oidc_module.Registration.parse_federation_registration_response,
    ]

    for consumer in consumers:
        source = inspect.getsource(consumer)
        assert "JWT(" not in source
        assert ".unpack(" not in source
        assert "verify_federation_jwt(" in source
        assert "mutable_verified_claims(" in source
