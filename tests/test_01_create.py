from cryptojwt import KeyJar
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
import pytest

from fedservice.entity.function.trust_chain_collector import verify_self_signed_signature
from idpyoidc.key_import import import_jwks_as_json

from fedservice.entity_statement.create import create_entity_configuration
from fedservice.entity_statement.create import create_entity_statement
from fedservice.entity_statement.create import create_subordinate_statement
from fedservice.federation_jwt.errors import FederationJwtHeaderError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

RECEIVER = 'https://example.org/op'
ISSUER_ID = "https://example.org"

def test_create_self_signed():
    metadata = {
        "application_type": "web",
        "claims": [
            "sub",
            "name",
            "email",
            "picture"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS512"
        ],
        "redirect_uris": [
            "https://foodle.uninett.no/callback"
        ],
        "response_types": [
            "code"
        ]
    }

    iss = ISSUER_ID
    sub = iss

    sign_key_jar = KeyJar()
    _key = new_rsa_key(kid="signing-key")
    sign_key_jar.add_keys("", [_key])
    authority = ["https://ntnu.no"]

    _jwt = create_entity_statement(iss, sub, sign_key_jar, ENTITY_CONFIGURATION,
                                   metadata=metadata,
                                   authority_hints=authority,
                                   signing_alg="RS256")

    assert _jwt

    # _verifier = factory(_jwt)
    # verifier_key_jar = KeyJar()
    # verifier_key_jar.add_keys("", [key_from_jwk_dict(json_pub_key)])
    # res = _verifier.verify_compact(keys=keys)
    res = verify_self_signed_signature(_jwt)

    assert res
    assert res['iss'] == iss
    assert res['sub'] == sub
    assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                               'authority_hints', 'jwks'}


def test_entity_configuration_profile_output():
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER_ID, [new_rsa_key(kid="entity-key")])
    metadata = {"federation_entity": {"contacts": ["ops@example.org"]}}

    token = create_entity_configuration(
        ISSUER_ID,
        key_jar=key_jar,
        metadata=metadata,
    )
    verified = verify_federation_jwt(
        profile=ENTITY_CONFIGURATION,
        token=token,
        key_jar=key_jar,
    )

    assert factory(token).jwt.headers["typ"] == ENTITY_CONFIGURATION.typ
    assert verified.claims()["iss"] == ISSUER_ID
    assert verified.claims()["sub"] == ISSUER_ID
    assert verified.claims()["metadata"]["federation_entity"]["contacts"] == (
        "ops@example.org",
    )
    assert verified.claims()["exp"] - verified.claims()["iat"] == 86400


def test_subordinate_statement_profile_output():
    issuer = "https://issuer.example.org"
    subject = "https://subject.example.org"
    key_jar = KeyJar()
    key_jar.add_keys(issuer, [new_rsa_key(kid="issuer-key")])

    token = create_subordinate_statement(
        issuer,
        subject,
        key_jar=key_jar,
        metadata={"federation_entity": {"contacts": ["ops@example.org"]}},
        constraints={"max_path_length": 2},
    )
    verified = verify_federation_jwt(
        profile=SUBORDINATE_STATEMENT,
        token=token,
        key_jar=key_jar,
    )

    assert factory(token).jwt.headers["typ"] == SUBORDINATE_STATEMENT.typ
    assert verified.claims()["iss"] == issuer
    assert verified.claims()["sub"] == subject
    assert verified.claims()["constraints"] == {"max_path_length": 2}


@pytest.mark.parametrize("header", ["typ", "kid", "alg"])
def test_entity_configuration_rejects_profile_header_override(header):
    key_jar = KeyJar()
    key_jar.add_keys(ISSUER_ID, [new_rsa_key(kid="entity-key")])

    with pytest.raises(FederationJwtHeaderError):
        create_entity_configuration(
            ISSUER_ID,
            key_jar=key_jar,
            extra_protected_headers={header: "override"},
        )


def test_entity_configuration_supports_blank_owner_keyjar():
    key_jar = KeyJar()
    key_jar.add_keys("", [new_rsa_key(kid="blank-owner-key")])

    token = create_entity_configuration(ISSUER_ID, key_jar=key_jar)

    assert factory(token).jwt.headers["kid"] == "blank-owner-key"


def test_entity_statement_uses_requested_lifetime():
    issuer = "https://issuer.example.org"
    subject = "https://subject.example.org"
    key_jar = KeyJar()
    key_jar.add_keys(issuer, [new_rsa_key(kid="issuer-key")])

    token = create_entity_statement(
        issuer,
        subject,
        key_jar,
        SUBORDINATE_STATEMENT,
        lifetime=321,
        include_jwks=False,
    )
    verified = verify_federation_jwt(
        profile=SUBORDINATE_STATEMENT,
        token=token,
        key_jar=key_jar,
    )

    assert verified.claims()["exp"] - verified.claims()["iat"] == 321


def test_signed_someone_else_metadata():
    metadata = {
        "application_type": "web",
        "claims": [
            "sub",
            "name",
            "email",
            "picture"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS512"
        ],
        "redirect_uris": [
            "https://foodle.uninett.no/callback"
        ],
        "response_types": [
            "code"
        ]
    }

    iss = "https://example.com"
    sub = "https://foo.example.org/rp"

    sub_key_jar = build_keyjar(KEYSPEC, issuer_id=sub)

    iss_key_jar = build_keyjar(KEYSPEC, issuer_id=iss)

    iss_key_jar = import_jwks_as_json(iss_key_jar,
                                      sub_key_jar.export_jwks_as_json(issuer_id=sub),
                                      sub)

    sub_key_jar = import_jwks_as_json(sub_key_jar,
                                      iss_key_jar.export_jwks_as_json(issuer_id=iss),
                                      iss)

    authority = {"https://core.example.com": ["https://federation.example.org"]}

    _jwt = create_entity_statement(iss, sub, iss_key_jar, SUBORDINATE_STATEMENT,
                                   metadata=metadata,
                                   authority_hints=authority)

    assert _jwt

    _verifier = factory(_jwt)
    keys = sub_key_jar.get_jwt_verify_keys(_verifier.jwt)
    res = _verifier.verify_compact(keys=keys, sigalg="RS256")

    assert res
    assert res['iss'] == iss
    assert res['sub'] == sub
    assert set(res.keys()) == {'metadata', 'iss', 'exp', 'sub', 'iat',
                               'authority_hints', 'jwks'}
