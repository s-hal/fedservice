import json
import os

from cryptojwt.jwt import utc_time_sans_frac
import pytest

from fedservice.exception import UnknownCriticalExtension
from fedservice.exception import WrongSubject
from fedservice.message import EntityStatement
from fedservice.message import SubordinateStatement
from fedservice.message import EntityConfiguration
from fedservice.message import ExplicitRegistrationResponse
from fedservice.message import FederationEntity
from fedservice.message import JWKSet
from fedservice.message import ResolveResponse
from fedservice.message import TrustMark
from fedservice.message import TrustMarkDelegation
from fedservice.message import TrustMarkIssuers
from fedservice.message import TrustMarkOwners
from fedservice.message import TrustMarks
from fedservice.message import TrustMarkStatusResponse

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


def test_subordinate_statement():
    file = full_path("document_examples/subordinate_statement_jwt.json")
    _data = json.loads(open(file, "r").read())
    _msg = SubordinateStatement().from_dict(_data)
    _now = utc_time_sans_frac()
    # Set expiration time to some time in the future
    _msg["exp"] = _now + 100
    _msg.verify(known_extensions=["jti"])
    assert set(_msg["metadata"].keys()) == {"openid_provider", "oauth_client"}
    assert set(_msg["metadata_policy"].keys()) == {"openid_provider", "oauth_client"}


def test_trust_mark_owners():
    file = full_path("document_examples/trust_mark_owners.json")
    _data = json.loads(open(file, "r").read())
    _msg = TrustMarkOwners().from_dict(_data)
    _msg.verify()


def test_trust_entity_statement_comb():
    file = full_path("document_examples/trust_mark_issuers.json")
    _data = json.loads(open(file, "r").read())
    _msg = TrustMarkIssuers().from_dict(_data)
    _msg.verify()


def test_entity_statement_comb():
    file_1 = full_path("document_examples/entity_configuration_jwt.json")
    _data = json.loads(open(file_1, "r").read())
    file_2 = full_path("document_examples/trust_mark_owners.json")
    _data_2 = json.loads(open(file_2, "r").read())
    _data["trust_mark_owners"] = _data_2
    file_3 = full_path("document_examples/trust_mark_issuers.json")
    _data_3 = json.loads(open(file_3, "r").read())
    _data["trust_mark_issuers"] = _data_3
    _data["sub"] = _data["iss"]

    _msg = EntityConfiguration().from_dict(_data)
    _now = utc_time_sans_frac()
    # Set expiration time to some time in the future
    _msg["exp"] = _now + 100
    _msg.verify(known_extensions=["jti"])

    assert set(_msg["trust_mark_issuers"].keys()) == {"https://openid.net/certification/op",
                                                      "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"}
    assert set(_msg["trust_mark_owners"].keys()) == {"https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"}
    assert _msg["trust_mark_owners"]["https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"]["sub"] == \
           "https://refeds.org/sirtfi"


def test_federation_entity():
    file = full_path("document_examples/federation_entity.json")
    _data = json.loads(open(file, "r").read())

    _msg = FederationEntity().from_dict(_data)

    assert set(_msg.keys()) == {'federation_fetch_endpoint',
                                'federation_list_endpoint',
                                'federation_trust_mark_list_endpoint',
                                'federation_trust_mark_status_endpoint',
                                'homepage_uri',
                                'organization_name'}


def test_oidc_rp():
    file = full_path("document_examples/oidc_rp.json")
    _data = json.loads(open(file, "r").read())

    _msg = FederationEntity().from_dict(_data)

    assert set(_msg.keys()) == {'iss', 'sub', 'iat', 'exp', 'metadata', 'jwks', 'authority_hints'}
    assert set(_msg['metadata'].keys()) == {'openid_relying_party'}
    assert set(_msg['metadata']['openid_relying_party'].keys()) == {'application_type',
                                                                    'client_registration_types',
                                                                    'grant_types',
                                                                    'jwks_uri',
                                                                    'logo_uri',
                                                                    'organization_name',
                                                                    'redirect_uris',
                                                                    'signed_jwks_uri'}


def test_oidc_op():
    file = full_path("document_examples/oidc_op.json")
    _data = json.loads(open(file, "r").read())

    _msg = FederationEntity().from_dict(_data)

    assert set(_msg.keys()) == {'iss', 'sub', 'iat', 'exp', 'metadata', 'jwks', 'authority_hints'}
    assert set(_msg['metadata'].keys()) == {'federation_entity', 'openid_provider'}
    assert set(_msg['metadata']['openid_provider'].keys()) == {'authorization_endpoint',
                                                               'client_registration_types_supported',
                                                               'federation_registration_endpoint',
                                                               'grant_types_supported',
                                                               'id_token_signing_alg_values_supported',
                                                               'issuer',
                                                               'logo_uri',
                                                               'op_policy_uri',
                                                               'pushed_authorization_request_endpoint',
                                                               'request_object_signing_alg_values_supported',
                                                               'response_types_supported',
                                                               'signed_jwks_uri',
                                                               'subject_types_supported',
                                                               'token_endpoint',
                                                               'token_endpoint_auth_methods_supported',
                                                               'token_endpoint_auth_signing_alg_values_supported'}


def test_JWKSet():
    file = full_path("document_examples/jwks_claim_set.json")
    _data = json.loads(open(file, "r").read())

    _msg = JWKSet().from_dict(_data)
    assert set(_msg.keys()) == {'iat', 'iss', 'sub', 'keys'}
    assert len(_msg["keys"]) == 2

def test_trust_mark():
    file = full_path("document_examples/trust_mark.json")
    _data = json.loads(open(file, "r").read())

    _msg = EntityStatement().from_dict(_data)
    assert set(_msg.keys()) == {'trust_marks', 'iss', 'iat', 'sub', 'exp', 'metadata'}
    assert len(_msg['trust_marks']) == 1

    # Set expiration time to some time in the future
    _now = utc_time_sans_frac()
    _msg["exp"] = _now + 100

    _msg.verify()

def test_trust_mark_delegation():
    file = full_path("document_examples/trust_mark_delegation.json")
    _data = json.loads(open(file, "r").read())

    _msg = TrustMark().from_dict(_data)
    assert set(_msg.keys()) == {'iat', 'trust_mark_type', 'delegation', 'exp', 'sub', 'iss'}

    # Set expiration time to some time in the future
    _now = utc_time_sans_frac()
    _msg["exp"] = _now + 100

    _msg.verify()


def entity_statement_payload(**overrides):
    payload = {
        "iss": "https://issuer.example.org",
        "sub": "https://subject.example.org",
        "iat": 1700000000,
        "exp": 1700000600,
    }
    payload.update(overrides)
    return payload


def trust_mark_payload(**overrides):
    payload = {
        "sub": "https://subject.example.org",
        "iss": "https://trust-mark-issuer.example.org",
        "iat": 1700000000,
        "trust_mark_type": "https://trust.example.org/marks/member",
    }
    payload.update(overrides)
    return payload


def resolve_response_payload(**overrides):
    payload = {
        "iss": "https://resolver.example.org",
        "sub": "https://subject.example.org",
        "iat": 1700000000,
        "exp": 1700000600,
        "metadata": {
            "federation_entity": {"contacts": ["ops@example.org"]}
        },
        "trust_chain": ["signed.entity.statement"],
    }
    payload.update(overrides)
    return payload


def trust_mark_status_response_payload(status="active"):
    return {
        "iss": "https://issuer.example.org",
        "iat": 1700000000,
        "trust_mark": "signed.trust.mark",
        "status": status,
    }


def trust_mark_delegation_payload(**overrides):
    payload = {
        "iss": "https://owner.example.org",
        "sub": "https://trust-mark-issuer.example.org",
        "trust_mark_type": "https://trust.example.org/marks/member",
        "iat": 1700000000,
    }
    payload.update(overrides)
    return payload


def test_entity_statement_minimal_payload_verifies():
    assert EntityStatement(**entity_statement_payload()).verify() is None


@pytest.mark.parametrize("claim", ["iss", "sub", "iat", "exp"])
def test_entity_statement_requires_core_claims(claim):
    payload = entity_statement_payload()
    payload.pop(claim)

    with pytest.raises(Exception):
        EntityStatement(**payload).verify()


def test_entity_statement_optional_fields_and_known_critical_extension():
    message = EntityStatement(
        **entity_statement_payload(
            jwks={"keys": []},
            metadata={"federation_entity": {"contacts": ["ops@example.org"]}},
            crit=["custom_extension"],
            custom_extension="value",
        )
    )

    assert message.verify(known_extensions=["custom_extension"]) is None


def test_entity_statement_rejects_unknown_critical_extension():
    message = EntityStatement(
        **entity_statement_payload(
            crit=["custom_extension"],
            custom_extension="value",
        )
    )

    with pytest.raises(UnknownCriticalExtension):
        message.verify()


def test_entity_configuration_accepts_compact_trust_mark_value():
    message = EntityConfiguration(
        **entity_statement_payload(
            iss="https://subject.example.org",
            trust_marks=[
                {
                    "trust_mark_type": "https://trust.example.org/marks/member",
                    "trust_mark": "signed.trust.mark",
                }
            ],
        )
    )

    assert message.verify() is None


def test_entity_configuration_rejects_mismatched_dictionary_trust_mark():
    message = EntityConfiguration(
        **entity_statement_payload(
            iss="https://subject.example.org",
            trust_marks=[
                {
                    "trust_mark_type": "https://trust.example.org/marks/member",
                    "trust_mark": trust_mark_payload(
                        trust_mark_type="https://trust.example.org/marks/other"
                    ),
                }
            ],
        )
    )

    with pytest.raises(ValueError, match="trust_mark_is values does not match"):
        message.verify()


def test_trust_marks_validate_structure_without_parsing_compact_value():
    message = TrustMarks(
        **{
            "https://trust.example.org/marks/member": {
                "trust_mark_type": "https://trust.example.org/marks/member",
                "trust_mark": "not-a-compact-jwt",
            }
        }
    )

    assert message.verify() is None


def test_trust_mark_minimal_and_optional_payloads_verify():
    assert TrustMark(**trust_mark_payload()).verify() is True
    message = TrustMark(
        **trust_mark_payload(
            logo_uri="https://trust.example.org/logo.svg",
            exp=1700000600,
            ref="https://trust.example.org/marks/member",
            delegation="signed.delegation.jwt",
        )
    )

    assert message.verify() is True


@pytest.mark.parametrize("claim", ["sub", "iss", "iat", "trust_mark_type"])
def test_trust_mark_requires_core_claims(claim):
    payload = trust_mark_payload()
    payload.pop(claim)

    with pytest.raises(Exception):
        TrustMark(**payload).verify()


def test_trust_mark_subject_validation():
    message = TrustMark(**trust_mark_payload())

    assert message.verify(entity_id="https://subject.example.org") is True
    with pytest.raises(WrongSubject):
        message.verify(entity_id="https://different.example.org")


def test_trust_mark_delegation_optional_fields_verify():
    message = TrustMarkDelegation(
        **trust_mark_delegation_payload(
            exp=1700000600,
            ref="https://trust.example.org/marks/member",
        )
    )

    assert message.verify() is True


@pytest.mark.parametrize(
    "claim", ["iss", "sub", "trust_mark_type", "iat"]
)
def test_trust_mark_delegation_requires_core_claims(claim):
    payload = trust_mark_delegation_payload()
    payload.pop(claim)

    with pytest.raises(Exception):
        TrustMarkDelegation(**payload).verify()


def test_resolve_response_minimal_and_optional_payloads_verify():
    assert ResolveResponse(**resolve_response_payload()).verify() is True
    message = ResolveResponse(
        **resolve_response_payload(
            aud="https://rp.example.org",
            trust_marks=[],
        )
    )

    assert message.verify() is True


@pytest.mark.parametrize(
    "claim", ["iss", "sub", "iat", "exp", "metadata", "trust_chain"]
)
def test_resolve_response_requires_core_claims(claim):
    payload = resolve_response_payload()
    payload.pop(claim)

    with pytest.raises(Exception):
        ResolveResponse(**payload).verify()


@pytest.mark.parametrize("status", ["active", "expired", "revoked", "invalid"])
def test_trust_mark_status_response_accepts_builtin_status_values(status):
    message = TrustMarkStatusResponse(
        **trust_mark_status_response_payload(status=status)
    )

    assert message.verify() is True


def test_trust_mark_status_response_accepts_configured_status_value():
    message = TrustMarkStatusResponse(
        **trust_mark_status_response_payload(status="pending")
    )

    assert message.verify(allowed_extra_status_values={"pending"}) is True


def test_trust_mark_status_response_rejects_unknown_status_value():
    message = TrustMarkStatusResponse(
        **trust_mark_status_response_payload(status="pending")
    )

    with pytest.raises(
        ValueError,
        match="Unknown Trust Mark Status Response status value",
    ):
        message.verify()


@pytest.mark.parametrize("claim", ["iss", "iat", "trust_mark", "status"])
def test_trust_mark_status_response_requires_core_claims(claim):
    payload = trust_mark_status_response_payload()
    payload.pop(claim)

    with pytest.raises(Exception):
        TrustMarkStatusResponse(**payload).verify()


def test_explicit_registration_response_requires_client_id():
    message = ExplicitRegistrationResponse(
        client_id="client-1",
        redirect_uris=["https://client.example.org/cb"],
        client_registration_types=["explicit"],
    )

    assert message.verify() is True

    with pytest.raises(Exception):
        ExplicitRegistrationResponse(
            redirect_uris=["https://client.example.org/cb"],
            client_registration_types=["explicit"],
        ).verify()
