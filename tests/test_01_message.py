import json
import os
from copy import deepcopy

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.message import Message
import pytest

from fedservice.exception import UnknownCriticalExtension
from fedservice.exception import ConstraintError
from fedservice.exception import MetadataPolicyCritError
from fedservice.exception import WrongSubject
from fedservice.message import EntityStatement
from fedservice.message import Constraints
from fedservice.message import Policy
from fedservice.message import MetadataPolicy
from fedservice.message import SubordinateStatement
from fedservice.message import EntityConfiguration
from fedservice.message import ExplicitRegistrationResponse
from fedservice.message import FederationEntity
from fedservice.message import HistoricalKeysResponse
from fedservice.message import JWKSet
from fedservice.message import ResolveResponse
from fedservice.message import TrustMark
from fedservice.message import TrustMarkDelegation
from fedservice.message import TrustMarkIssuers
from fedservice.message import TrustMarkOwners
from fedservice.message import TrustMarks
from fedservice.message import TrustMarkStatusResponse

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


@pytest.mark.parametrize("operator", ["value", "default"])
@pytest.mark.parametrize("value", [
    "Name", "", 7, 0, -2, 1.5, 1.0, True, False,
    ["a", "b"], [], [""], [None, False, 1.5, ["nested"], {"name": "item"}],
])
def test_policy_value_default_json_round_trip(operator, value):
    source = {operator: deepcopy(value)}
    before = deepcopy(source)
    for message in (Policy(**source), Policy().from_dict(source),
                    Policy().deserialize(json.dumps(source), "json")):
        message.verify()
        assert message.to_dict() == source
        assert type(message[operator]) is type(value)
        serialized = message.serialize("json")
        assert json.loads(serialized) == source
        restored = Policy().deserialize(serialized, "json")
        assert restored.to_dict() == source
        assert type(restored[operator]) is type(value)
    assigned = Policy()
    assigned[operator] = value
    assigned.verify()
    assert assigned.to_dict() == source
    assert source == before


@pytest.mark.parametrize("operator", ["value", "default"])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_policy_null_domain_is_operator_specific(operator, path):
    source = {operator: None}
    if path == "constructor":
        message = Policy(**source)
    elif path == "from_dict":
        message = Policy().from_dict(source)
    elif path == "json":
        message = Policy().deserialize(json.dumps(source), "json")
    else:
        message = Policy()
        message[operator] = None
    if operator == "default":
        with pytest.raises(ValueError, match="default.*null"):
            message.verify()
    else:
        message.verify()
        restored = Policy().deserialize(message.serialize("json"), "json")
        restored.verify()
        assert restored.to_dict() == {"value": None}
    assert message.to_dict() == source == {operator: None}


@pytest.mark.parametrize("operator", ["value", "default"])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_subordinate_payload_validates_nested_null_policy(operator, path):
    policy = {"federation_entity": {"organization_name": {operator: None}}}
    now = utc_time_sans_frac()
    payload = {"iss": "https://superior.example.org", "sub": "https://subject.example.org",
               "iat": now, "exp": now + 600, "jwks": {"keys": []}, "metadata_policy": policy}
    before = deepcopy(payload)
    if path == "constructor":
        statement = SubordinateStatement(**payload)
    elif path == "from_dict":
        statement = SubordinateStatement().from_dict(payload)
    elif path == "json":
        statement = SubordinateStatement().deserialize(json.dumps(payload), "json")
    else:
        statement = SubordinateStatement(**{key: val for key, val in payload.items()
                                             if key != "metadata_policy"})
        statement["metadata_policy"] = policy
    nested = MetadataPolicy(**policy)
    if operator == "default":
        with pytest.raises(ValueError, match="default.*null"):
            statement.verify()
        with pytest.raises(ValueError, match="default.*null"):
            nested.verify()
    else:
        statement.verify()
        nested.verify()
    assert statement.to_dict() == payload == before


@pytest.mark.parametrize("operator", ["value", "default"])
@pytest.mark.parametrize("value", [
    {"name": "not a scalar or array"}, ("tuple",), {"set"}, b"bytes",
    float("nan"), float("inf"), [("nested tuple",)], [{1: "non-string key"}],
])
def test_policy_values_do_not_accept_non_json_python_types(operator, value):
    with pytest.raises(ValueError, match="JSON"):
        Policy(**{operator: value})


@pytest.mark.parametrize("operator", ["value", "default"])
def test_policy_values_do_not_alias_inputs_or_serialized_results(operator):
    source = {operator: [["original"], {"nested": ["original"]}]}
    first = Policy(**source)
    second = Policy(**source)
    first[operator][0].append("changed")
    first[operator][1]["nested"].append("changed")
    assert second.to_dict() == source
    serialized = second.to_dict()
    serialized[operator][0].append("serialized change")
    assert second.to_dict() == source
    assert source == {operator: [["original"], {"nested": ["original"]}]}
    assert Policy().to_dict() == {}


def test_nested_subordinate_policy_values_preserve_strings():
    metadata_policy = {"federation_entity": {
        "organization_name": {"value": "Name"},
        "logo_uri": {"default": "https://subject.example.org/logo"},
    }}
    now = utc_time_sans_frac()
    source = {"iss": "https://issuer.example.org", "sub": "https://subject.example.org",
              "iat": now, "exp": now + 600, "jwks": {"keys": []}, "metadata_policy": metadata_policy}
    before = deepcopy(source)
    statement = SubordinateStatement().from_json(json.dumps(source))
    statement.verify()
    statement["metadata_policy"].verify()
    parsed = MetadataPolicy().from_json(statement["metadata_policy"].to_json())
    parsed.verify()
    assert parsed.to_dict() == metadata_policy
    assert statement.to_dict() == source == before


@pytest.mark.parametrize("allowed", [[], ["openid_provider"], ["oauth_client", "openid_provider"]])
def test_allowed_entity_types_schema(allowed):
    constraints = Constraints(allowed_entity_types=allowed)
    assert constraints.verify()
    assert constraints.to_dict() == {"allowed_entity_types": allowed}


def test_allowed_entity_types_excludes_federation_entity():
    with pytest.raises(ConstraintError, match="federation_entity"):
        Constraints(allowed_entity_types=["federation_entity"]).verify()


def test_allowed_entity_types_null_is_not_empty_array():
    with pytest.raises(ConstraintError, match="array"):
        Constraints(allowed_entity_types=None).verify()


@pytest.mark.parametrize("critical", [[], None, ["regexp"]] + [[name] for name in (
    "value", "add", "default", "one_of", "subset_of", "superset_of", "essential",
)])
@pytest.mark.parametrize("with_policy", [False, True])
def test_metadata_policy_critical_declarations_rejected(critical, with_policy):
    now = utc_time_sans_frac()
    statement = SubordinateStatement(
        iss="https://ta.example.org", sub="https://subject.example.org",
        iat=now, exp=now + 3600, jwks={"keys": []}, metadata_policy_crit=critical,
    )
    if with_policy:
        statement["metadata_policy"] = {"federation_entity": {
            "organization_name": {"regexp": ".*", "value": "Name"},
        }}
    with pytest.raises(MetadataPolicyCritError):
        statement.verify(known_policy_extensions=["regexp"])


def test_policy_uses_final_critical_name_without_nominal_support_bypass():
    policy = Policy(regexp=".*")
    policy.verify()
    with pytest.raises(MetadataPolicyCritError):
        policy.verify(metadata_policy_crit=["regexp"], known_policy_extensions=["regexp"])
    with pytest.raises(MetadataPolicyCritError):
        Policy().verify(metadata_policy_crit=["regexp"])


def full_path(local_file):
    return os.path.join(BASE_PATH, local_file)


@pytest.mark.parametrize("claim", ["metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint"])
@pytest.mark.parametrize("value", [{}, [], None, False, 0, "", [""], "present"])
def test_entity_configuration_rejects_subordinate_only_claims(claim, value):
    now = utc_time_sans_frac()
    message = EntityConfiguration(
        iss="https://entity.example.org", sub="https://entity.example.org",
        iat=now, exp=now + 600, **{claim: value}
    )
    with pytest.raises(ValueError, match=claim):
        message.verify()


@pytest.mark.parametrize("claims", [
    {"constraints": {"max_path_length": 0}},
    {"metadata_policy": {"federation_entity": {"organization_name": {"value": "Name"}}}},
    {"source_endpoint": "https://issuer.example.org/fetch"},
])
def test_subordinate_only_claims_remain_valid(claims):
    now = utc_time_sans_frac()
    message = SubordinateStatement(
        iss="https://issuer.example.org", sub="https://subject.example.org",
        iat=now, exp=now + 600, jwks={"keys": []}, **claims
    )
    message.verify()


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints", "trust_marks",
                                   "trust_mark_issuers", "trust_mark_owners"])
@pytest.mark.parametrize("value", [[], {}, None, False, 0, "", [""], ["https://ta.example.org"]])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_subordinate_rejects_ec_claim_presence(claim, value, path):
    payload = entity_statement_payload(**{claim: value})
    if path == "constructor":
        statement = SubordinateStatement(**payload)
    elif path == "from_dict":
        statement = SubordinateStatement().from_dict(payload)
    elif path == "json":
        statement = SubordinateStatement().from_json(json.dumps(payload))
    else:
        statement = SubordinateStatement()
        statement[claim] = value
        statement.from_dict(entity_statement_payload())
    assert claim in statement
    assert statement[claim] == value
    with pytest.raises(ValueError, match=claim):
        statement.verify()
    del statement[claim]
    statement.verify()
    statement.from_dict({claim: ""})
    with pytest.raises(ValueError, match=claim):
        statement.verify()
    del statement[claim]
    statement.verify()


def test_subordinate_statement():
    file = full_path("document_examples/subordinate_statement_jwt.json")
    _data = json.loads(open(file, "r").read())
    _msg = SubordinateStatement().from_dict(_data)
    _now = utc_time_sans_frac()
    # Set expiration time to some time in the future
    _msg["exp"] = _now + 100
    # The specification example requires regexp, which is not implemented.
    with pytest.raises(MetadataPolicyCritError, match="Unsupported"):
        _msg.verify(known_extensions=["jti"])
    del _msg["metadata_policy_crit"]
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
    _data["jwks"] = {"keys": []}

    _msg = EntityStatement().from_dict(_data)
    assert set(_msg.keys()) == {'trust_marks', 'iss', 'iat', 'sub', 'exp', 'metadata', 'jwks'}
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
        "jwks": {"keys": []},
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


def explicit_registration_response_payload(**overrides):
    payload = {
        "iss": "https://op.example.org",
        "sub": "https://client.example.org",
        "iat": 1700000000,
        "exp": 1700000600,
        "aud": "https://client.example.org",
        "trust_anchor": "https://ta.example.org",
        "authority_hints": ["https://superior.example.org"],
        "metadata": {
            "openid_relying_party": {
                "client_id": "client-id",
                "redirect_uris": ["https://client.example.org/cb"],
            }
        },
    }
    payload.update(overrides)
    return payload


def test_entity_statement_minimal_payload_verifies():
    assert EntityStatement(**entity_statement_payload()).verify() is None


@pytest.mark.parametrize("claim", ["iss", "sub"])
@pytest.mark.parametrize("value", [
    None, False, 12, [], [""], {}, "", "not-an-entity-id", "http://example.org",
    "https:///path", "https://", "https://example.org?", "https://example.org#",
    "https://example.org?q=1", "https://example.org/#fragment",
    " https://example.org", "https://example.org/ ", "https://exa\nmple.org",
    "https://example.org/\t", "https://example.org/\x00", "https://example.org/\x7f",
    "https://[invalid", "https://example.org:invalid", "https://example.org:65536",
    "https://example.org/%ZZ", "https://example.org/\\path",
    "https://user@@example.org", "https://example.org/path[part]",
    "https://example.org/path[part", "https://example.org/path]part",
])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_entity_identifier_input_paths_reject_and_recover(claim, value, path):
    payload = entity_statement_payload()
    if path == "constructor":
        statement = EntityStatement(**dict(payload, **{claim: value}))
    else:
        statement = EntityStatement(**payload)
        if path == "from_dict":
            statement.from_dict({claim: value})
        elif path == "assignment":
            statement[claim] = value
        else:
            statement.update({claim: value})
    assert statement[claim] == value
    with pytest.raises(ValueError, match=claim):
        statement.verify()
    statement.from_dict({claim: payload[claim]})
    statement.verify()


@pytest.mark.parametrize("identifier", [
    "https://example.org", "https://Example.org:8443/path",
    "https://example.org/a%2Fb%3Fc%23d", "https://[::1]:8443/path",
    "https://Example.org:8443/a@b:c;d=1", "https://example.org/path%5Bpart%5D",
    "https://[2001:db8::1]:8443/a%2Fb%3Fc%23d", "https://user@example.org/a@b",
])
def test_entity_identifiers_preserve_exact_strings(identifier):
    statement = EntityConfiguration()
    statement["iss"] = identifier
    statement.update({"sub": identifier})
    statement.from_dict({"iat": 1700000000, "exp": 1700000600, "jwks": {"keys": []}})
    statement.verify()
    assert statement.to_dict()["iss"] == statement.to_dict()["sub"] == identifier


@pytest.mark.parametrize("claim", ["authority_hints", "trust_anchor_hints"])
@pytest.mark.parametrize("value", [
    [], "https://ta.example.org", None, {}, 12, False, "", [""], [None],
    [12, "https://ta.example.org"], ["https://ta.example.org", 12],
    ["https://ta.example.org", ""], ["bad", "https://ta.example.org"],
    ["https://ta.example.org", "http://invalid.example.org"],
    ["https://ta.example.org?"], ["https://ta.example.org#"],
    ["https://user@@example.org"], ["https://example.org/path[part]"],
    ["https://example.org/path[part"], ["https://example.org/path]part"],
])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_ec_hint_input_paths_reject_and_recover(claim, value, path):
    payload = entity_statement_payload(iss="https://subject.example.org")
    valid = ["https://Ta.example.org:8443/a%2Fb", "https://other.example.org",
             "https://Ta.example.org:8443/a%2Fb"]
    if path == "constructor":
        statement = EntityConfiguration(**dict(payload, **{claim: value}))
    else:
        statement = EntityConfiguration(**dict(payload, **{claim: valid}))
        if path == "from_dict":
            statement.from_dict({claim: value})
        elif path == "assignment":
            statement[claim] = value
        else:
            statement.update({claim: value})
    assert statement[claim] == value
    with pytest.raises(ValueError, match=claim):
        statement.verify()
    statement[claim] = valid[:]
    statement.verify()
    assert statement.to_dict()[claim] == valid
    statement[claim].append(None)
    with pytest.raises(ValueError, match=claim):
        statement.verify()
    del statement[claim]
    statement.verify()


@pytest.mark.parametrize("message_cls", [EntityConfiguration, SubordinateStatement])
@pytest.mark.parametrize("value", [
    None, {}, {"keys": {}}, {"keys": [12]}, [], [None], [""], "",
    '{"keys": []}', {"keys": None}, {"keys": 12}, {"keys": "[]"},
])
@pytest.mark.parametrize("path", ["from_dict", "assignment"])
def test_jwks_replacement_and_correction(message_cls, value, path):
    payload = entity_statement_payload()
    if message_cls is EntityConfiguration:
        payload["iss"] = payload["sub"]
    message = message_cls()
    message.from_dict(payload)
    message.verify()
    if path == "assignment":
        message["jwks"] = deepcopy(value)
    else:
        message.from_dict({"jwks": deepcopy(value)})
    assert message["jwks"] == value
    with pytest.raises(ValueError, match="jwks"):
        message.verify()
    message["jwks"] = {"keys": []}
    message.verify()
    assert message.to_dict()["jwks"] == {"keys": []}
    message["jwks"]["keys"] = {}
    with pytest.raises(ValueError, match="keys array"):
        message.verify()
    message.from_dict({"jwks": {"keys": []}})
    message.verify()
    message["jwks"]["keys"].append(12)
    with pytest.raises(ValueError, match="entries"):
        message.verify()


def test_partial_statement_accepts_incremental_jwks_assignment():
    message = EntityConfiguration(sub="https://subject.example.org")
    message["jwks"] = {"keys": []}
    payload = entity_statement_payload(iss=message["sub"])
    message.from_dict(payload)
    message.verify()
    assert message.to_dict() == payload


@pytest.mark.parametrize("claim", ["iat", "exp"])
@pytest.mark.parametrize("value", ["1700000000", "", True, False, None, [], [0], {},
                                    float("nan"), float("inf"), float("-inf"), (0,)])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_numeric_date_input_paths_reject_and_recover(claim, value, path):
    payload = entity_statement_payload()
    if path == "constructor":
        statement = EntityStatement(**dict(payload, **{claim: value}))
    else:
        statement = EntityStatement(**payload)
        if path == "from_dict":
            statement.from_dict({claim: value})
        elif path == "assignment":
            statement[claim] = value
        else:
            statement.update({claim: value})
    with pytest.raises(ValueError, match=claim):
        statement.verify()
    statement[claim] = 1700000000.25
    statement.verify()
    assert statement.to_dict()[claim] == 1700000000.25
    assert type(statement[claim]) is float


@pytest.mark.parametrize("value", [0, 0.0, 1700000000, 1700000000.0, 1700000000.25])
def test_numeric_date_types_and_required_declarations_survive_validation(value):
    statement = EntityStatement(**entity_statement_payload(iat=value, exp=value))
    schema = statement.c_param
    statement.verify()
    assert statement.c_param is schema is EntityStatement.c_param
    for claim in ("iat", "exp"):
        assert schema[claim][1] is True
        assert statement[claim] == value
        assert type(statement[claim]) is type(value)
        assert type(statement.to_dict()[claim]) is type(value)


@pytest.mark.parametrize("claim", ["iss", "sub", "jwks", "iat", "exp"])
def test_zero_dates_do_not_disable_other_required_claims(claim):
    payload = entity_statement_payload(iat=0, exp=0.0)
    del payload[claim]
    with pytest.raises(MissingRequiredAttribute, match=claim):
        EntityStatement(**payload).verify()


@pytest.mark.parametrize("claim", ["iss", "sub", "iat", "exp", "jwks"])
def test_entity_statement_requires_core_claims(claim):
    payload = entity_statement_payload()
    payload.pop(claim)

    with pytest.raises(MissingRequiredAttribute):
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


@pytest.mark.parametrize("value", [None, [], "extension", {}, [12], [""],
                                    ["extension", "extension"], ["missing"],
                                    ["extension", "missing"], ["iss"], ["jwks"],
                                    ["authority_hints"], ["trust_anchor_hints"], ["metadata_policy"]])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_payload_crit_input_paths_reject_and_recover(value, path):
    payload = entity_statement_payload(extension="")
    if path == "constructor":
        statement = EntityStatement(**dict(payload, crit=value))
    else:
        statement = EntityStatement(**dict(payload, crit=["extension"]))
        if path == "from_dict":
            statement.from_dict({"crit": value})
        elif path == "assignment":
            statement["crit"] = value
        else:
            statement.update({"crit": value})
    assert statement["crit"] == value
    with pytest.raises(ValueError, match="crit"):
        statement.verify(known_extensions=["extension", "missing", "iss", "jwks",
                                           "authority_hints", "trust_anchor_hints", "metadata_policy"])
    statement["crit"] = ["extension"]
    statement.verify(known_extensions=["extension"])


@pytest.mark.parametrize("value", ["", [""], None, False, 0, [], {}])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_payload_crit_preserves_falsey_extension_presence(value, path):
    statement = EntityStatement(**entity_statement_payload())
    data = {"extension": value}
    if path == "constructor":
        statement = EntityStatement(**entity_statement_payload(**data))
    elif path == "from_dict":
        statement.from_dict(data)
    elif path == "assignment":
        statement["extension"] = value
    else:
        statement.update(data)
    statement["crit"] = ["extension"]
    assert "extension" in statement and statement["extension"] == value
    statement.verify(known_extensions=["extension"])
    with pytest.raises(UnknownCriticalExtension):
        statement.verify()
    del statement["extension"]
    with pytest.raises(ValueError, match="absent"):
        statement.verify(known_extensions=["extension"])
    del statement["crit"]
    statement.verify()


def test_registration_crit_cannot_name_own_defined_claim():
    statement = ExplicitRegistrationResponse(**explicit_registration_response_payload(crit=["aud"]))
    with pytest.raises(ValueError, match="defined"):
        statement.verify(known_extensions=["aud"])


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

    with pytest.raises(MissingRequiredAttribute):
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

    with pytest.raises(MissingRequiredAttribute):
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

    with pytest.raises(MissingRequiredAttribute):
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

    with pytest.raises(MissingRequiredAttribute):
        TrustMarkStatusResponse(**payload).verify()


@pytest.mark.parametrize("entity_type", ["openid_relying_party", "oauth_client"])
def test_explicit_registration_response_envelope_verifies(entity_type):
    payload = explicit_registration_response_payload(
        metadata={entity_type: {"client_id": "client-id"}}
    )

    assert ExplicitRegistrationResponse(**payload).verify() is None


@pytest.mark.parametrize(
    "claim",
    [
        "iss",
        "sub",
        "iat",
        "exp",
        "aud",
        "trust_anchor",
        "authority_hints",
        "metadata",
    ],
)
def test_explicit_registration_response_requires_envelope_claims(claim):
    payload = explicit_registration_response_payload()
    payload.pop(claim)

    with pytest.raises(MissingRequiredAttribute):
        ExplicitRegistrationResponse(**payload).verify()


def test_explicit_registration_response_rejects_empty_authority_hints():
    payload = explicit_registration_response_payload(authority_hints=[])

    with pytest.raises(MissingRequiredAttribute):
        ExplicitRegistrationResponse(**payload).verify()


def test_explicit_registration_response_rejects_multiple_authority_hints():
    payload = explicit_registration_response_payload(
        authority_hints=[
            "https://superior.example.org",
            "https://other-superior.example.org",
        ]
    )

    with pytest.raises(ValueError, match="exactly one value"):
        ExplicitRegistrationResponse(**payload).verify()


def test_explicit_registration_response_requires_audience_to_match_subject():
    payload = explicit_registration_response_payload(
        aud="https://other-client.example.org"
    )

    with pytest.raises(ValueError, match="aud must match sub"):
        ExplicitRegistrationResponse(**payload).verify()


@pytest.mark.parametrize(
    "message_cls",
    (
        EntityConfiguration,
        SubordinateStatement,
        ResolveResponse,
        TrustMark,
        TrustMarkDelegation,
        TrustMarkStatusResponse,
        JWKSet,
        HistoricalKeysResponse,
        ExplicitRegistrationResponse,
    ),
)
def test_federation_payload_schemas_reject_jwt_container_operations(message_cls):
    payload = message_cls()

    assert isinstance(payload, Message)
    with pytest.raises(NotImplementedError):
        payload.to_jwt()
    with pytest.raises(NotImplementedError):
        payload.from_jwt("header.payload.signature")
