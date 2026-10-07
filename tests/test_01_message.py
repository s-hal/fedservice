import json
import os
from copy import deepcopy

from cryptojwt.jwt import utc_time_sans_frac
from idpyoidc.exception import MissingRequiredAttribute
from idpyoidc.exception import DecodeError
from idpyoidc.message import Message
from idpyoidc.message import OPTIONAL_LIST_OF_STRINGS
from idpyoidc.message.oidc import deserialize_from_one_of
from idpyoidc.message.oidc import SINGLE_OPTIONAL_STRING
import pytest

from fedservice.exception import UnknownCriticalExtension
from fedservice.exception import ConstraintError
from fedservice.exception import MetadataPolicyCritError
from fedservice.exception import WrongSubject
from fedservice.message import EntityStatement
from fedservice.message import Constraints
from fedservice.message import NamingConstraints
from fedservice.message import Policy
from fedservice.message import policy_value_deser
from fedservice.message import MetadataPolicy
from fedservice.message import metadata_policy_deser
from fedservice.message import Metadata
from fedservice.message import metadata_deser
from fedservice.message import OPMetadata
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


@pytest.mark.parametrize("operator", ["add", "one_of", "subset_of", "superset_of"])
@pytest.mark.parametrize("value", [None, "item", {"item": "value"}, ["item", 1]])
def test_policy_set_operators_reject_original_non_string_arrays(operator, value):
    source = {operator: deepcopy(value), "essential": False}
    before = deepcopy(source)
    policy = Policy(**source)
    assert operator in policy
    assert policy[operator] == value
    with pytest.raises(ValueError, match=operator):
        policy.verify()
    assert source == before


@pytest.mark.parametrize("value", [None, "true", [], 1])
def test_policy_essential_rejects_original_non_boolean_values(value):
    source = {"essential": deepcopy(value), "value": 0}
    before = deepcopy(source)
    policy = Policy(**source)
    assert "essential" in policy
    assert policy["essential"] == value
    with pytest.raises(ValueError, match="essential"):
        policy.verify()
    assert source == before


@pytest.mark.parametrize("path,operator,value", [
    ("constructor", "add", "item"),
    ("from_dict", "one_of", {"item": "value"}),
    ("json", "subset_of", None),
    ("assignment", "superset_of", ["item", 1]),
    ("update", "essential", 0),
])
def test_policy_operand_input_paths_reach_live_validation(path, operator, value):
    source = {operator: deepcopy(value)}
    before = deepcopy(source)
    if path == "constructor":
        policy = Policy(**source)
    elif path == "from_dict":
        policy = Policy().from_dict(source)
    elif path == "json":
        policy = Policy().deserialize(json.dumps(source), "json")
    else:
        policy = Policy()
        if path == "assignment":
            policy[operator] = value
        else:
            policy.update(source)
    assert operator in policy
    assert policy[operator] == value
    with pytest.raises(ValueError, match=operator):
        policy.verify()
    assert source == before


def test_policy_validates_mutated_operands_and_allows_repair():
    policy = Policy(add=["original"], value=["", 0, 1.5, ["nested"], {"items": []}])
    policy.verify()
    policy["add"].append(1)
    with pytest.raises(ValueError, match="add"):
        policy.verify()
    policy["add"][-1] = "repaired"
    policy.verify()
    policy["value"].append(("not JSON",))
    with pytest.raises(ValueError, match="JSON"):
        policy.verify()
    policy["value"].pop()
    policy.verify()


@pytest.mark.parametrize("operator,value,error", [
    ("value", {"not": "a supported root value"}, "JSON"),
    ("default", None, "default.*null"),
])
def test_policy_raw_update_rejects_unsupported_value_domain(operator, value, error):
    policy = Policy()
    policy.update({operator: value})
    with pytest.raises(ValueError, match=error):
        policy.verify()


def test_policy_preserves_valid_falsey_operands_and_noncritical_extensions():
    source = {
        "add": [], "one_of": [], "subset_of": [], "superset_of": [],
        "essential": False, "value": None, "custom": "", "other": [""],
    }
    policy = Policy(**source)
    policy.verify()
    assert policy.to_dict() == source


@pytest.mark.parametrize("path,critical", [
    ("constructor", ""), ("from_dict", [""]), ("json", ""),
    ("assignment", [""]), ("update", ""),
])
def test_metadata_policy_critical_input_paths_preserve_malformed_declaration(path, critical):
    payload = entity_statement_payload()
    source = {"metadata_policy_crit": deepcopy(critical)}
    if path == "constructor":
        statement = SubordinateStatement(**dict(payload, **source))
    elif path == "from_dict":
        statement = SubordinateStatement(**payload).from_dict(source)
    elif path == "json":
        statement = SubordinateStatement(**payload).deserialize(json.dumps(source), "json")
    else:
        statement = SubordinateStatement(**payload)
        if path == "assignment":
            statement["metadata_policy_crit"] = critical
        else:
            statement.update(source)
    assert "metadata_policy_crit" in statement
    assert statement["metadata_policy_crit"] == critical
    with pytest.raises(MetadataPolicyCritError):
        statement.verify()


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


@pytest.mark.parametrize("value", ["1", 1.5, True, None])
def test_constraints_reject_original_non_integer_path_lengths(value):
    source = {"max_path_length": value, "allowed_entity_types": []}
    constraints = Constraints(**source)
    assert constraints["max_path_length"] == value
    with pytest.raises(ConstraintError, match="max_path_length"):
        constraints.verify()
    assert source == {"max_path_length": value, "allowed_entity_types": []}


@pytest.mark.parametrize("value", ["oauth_client", None, {}, ["oauth_client", None]])
def test_constraints_reject_original_non_string_allowed_entity_arrays(value):
    source = {"max_path_length": 0, "allowed_entity_types": deepcopy(value)}
    before = deepcopy(source)
    constraints = Constraints(**source)
    assert constraints["allowed_entity_types"] == value
    with pytest.raises(ConstraintError, match="allowed_entity_types"):
        constraints.verify()
    assert source == before


@pytest.mark.parametrize("value", [[], None, '{"permitted": [".example.org"]}', "invalid"])
def test_constraints_reject_original_non_object_naming_container(value):
    source = {"max_path_length": 0, "naming_constraints": deepcopy(value)}
    before = deepcopy(source)
    constraints = Constraints(**source)
    assert constraints["naming_constraints"] == value
    with pytest.raises(ConstraintError, match="naming_constraints"):
        constraints.verify()
    assert source == before


@pytest.mark.parametrize("path,source,error", [
    ("constructor", {"max_path_length": "1"}, "max_path_length"),
    ("from_dict", {"allowed_entity_types": "oauth_client"}, "allowed_entity_types"),
    ("json", {"naming_constraints": []}, "naming_constraints"),
    ("assignment", {"max_path_length": 1.5}, "max_path_length"),
    ("update", {"naming_constraints": {"permitted": ".example.org"}}, "permitted"),
])
def test_constraint_value_input_paths_reach_live_validation(path, source, error):
    before = deepcopy(source)
    if path == "constructor":
        constraints = Constraints(**source)
    elif path == "from_dict":
        constraints = Constraints().from_dict(source)
    elif path == "json":
        constraints = Constraints().deserialize(json.dumps(source), "json")
    else:
        constraints = Constraints()
        if path == "assignment":
            for key, value in source.items():
                constraints[key] = value
        else:
            constraints.update(source)
    with pytest.raises(ConstraintError, match=error):
        constraints.verify()
    assert source == before


@pytest.mark.parametrize("path,value", [
    ("constructor", []),
    ("from_dict", None),
    ("json", '{"max_path_length": 1}'),
    ("assignment", "invalid"),
    ("update", 0),
])
def test_subordinate_constraint_root_paths_reject_non_objects(path, value):
    payload = entity_statement_payload()
    source = {"constraints": deepcopy(value)}
    if path == "constructor":
        statement = SubordinateStatement(**dict(payload, **source))
    elif path == "from_dict":
        statement = SubordinateStatement(**payload).from_dict(source)
    elif path == "json":
        statement = SubordinateStatement(**payload).deserialize(json.dumps(source), "json")
    else:
        statement = SubordinateStatement(**payload)
        if path == "assignment":
            statement["constraints"] = value
        else:
            statement.update(source)
    assert statement["constraints"] == value
    with pytest.raises(ConstraintError, match="constraints"):
        statement.verify()


def test_constraints_revalidate_nested_mutation_and_repair():
    constraints = Constraints(
        max_path_length=1,
        allowed_entity_types=["oauth_client"],
        naming_constraints={"permitted": [".example.org"], "excluded": []},
    )
    constraints.verify()
    constraints["allowed_entity_types"].append(None)
    with pytest.raises(ConstraintError, match="allowed_entity_types"):
        constraints.verify()
    constraints["allowed_entity_types"][-1] = "openid_provider"
    constraints.verify()
    constraints["naming_constraints"]["permitted"].append("https://invalid.example.org")
    with pytest.raises(ConstraintError, match="permitted"):
        constraints.verify()
    constraints["naming_constraints"]["permitted"].pop()
    constraints.verify()
    constraints.update({"max_path_length": "1"})
    with pytest.raises(ConstraintError, match="max_path_length"):
        constraints.verify()
    constraints.update({"max_path_length": 1})
    constraints.verify()


@pytest.mark.parametrize("source", [
    {},
    {"max_path_length": 0},
    {"max_path_length": 2, "allowed_entity_types": []},
    {"naming_constraints": {}},
    {"naming_constraints": {"permitted": [], "excluded": []}},
    {"unknown_constraint": {"extension": None}},
])
def test_constraints_accept_supported_empty_and_extension_values(source):
    constraints = Constraints(**deepcopy(source))
    assert constraints.verify()
    assert constraints.to_dict() == source


def test_constraint_dictionary_deserialization_is_isolated_but_raw_update_is_not():
    source = {
        "allowed_entity_types": ["oauth_client"],
        "naming_constraints": {"permitted": [".example.org"]},
    }
    first = Constraints(**source)
    second = Constraints(**source)
    first["allowed_entity_types"].append("openid_provider")
    first["naming_constraints"]["permitted"].append("leaf.example.org")
    assert source == {
        "allowed_entity_types": ["oauth_client"],
        "naming_constraints": {"permitted": [".example.org"]},
    }
    assert second.to_dict() == source
    raw_allowed = ["oauth_client"]
    raw = Constraints()
    raw.update({"allowed_entity_types": raw_allowed})
    assert raw["allowed_entity_types"] is raw_allowed


@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_subordinate_dispatches_to_supplied_constraints_subclass(path):
    seen = []

    class LocalConstraints(Constraints):
        def verify(self, **kwargs):
            super().verify(**kwargs)
            seen.append(kwargs)
            if kwargs.get("local_approval") != "approved":
                raise ConstraintError("Local constraint approval required")

    constraints = LocalConstraints(max_path_length=0)
    payload = entity_statement_payload()
    if path == "constructor":
        statement = SubordinateStatement(**dict(payload, constraints=constraints))
    elif path == "from_dict":
        statement = SubordinateStatement().from_dict(dict(payload, constraints=constraints))
    else:
        statement = SubordinateStatement(**payload)
        if path == "assignment":
            statement["constraints"] = constraints
        else:
            statement.update({"constraints": constraints})
    assert statement["constraints"] is constraints
    with pytest.raises(ConstraintError, match="Local constraint approval required"):
        statement.verify()
    assert statement.verify(local_approval="approved") is None
    assert seen == [{}, {"local_approval": "approved"}]


def test_constraints_dispatch_supplied_naming_subclass_and_generic_message_schema():
    seen = []

    class LocalNamingConstraints(NamingConstraints):
        def verify(self, **kwargs):
            super().verify(**kwargs)
            seen.append(kwargs)

    naming = LocalNamingConstraints(permitted=[".example.org"])
    constraints = Constraints(naming_constraints=naming)
    assert constraints["naming_constraints"] is naming
    assert constraints.verify(local_approval="approved")
    assert seen == [{"local_approval": "approved"}]
    naming["permitted"].append(None)
    with pytest.raises(ConstraintError, match="permitted"):
        constraints.verify(local_approval="approved")
    naming["permitted"].pop()

    generic = Message()
    generic.update({"permitted": ".example.org"})
    constraints.update({"naming_constraints": generic})
    with pytest.raises(ConstraintError, match="permitted"):
        constraints.verify()
    generic.update({"permitted": [".example.org"]})
    assert constraints.verify()

    generic_constraints = Message()
    generic_constraints.update({"max_path_length": 0, "naming_constraints": generic})
    statement = SubordinateStatement(**entity_statement_payload())
    statement.update({"constraints": generic_constraints})
    assert statement["constraints"] is generic_constraints
    statement.verify()


def test_constraint_declared_deserializer_overrides_are_used():
    seen = []

    class LocalNamingConstraints(NamingConstraints):
        pass

    def local_naming_deserializer(value, *, sformat):
        seen.append(("naming", sformat))
        return deserialize_from_one_of(value, LocalNamingConstraints, sformat)

    class LocalConstraints(Constraints):
        c_param = Constraints.c_param.copy()

    naming_spec = list(LocalConstraints.c_param["naming_constraints"])
    naming_spec[3] = local_naming_deserializer
    LocalConstraints.c_param["naming_constraints"] = tuple(naming_spec)

    def local_constraints_deserializer(value, *, sformat):
        seen.append(("constraints", sformat))
        return deserialize_from_one_of(value, LocalConstraints, sformat)

    class LocalStatement(SubordinateStatement):
        c_param = SubordinateStatement.c_param.copy()

    constraint_spec = list(LocalStatement.c_param["constraints"])
    constraint_spec[3] = local_constraints_deserializer
    LocalStatement.c_param["constraints"] = tuple(constraint_spec)
    statement = LocalStatement(**entity_statement_payload(constraints={
        "naming_constraints": {"permitted": [".example.org"]},
    }))
    assert isinstance(statement["constraints"], LocalConstraints)
    assert isinstance(statement["constraints"]["naming_constraints"], LocalNamingConstraints)
    assert seen == [("constraints", "dict"), ("naming", "dict")]
    statement.verify()


def _constraint_list_schema(field, deserializer):
    base = Constraints if field == "allowed_entity_types" else NamingConstraints

    class LocalSchema(base):
        c_param = base.c_param.copy()

    spec = list(LocalSchema.c_param[field])
    spec[3] = deserializer
    LocalSchema.c_param[field] = tuple(spec)
    return LocalSchema


def _parse_constraint_list(schema, path, source):
    if path == "constructor":
        return schema(**source)
    if path == "from_dict":
        return schema().from_dict(source)
    if path == "json":
        return schema().deserialize(json.dumps(source), "json")
    result = schema()
    for key, value in source.items():
        result[key] = value
    return result


@pytest.mark.parametrize("field", ["permitted", "excluded", "allowed_entity_types"])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
@pytest.mark.parametrize("value", [[], ["example.org"]])
def test_constraint_list_fields_use_declared_deserializer(field, path, value):
    seen = []
    appended = "openid_provider" if field == "allowed_entity_types" else "child.example.org"

    def local_deserializer(operand, *, sformat):
        seen.append(sformat)
        operand.append(appended)
        return operand

    schema = _constraint_list_schema(field, local_deserializer)
    source = {field: deepcopy(value)}
    before = deepcopy(source)
    parsed = _parse_constraint_list(schema, path, source)
    parsed.verify()
    assert parsed[field] == value + [appended]
    assert json.loads(parsed.serialize("json"))[field] == value + [appended]
    assert seen == ["dict"]
    assert source == before


@pytest.mark.parametrize("field", ["permitted", "excluded", "allowed_entity_types"])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_constraint_list_field_deserializer_rejection_is_effective(field, path):
    seen = []

    def rejecting_deserializer(operand, *, sformat):
        seen.append((operand, sformat))
        raise ValueError("local constraint list deserializer rejected input")

    schema = _constraint_list_schema(field, rejecting_deserializer)
    with pytest.raises(ValueError, match="local constraint list deserializer rejected input"):
        _parse_constraint_list(schema, path, {field: ["example.org"]})
    assert seen == [(["example.org"], "dict")]


@pytest.mark.parametrize("field", ["permitted", "excluded", "allowed_entity_types"])
@pytest.mark.parametrize("result", ["wrapped", ["valid", 1]])
def test_constraint_list_field_deserializer_result_is_validated(field, result):
    def invalid_deserializer(operand, *, sformat):
        assert operand == ["example.org"]
        assert sformat == "dict"
        return deepcopy(result)

    schema = _constraint_list_schema(field, invalid_deserializer)
    with pytest.raises(ConstraintError, match=field):
        schema(**{field: ["example.org"]})


@pytest.mark.parametrize("field", ["permitted", "excluded", "allowed_entity_types"])
@pytest.mark.parametrize("malformed", [None, "example.org", {"name": "example.org"},
                                        ["example.org", None]])
def test_constraint_list_malformed_input_bypasses_callback_and_allows_repair(
        field, malformed):
    seen = []
    repair = "oauth_client" if field == "allowed_entity_types" else ".example.org"
    appended = "openid_provider" if field == "allowed_entity_types" else "leaf.example.org"

    def local_deserializer(operand, *, sformat):
        seen.append(sformat)
        return operand + [appended]

    schema = _constraint_list_schema(field, local_deserializer)
    source = {field: deepcopy(malformed)}
    before = deepcopy(source)
    parsed = schema(**source)
    assert seen == []
    with pytest.raises(ConstraintError, match=field):
        parsed.verify()
    assert source == before

    parsed.update({field: [repair]})
    parsed.verify()
    assert parsed[field] == [repair]
    assert seen == []

    parsed[field] = [repair]
    parsed.verify()
    assert parsed[field] == [repair, appended]
    assert seen == ["dict"]


@pytest.mark.parametrize("field,result", [
    ("permitted", ["https://invalid.example.org"]),
    ("excluded", ["*.example.org"]),
    ("allowed_entity_types", ["federation_entity"]),
])
def test_constraint_list_callback_cannot_bypass_semantic_validation(field, result):
    def invalid_deserializer(operand, *, sformat):
        assert sformat == "dict"
        return deepcopy(result)

    schema = _constraint_list_schema(field, invalid_deserializer)
    parsed = schema(**{field: ["example.org"]})
    with pytest.raises(ConstraintError, match=field if field != "allowed_entity_types"
                       else "federation_entity"):
        parsed.verify()


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


@pytest.mark.parametrize("position,entity_type", [
    ("root", None), ("type", "federation_entity"), ("type", "https://example.org/type"),
    ("parameter", "federation_entity"), ("parameter", "https://example.org/type"),
])
@pytest.mark.parametrize("invalid", [None, False, 0, "", "text", [], [None], [""], [{}], {},
                                    '{"federation_entity": {"name": {"value": "Name"}}}'])
def test_subordinate_policy_rejects_container_shapes(position, entity_type, invalid):
    if position == "root":
        policy = invalid
    else:
        parameters = invalid if position == "type" else {
            "organization_name": invalid, "valid_sibling": {"value": "Name"},
        }
        policy = {entity_type: parameters, "valid_type": {"name": {"value": "Name"}}}
    source = entity_statement_payload(metadata_policy=policy)
    before = deepcopy(source)
    statement = SubordinateStatement(**source)
    with pytest.raises(ValueError, match="metadata_policy") as error:
        statement.verify()
    if entity_type:
        assert entity_type in str(error.value)
    if position == "parameter":
        assert "organization_name" in str(error.value)
    assert source == before


@pytest.mark.parametrize("path", ["from_dict", "json", "assignment"])
@pytest.mark.parametrize("policy", [
    [], {"federation_entity": [None]},
    {"federation_entity": {"bad": "", "good": {"value": "Name"}}},
])
def test_subordinate_policy_input_paths_preserve_invalid_replacements(path, policy):
    statement = SubordinateStatement(**entity_statement_payload(
        metadata_policy={"federation_entity": {"name": {"value": "Name"}}}))
    if path == "from_dict":
        statement.from_dict({"metadata_policy": policy})
    elif path == "json":
        statement.deserialize(json.dumps({"metadata_policy": policy}), "json")
    else:
        statement["metadata_policy"] = policy
    with pytest.raises(ValueError, match="metadata_policy"):
        statement.verify()
    statement["metadata_policy"] = {"federation_entity": {"name": {"value": "Repaired"}}}
    statement.verify()


@pytest.mark.parametrize("raw", [False, True])
def test_subordinate_policy_validates_live_mutation_and_repair(raw):
    policy = {"federation_entity": {"name": {"value": "Name"}}}
    statement = SubordinateStatement(**entity_statement_payload())
    if raw:
        statement.update({"metadata_policy": policy})
    else:
        statement["metadata_policy"] = policy
    statement.verify()
    current = statement["metadata_policy"]
    parameters = current["federation_entity"]
    parameters["name"].clear()
    with pytest.raises(ValueError, match="metadata_policy federation_entity parameter name"):
        statement.verify()
    parameters["name"] = {"value": None}
    statement.verify()
    parameters.update({"name": [""]})
    with pytest.raises(ValueError, match="metadata_policy federation_entity parameter name"):
        statement.verify()
    parameters["name"] = {"unknown_operator": ""}
    statement.verify()
    current["federation_entity"] = []
    with pytest.raises(ValueError, match="metadata_policy federation_entity"):
        statement.verify()
    current.update({"federation_entity": {"name": {"value": []}}})
    statement.verify()
    statement.update({"metadata_policy": None})
    with pytest.raises(ValueError, match="metadata_policy"):
        statement.verify()
    statement.update({"metadata_policy": current})
    statement.verify()


def test_policy_container_message_and_round_trip_compatibility():
    policy = {"federation_entity": {
        "organization_name#sv": {"value": ""}, "extra": {"custom": ""},
        "remove": {"value": None}, "empty": {"value": []},
    }, "https://example.org/type": {
        "flag": {"value": False}, "zero": {"value": 0},
        "nested": {"value": [None, {"nested": [], "items": [None, False, 0]}]},
    }}
    for parsed in (MetadataPolicy(**policy), metadata_policy_deser(policy, "dict"),
                   metadata_policy_deser(json.dumps(policy), "json")):
        parsed.verify()
        assert isinstance(parsed["federation_entity"], Message)
        assert parsed.to_dict() == policy
        restored = MetadataPolicy().from_json(parsed.to_json())
        restored.verify()
        assert restored.to_dict() == policy
    local = MetadataPolicy()
    with pytest.raises(ValueError, match="metadata_policy"):
        local.verify()
    # Empty standalone rules remain valid for internal policy assembly.
    rule = Policy()
    rule.verify()
    rule["value"] = None
    parameters = Message(name=rule)
    local["federation_entity"] = parameters
    statement = SubordinateStatement(**entity_statement_payload(metadata_policy=local))
    statement.verify()
    assert statement["metadata_policy"] is local
    assert local["federation_entity"] is parameters
    rule["default"] = None
    with pytest.raises(ValueError, match="default.*null"):
        statement.verify()
    del rule["default"]
    statement.verify()
    del statement["metadata_policy"]
    statement.verify()


@pytest.mark.parametrize("path", ["helper", "statement"])
@pytest.mark.parametrize("entity_type", ["federation_entity", "https://example.org/type"])
def test_policy_deserialization_preserves_mutation_isolation(path, entity_type):
    source = {entity_type: {"extra": {"custom": ["original"]}}}
    results = []
    for _ in range(2):
        if path == "helper":
            results.append(metadata_policy_deser(source, "dict"))
        else:
            results.append(SubordinateStatement(**entity_statement_payload(
                metadata_policy=source))["metadata_policy"])
    first, second = results
    first[entity_type]["extra"]["custom"].append("parsed change")
    assert source == {entity_type: {"extra": {"custom": ["original"]}}}
    assert second.to_dict() == source
    source[entity_type]["extra"]["custom"].append("source change")
    assert first[entity_type]["extra"]["custom"] == ["original", "parsed change"]
    assert second[entity_type]["extra"]["custom"] == ["original"]


@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_subordinate_dispatches_to_supplied_metadata_policy(path):
    seen = []

    class LocalPolicy(MetadataPolicy):
        """Test-only policy requiring explicit local approval after normal checks."""

        def verify(self, **kwargs):
            super().verify(**kwargs)
            seen.append(kwargs)
            if kwargs.get("local_approval") != "approved":
                raise ValueError("Local policy approval required")

    policy = LocalPolicy(federation_entity={"name": {"value": "Name"}})
    payload = entity_statement_payload()
    if path == "constructor":
        statement = SubordinateStatement(**dict(payload, metadata_policy=policy))
    elif path == "from_dict":
        statement = SubordinateStatement().from_dict(dict(payload, metadata_policy=policy))
    else:
        statement = SubordinateStatement(**payload)
        if path == "assignment":
            statement["metadata_policy"] = policy
        else:
            statement.update({"metadata_policy": policy})
    assert statement["metadata_policy"] is policy
    with pytest.raises(ValueError, match="Local policy approval required"):
        policy.verify()
    with pytest.raises(ValueError, match="Local policy approval required"):
        statement.verify()
    assert statement.verify(local_approval="approved") is None
    assert seen == [{}, {}, {"local_approval": "approved"}]

    policy.update({"federation_entity": {}})
    with pytest.raises(ValueError, match="metadata_policy federation_entity"):
        statement.verify(local_approval="approved")
    policy.update({"federation_entity": {"name": {"default": None}}})
    with pytest.raises(ValueError, match="default.*null"):
        statement.verify(local_approval="approved")
    policy.update({"federation_entity": {"name": {"value": "Repaired"}}})
    assert statement.verify(local_approval="approved") is None
    assert statement["metadata_policy"] is policy


@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
@pytest.mark.parametrize("claim", ["metadata", "metadata_policy"])
def test_statement_uses_declared_nested_deserializer(path, claim):
    seen = []
    entity_type = "https://example.org/type"
    if claim == "metadata":
        nested_type = Metadata
        base_statement = EntityConfiguration
        value = {entity_type: {"items": ["original"]}}
    else:
        nested_type = MetadataPolicy
        base_statement = SubordinateStatement
        value = {entity_type: {"items": {"value": ["original"]}}}

    class LocalNested(nested_type):
        pass

    def local_deserializer(source, *, sformat):
        seen.append(sformat)
        return deserialize_from_one_of(source, LocalNested, sformat)

    class LocalStatement(base_statement):
        c_param = base_statement.c_param.copy()
        spec = list(c_param[claim])
        spec[3] = local_deserializer
        c_param[claim] = tuple(spec)

    payload = entity_statement_payload(**{claim: value})
    if claim == "metadata":
        payload["iss"] = payload["sub"]
    before = deepcopy(value)
    if path == "constructor":
        statement = LocalStatement(**payload)
    elif path == "from_dict":
        statement = LocalStatement().from_dict(payload)
    elif path == "json":
        statement = LocalStatement().deserialize(json.dumps(payload), "json")
    else:
        statement = LocalStatement(**{key: item for key, item in payload.items()
                                      if key != claim})
        statement[claim] = value

    nested = statement[claim]
    assert isinstance(nested, LocalNested)
    assert seen == ["dict"]
    if claim == "metadata":
        nested[entity_type]["items"].append("parsed")
    else:
        nested[entity_type]["items"]["value"].append("parsed")
    assert value == before


@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_statement_dispatches_to_supplied_metadata(path):
    seen = []

    class LocalMetadata(Metadata):
        def verify(self, **kwargs):
            super().verify(**kwargs)
            seen.append(kwargs)
            if kwargs.get("local_approval") != "approved":
                raise ValueError("Local metadata approval required")

    metadata = LocalMetadata(federation_entity={"organization_name": "Name"})
    payload = entity_statement_payload(iss="https://subject.example.org")
    if path == "constructor":
        statement = EntityConfiguration(**dict(payload, metadata=metadata))
    elif path == "from_dict":
        statement = EntityConfiguration().from_dict(dict(payload, metadata=metadata))
    else:
        statement = EntityConfiguration(**payload)
        if path == "assignment":
            statement["metadata"] = metadata
        else:
            statement.update({"metadata": metadata})

    assert statement["metadata"] is metadata
    with pytest.raises(ValueError, match="Local metadata approval required"):
        statement.verify()
    assert statement.verify(local_approval="approved") is None
    assert seen == [
        {"iss": "https://subject.example.org"},
        {"local_approval": "approved", "iss": "https://subject.example.org"},
    ]
    metadata["federation_entity"].update({"extension": None})
    with pytest.raises(ValueError, match="metadata federation_entity parameter extension"):
        statement.verify(local_approval="approved")


@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_statement_dispatches_to_supplied_parameter_policy(path):
    seen = []

    class LocalParameterPolicy(Policy):
        def verify(self, **kwargs):
            super().verify(**kwargs)
            seen.append(kwargs)
            if kwargs.get("local_approval") != "approved":
                raise ValueError("Local parameter policy approval required")

    parameter_policy = LocalParameterPolicy(value="Name")
    parameters = Message()
    parameters.update({"organization_name": parameter_policy})
    metadata_policy = MetadataPolicy()
    metadata_policy.update({"federation_entity": parameters})
    payload = entity_statement_payload()
    if path == "constructor":
        statement = SubordinateStatement(**dict(payload, metadata_policy=metadata_policy))
    elif path == "from_dict":
        statement = SubordinateStatement().from_dict(
            dict(payload, metadata_policy=metadata_policy)
        )
    else:
        statement = SubordinateStatement(**payload)
        if path == "assignment":
            statement["metadata_policy"] = metadata_policy
        else:
            statement.update({"metadata_policy": metadata_policy})

    assert statement["metadata_policy"] is metadata_policy
    assert metadata_policy["federation_entity"] is parameters
    assert parameters["organization_name"] is parameter_policy
    with pytest.raises(ValueError, match="Local parameter policy approval required"):
        statement.verify()
    assert statement.verify(local_approval="approved") is None
    assert seen == [{}, {"local_approval": "approved"}]
    parameter_policy["default"] = None
    with pytest.raises(ValueError, match="default.*null"):
        statement.verify(local_approval="approved")


@pytest.mark.parametrize("operator", ["value", "default"])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_policy_uses_declared_value_deserializer(operator, path):
    seen = []

    def local_deserializer(value, *, sformat):
        seen.append(sformat)
        return policy_value_deser(value, sformat=sformat)

    class LocalPolicy(Policy):
        c_param = Policy.c_param.copy()

    spec = list(LocalPolicy.c_param[operator])
    spec[3] = local_deserializer
    LocalPolicy.c_param[operator] = tuple(spec)
    value = [["original"], {"nested": ["original"]}]
    source = {operator: value}
    before = deepcopy(source)
    if path == "constructor":
        policy = LocalPolicy(**source)
    elif path == "from_dict":
        policy = LocalPolicy().from_dict(source)
    elif path == "json":
        policy = LocalPolicy().deserialize(json.dumps(source), "json")
    else:
        policy = LocalPolicy()
        policy[operator] = value

    assert seen == ["dict"]
    policy[operator][0].append("parsed")
    policy[operator][1]["nested"].append("parsed")
    assert source == before


@pytest.mark.parametrize("operator", ["add", "one_of", "subset_of", "superset_of"])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
@pytest.mark.parametrize("value", [[], ["original"]])
def test_policy_list_operators_use_declared_deserializer(operator, path, value):
    seen = []

    def local_deserializer(operand, *, sformat):
        seen.append(sformat)
        operand.append("deserialized")
        return operand

    class LocalPolicy(Policy):
        c_param = Policy.c_param.copy()

    spec = list(LocalPolicy.c_param[operator])
    spec[3] = local_deserializer
    LocalPolicy.c_param[operator] = tuple(spec)
    source = {operator: deepcopy(value)}
    before = deepcopy(source)
    if path == "constructor":
        policy = LocalPolicy(**source)
    elif path == "from_dict":
        policy = LocalPolicy().from_dict(source)
    elif path == "json":
        policy = LocalPolicy().deserialize(json.dumps(source), "json")
    else:
        policy = LocalPolicy()
        policy[operator] = source[operator]

    policy.verify()
    assert seen == ["dict"]
    assert policy[operator] == value + ["deserialized"]
    assert json.loads(policy.serialize("json"))[operator] == value + ["deserialized"]
    assert source == before


@pytest.mark.parametrize("operator", ["add", "one_of", "subset_of", "superset_of"])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_policy_list_operator_deserializer_rejection_is_effective(operator, path):
    seen = []

    def rejecting_deserializer(operand, *, sformat):
        seen.append((operand, sformat))
        raise ValueError("local list deserializer rejected input")

    class LocalPolicy(Policy):
        c_param = Policy.c_param.copy()

    spec = list(LocalPolicy.c_param[operator])
    spec[3] = rejecting_deserializer
    LocalPolicy.c_param[operator] = tuple(spec)
    source = {operator: ["original"]}
    with pytest.raises(ValueError, match="local list deserializer rejected input"):
        if path == "constructor":
            LocalPolicy(**source)
        elif path == "from_dict":
            LocalPolicy().from_dict(source)
        elif path == "json":
            LocalPolicy().deserialize(json.dumps(source), "json")
        else:
            policy = LocalPolicy()
            policy[operator] = source[operator]
    assert seen == [(["original"], "dict")]


@pytest.mark.parametrize("operator", ["add", "one_of", "subset_of", "superset_of"])
@pytest.mark.parametrize("result", ["wrapped", ["valid", 1]])
def test_policy_list_operator_deserializer_result_is_validated(operator, result):
    def invalid_deserializer(operand, *, sformat):
        assert operand == ["original"]
        assert sformat == "dict"
        return deepcopy(result)

    class LocalPolicy(Policy):
        c_param = Policy.c_param.copy()

    spec = list(LocalPolicy.c_param[operator])
    spec[3] = invalid_deserializer
    LocalPolicy.c_param[operator] = tuple(spec)
    with pytest.raises(ValueError, match=operator):
        LocalPolicy(**{operator: ["original"]})


@pytest.mark.parametrize("operator", ["add", "one_of", "subset_of", "superset_of"])
@pytest.mark.parametrize("malformed", [None, "item", {"item": "value"}, ["item", 1], [None]])
def test_policy_list_operator_malformed_input_bypasses_callback_and_allows_repair(
        operator, malformed):
    seen = []

    def local_deserializer(operand, *, sformat):
        seen.append(sformat)
        return operand + ["deserialized"]

    class LocalPolicy(Policy):
        c_param = Policy.c_param.copy()

    spec = list(LocalPolicy.c_param[operator])
    spec[3] = local_deserializer
    LocalPolicy.c_param[operator] = tuple(spec)
    source = {operator: deepcopy(malformed)}
    before = deepcopy(source)
    policy = LocalPolicy(**source)
    assert seen == []
    with pytest.raises(ValueError, match=operator):
        policy.verify()
    assert source == before

    policy.update({operator: ["raw repair"]})
    policy.verify()
    assert policy[operator] == ["raw repair"]
    assert seen == []

    policy[operator] = ["assigned repair"]
    policy.verify()
    assert policy[operator] == ["assigned repair", "deserialized"]
    assert seen == ["dict"]


@pytest.mark.parametrize("representation", ["dict", "message", "message_subclass"])
@pytest.mark.parametrize("source,error", [
    ({"federation_entity": {"name": {"value": None}}}, None),
    ({}, "metadata_policy"),
    ({"federation_entity": []}, "metadata_policy federation_entity"),
    ({"federation_entity": {"name": {"default": None}}}, "default.*null"),
])
def test_subordinate_untyped_policy_uses_shared_validation(representation, source, error):
    class OtherMessage(Message):
        """A generic message override is not a MetadataPolicy verification hook."""

        def verify(self, **kwargs):
            raise AssertionError("Generic message verification must not be dispatched")

    policy = deepcopy(source)
    if representation != "dict":
        policy = Message() if representation == "message" else OtherMessage()
        policy.update(deepcopy(source))
    statement = SubordinateStatement(**entity_statement_payload())
    statement.update({"metadata_policy": policy})
    assert statement["metadata_policy"] is policy
    if error:
        with pytest.raises(ValueError, match=error):
            statement.verify()
    else:
        assert statement.verify() is None


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


@pytest.mark.parametrize("path", ["helper", "statement"])
@pytest.mark.parametrize("entity_type,parameter,initial", [
    ("https://example.org/type", "roles", ("reader",)),
    ("federation_entity", "extension", ()),
])
def test_metadata_deserialization_isolates_source_and_results(path, entity_type, parameter, initial):
    source = {entity_type: {parameter: list(initial)}}
    results = []
    for _ in range(2):
        if path == "helper":
            parsed = metadata_deser(source, "dict")
        else:
            statement = EntityConfiguration(**entity_statement_payload(
                iss="https://subject.example.org", metadata=source))
            statement.verify()
            parsed = statement["metadata"]
        assert isinstance(parsed, Metadata)
        if entity_type == "federation_entity":
            assert isinstance(parsed[entity_type], FederationEntity)
        assert parsed[entity_type][parameter] == list(initial)
        results.append(parsed)

    first, second = results
    first[entity_type][parameter].append("parsed change")
    assert source == {entity_type: {parameter: list(initial)}}
    assert second[entity_type][parameter] == list(initial)

    source[entity_type][parameter].append("source change")
    assert source[entity_type][parameter] == list(initial) + ["source change"]
    assert first[entity_type][parameter] == list(initial) + ["parsed change"]
    assert second[entity_type][parameter] == list(initial)
    first.verify()
    second.verify()


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
@pytest.mark.parametrize("entity_type", [None, "federation_entity", "https://example.org/type"])
@pytest.mark.parametrize("value", [None, "", "text", '{"federation_entity": {}}',
                                  [], [""], [{}], [None], 0, False])
def test_statement_metadata_rejects_nonobject_containers(schema, entity_type, value):
    metadata = value if entity_type is None else {entity_type: value}
    payload = entity_statement_payload(iss="https://subject.example.org", metadata=metadata)
    before = deepcopy(payload)
    statement = schema(**payload)
    stored = statement["metadata"] if entity_type is None else statement["metadata"][entity_type]
    assert stored == value
    with pytest.raises(ValueError, match="metadata") as error:
        statement.verify()
    if entity_type is not None:
        assert entity_type in str(error.value)
    assert payload == before


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
@pytest.mark.parametrize("path,value", [
    ("from_dict", []), ("json", [None]), ("assignment", "{}"), ("update", None),
])
def test_statement_metadata_replacement_and_repair(schema, path, value):
    statement = schema(**entity_statement_payload(
        iss="https://subject.example.org", metadata={"federation_entity": {}}))
    if path == "from_dict":
        statement.from_dict({"metadata": value})
    elif path == "json":
        statement.deserialize(json.dumps({"metadata": value}), "json")
    elif path == "assignment":
        statement["metadata"] = value
    else:
        statement.update({"metadata": value})
    assert statement["metadata"] == value
    with pytest.raises(ValueError, match="metadata"):
        statement.verify()
    statement["metadata"] = {}
    statement.verify()
    assert isinstance(statement["metadata"], Metadata)


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
@pytest.mark.parametrize("entity_type,parameter,path", [
    ("federation_entity", "organization_name", "constructor"),
    ("federation_entity", "extension", "from_dict"),
    ("https://example.org/type", "extension", "json"),
    ("federation_entity", "organization_name#sv", "assignment"),
    ("federation_entity", "contacts", "constructor"),
    ("openid_provider", "organization_name", "update"),
])
def test_statement_metadata_rejects_null_parameters(schema, entity_type, parameter, path):
    data = {"metadata": {entity_type: {parameter: None}}}
    before = deepcopy(data)
    statement = schema(**entity_statement_payload(iss="https://subject.example.org"))
    if path == "constructor":
        statement = schema(**entity_statement_payload(iss="https://subject.example.org", **data))
    elif path == "from_dict":
        statement.from_dict(data)
    elif path == "json":
        statement.deserialize(json.dumps(data), "json")
    elif path == "assignment":
        statement["metadata"] = data["metadata"]
    else:
        statement.update(data)
    with pytest.raises(ValueError, match="metadata") as error:
        statement.verify()
    assert entity_type in str(error.value)
    assert parameter in str(error.value)
    assert data == before
    statement["metadata"][entity_type][parameter] = "Repaired"
    statement.verify()


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
@pytest.mark.parametrize("raw", [False, True])
@pytest.mark.parametrize("update", [False, True])
def test_statement_metadata_rechecks_live_nested_contents(schema, raw, update):
    statement = schema(**entity_statement_payload(iss="https://subject.example.org"))
    metadata = {"federation_entity": {"organization_name": "Name"}}
    if raw:
        statement.update({"metadata": metadata})
    else:
        statement["metadata"] = metadata
        assert isinstance(statement["metadata"]["federation_entity"], FederationEntity)
    metadata = statement["metadata"]
    parameters = metadata["federation_entity"]
    if update:
        parameters.update({"organization_name": None})
    else:
        parameters["organization_name"] = None
    with pytest.raises(ValueError, match="metadata federation_entity parameter organization_name"):
        statement.verify()
    assert parameters["organization_name"] is None
    parameters["organization_name"] = "Repaired"
    statement.verify()
    if update:
        metadata.update({"federation_entity": [None]})
    else:
        metadata["federation_entity"] = []
    with pytest.raises(ValueError, match="metadata federation_entity"):
        statement.verify()
    metadata["federation_entity"] = {}
    statement.verify()


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
def test_statement_metadata_preserves_empty_partial_and_extension_objects(schema):
    extensions = {"text": "Name", "empty_text": "", "number": 0, "flag": False,
                  "array": [1, "two"], "empty_array": [], "empty_item": [""],
                  "object": {"nested": None, "items": [None, False, 0]}}
    source = {"federation_entity": dict(extensions, **{"organization_name#sv": "Namn"}),
              "openid_provider": {"organization_name": "Partial OP"},
              "oauth_client": {}, "https://example.org/type": extensions,
              "https://example.org/empty": {}}
    before = deepcopy(source)
    payload = entity_statement_payload(iss="https://subject.example.org", metadata=source)
    statement = schema(**payload)
    assert isinstance(statement["metadata"], Metadata)
    assert isinstance(statement["metadata"]["federation_entity"], FederationEntity)
    assert isinstance(statement["metadata"]["openid_provider"], OPMetadata)
    for parsed in (statement, schema().from_dict(payload),
                   schema().deserialize(json.dumps(payload), "json"),
                   schema(**dict(payload, metadata=statement["metadata"].to_dict())),
                   schema(**dict(payload, metadata=json.loads(statement["metadata"].to_json())))):
        parsed.verify()
        metadata = parsed["metadata"]
        metadata.verify()
        assert set(metadata.keys()) == set(source)
        for entity_type, parameters in source.items():
            for name, value in parameters.items():
                assert metadata[entity_type][name] == value
        assert metadata["https://example.org/empty"] == {}
    assert source == before
    statement["metadata"] = {}
    statement.verify()
    assert statement.to_dict()["metadata"] == {}
    del statement["metadata"]
    statement.verify()
    assert "metadata" not in statement.to_dict()


@pytest.mark.parametrize("schema", [EntityConfiguration, SubordinateStatement])
def test_statement_metadata_accepts_existing_messages_and_raw_updates(schema):
    parameters = FederationEntity(organization_name="Name")
    metadata = Metadata(federation_entity=parameters, openid_provider=OPMetadata())
    statement = schema(**entity_statement_payload(
        iss="https://subject.example.org", metadata=metadata))
    statement.verify()
    assert statement["metadata"] is metadata
    assert metadata["federation_entity"] is parameters
    parameters.update({"extra": None})
    with pytest.raises(ValueError, match="metadata federation_entity parameter extra"):
        metadata.verify()
    parameters["extra"] = ""
    metadata.verify()
    statement.verify()
    for root in ({"federation_entity": parameters}, Message(federation_entity=parameters)):
        statement.update({"metadata": root})
        statement.verify()
    partial = schema(metadata={"openid_provider": {}})
    with pytest.raises(MissingRequiredAttribute):
        partial.verify()


@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_known_metadata_empty_array_survives_typed_deserialization(path):
    source = {"federation_entity": {"contacts": []}}
    before = deepcopy(source)
    if path == "constructor":
        metadata = Metadata(**source)
    elif path == "from_dict":
        metadata = Metadata().from_dict(source)
    elif path == "json":
        metadata = Metadata().deserialize(json.dumps(source), "json")
    else:
        metadata = Metadata()
        metadata["federation_entity"] = source["federation_entity"]
    metadata.verify()
    assert isinstance(metadata["federation_entity"], FederationEntity)
    assert "contacts" in metadata["federation_entity"]
    assert metadata["federation_entity"]["contacts"] == []
    assert metadata.to_dict() == source
    restored = Metadata().deserialize(metadata.serialize("json"), "json")
    restored.verify()
    assert restored.to_dict() == source
    metadata["federation_entity"]["contacts"].append("parsed@example.org")
    assert source == before
    source["federation_entity"]["contacts"].append("source@example.org")
    assert restored["federation_entity"]["contacts"] == []


@pytest.mark.parametrize("entity_type,field,default", [
    ("openid_relying_party", "application_type", "web"),
    ("openid_relying_party", "response_types", ["code"]),
    ("openid_provider", "grant_types_supported", ["authorization_code", "implicit"]),
])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment", "update"])
def test_metadata_explicit_null_cannot_become_default(entity_type, field, default, path):
    source = {entity_type: {field: None}}
    if path == "constructor":
        parsed = Metadata(**source)
    elif path == "from_dict":
        parsed = Metadata().from_dict(source)
    else:
        parsed = Metadata()
        if path == "assignment":
            parsed[entity_type] = source[entity_type]
        else:
            parsed.update(deepcopy(source))
    assert parsed[entity_type][field] is None
    with pytest.raises(ValueError, match="must not be null"):
        parsed.verify()
    parsed[entity_type][field] = default
    parsed.verify()
    assert source == {entity_type: {field: None}}


@pytest.mark.parametrize("entity_type,field", [
    ("openid_relying_party", "response_types"),
    ("openid_provider", "grant_types_supported"),
])
@pytest.mark.parametrize("value", [None, [], ["explicit"]])
def test_metadata_empty_array_is_not_omission(entity_type, field, value):
    omitted = Metadata(**{entity_type: {}})
    source = {entity_type: {} if value is None else {field: value}}
    parsed = Metadata(**source)
    parsed.verify()
    expected = omitted[entity_type][field] if value is None else value
    assert parsed[entity_type][field] == expected
    assert omitted[entity_type][field]


@pytest.mark.parametrize("lookup", ["exact", "language", "wildcard"])
@pytest.mark.parametrize("null_allowed", [False, True])
@pytest.mark.parametrize("value", [[], ["original"]])
@pytest.mark.parametrize("mode", ["accept", "reject", "invalid"])
def test_metadata_nested_array_callback_dispatch(lookup, null_allowed, value, mode):
    seen = []
    field = {"exact": "items", "language": "items#sv", "wildcard": "extension"}[lookup]

    def load(items, *, sformat):
        seen.append((deepcopy(items), sformat))
        if mode == "reject":
            raise ValueError("nested metadata callback rejected")
        return "not-an-array" if mode == "invalid" else items + ["processed"]

    class Parameters(Message):
        c_param = {"*" if lookup == "wildcard" else "items":
                   ([str], False, None, load, null_allowed)}
        c_default = {field: ["default"]}

    def deserialize(value, *, sformat):
        return deserialize_from_one_of(value, Parameters, sformat)

    class LocalMetadata(Metadata):
        c_param = Metadata.c_param.copy()
        c_param["federation_entity"] = (Message, False, None, deserialize, False)

    source = {"federation_entity": {field: deepcopy(value)}}
    if mode == "reject":
        with pytest.raises(DecodeError, match="nested metadata callback rejected"):
            LocalMetadata(**source)
    elif mode == "invalid":
        with pytest.raises(ValueError, match="array"):
            LocalMetadata(**source).verify()
    else:
        parsed = LocalMetadata(**source)
        parsed.verify()
        assert parsed["federation_entity"][field] == value + ["processed"]
    assert seen == [(value, "dict")]
    assert source == {"federation_entity": {field: value}}
    assert Parameters.c_param["*" if lookup == "wildcard" else "items"][-1] is null_allowed
    assert Parameters.c_default == {field: ["default"]}


def _metadata_fallback_schema(base, deserializer):
    class LocalSchema(base):
        c_param = base.c_param.copy()
        c_param["*"] = (Message, False, None, deserializer, False)

    return LocalSchema


@pytest.mark.parametrize("base", [Metadata, MetadataPolicy])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "dict_deserialize", "json"])
@pytest.mark.parametrize("result_kind", ["dict", "message", "none", "list", "string"])
def test_metadata_fallback_retains_actual_result(base, path, result_kind):
    seen = []
    results = []
    value = {"name": ["original"]} if base is Metadata else {"name": {"value": ["original"]}}
    source = {"https://example.org/type": deepcopy(value)}

    def deserialize(items, *, sformat):
        seen.append((deepcopy(items), sformat))
        nested = items["name"] if base is Metadata else items["name"]["value"]
        nested.append("processed")
        result = {"dict": items, "message": Message(**items), "none": None,
                  "list": [], "string": "unsupported"}[result_kind]
        results.append(result)
        return result

    schema = _metadata_fallback_schema(base, deserialize)
    if path == "constructor":
        parsed = schema(**source)
    elif path == "from_dict":
        parsed = schema().from_dict(source)
    elif path == "dict_deserialize":
        parsed = schema().deserialize(source, "dict")
    else:
        parsed = schema().deserialize(json.dumps(source), "json")
    result = parsed["https://example.org/type"]
    assert seen == [(value, "dict")]
    assert source == {"https://example.org/type": value}
    if result_kind in ("dict", "message"):
        parsed.verify()
        assert result is results[0]
        nested = result["name"] if base is Metadata else result["name"]["value"]
        assert nested == ["original", "processed"]
        nested.append("result mutation")
        assert source == {"https://example.org/type": value}
    else:
        assert result is results[0]
        with pytest.raises(ValueError, match="JSON object"):
            parsed.verify()


@pytest.mark.parametrize("base", [Metadata, MetadataPolicy])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "assignment"])
def test_supplied_extension_message_retains_local_identity(base, path):
    calls = []

    class LocalMessage(Message):
        def verify(self, **kwargs):
            calls.append(self["name"])
            raise ValueError("local instance verification")

    value = {"name": "original"} if base is Metadata else {"name": Policy(value="original")}
    nested = LocalMessage(**value)
    source = {"https://example.org/type": nested}
    if path == "constructor":
        parsed = base(**source)
    elif path == "from_dict":
        parsed = base().from_dict(source)
    else:
        parsed = base()
        parsed["https://example.org/type"] = nested
    assert parsed["https://example.org/type"] is nested
    nested["name"] = "changed" if base is Metadata else Policy(value="changed")
    assert parsed["https://example.org/type"]["name"] is nested["name"]
    with pytest.raises(ValueError, match="local instance verification"):
        parsed["https://example.org/type"].verify()
    assert calls == [nested["name"]]
    parsed.verify()


@pytest.mark.parametrize("base", [Metadata, MetadataPolicy])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "dict_deserialize", "json"])
def test_metadata_fallback_schema_uses_declared_deserializer(base, path):
    callbacks = []
    validations = []

    class LocalEntityType(Message):
        def verify(self, **kwargs):
            validations.append(kwargs)
            return super().verify(**kwargs)

    def local_deserializer(value, *, sformat):
        callbacks.append((deepcopy(value), sformat))
        parsed = deserialize_from_one_of(value, LocalEntityType, sformat)
        parsed["callback_marker"] = (
            {"value": "accepted"} if base is MetadataPolicy else ["accepted"]
        )
        if "empty" in value:
            parsed["empty"] = "callback-preserved"
        return parsed

    schema = _metadata_fallback_schema(base, local_deserializer)
    entity_type = "https://example.org/type"
    if base is Metadata:
        value = {"name": "original", "empty": "", "items": [],
                 "nested": {"flag": False}}
    else:
        value = {"name": {"value": "original"}}
    source = {entity_type: deepcopy(value)}
    before = deepcopy(source)
    if path == "constructor":
        parsed = schema(**source)
    elif path == "from_dict":
        parsed = schema().from_dict(source)
    elif path == "dict_deserialize":
        parsed = schema().deserialize(source, "dict")
    else:
        parsed = schema().deserialize(json.dumps(source), "json")

    parsed.verify()
    nested = parsed[entity_type]
    assert isinstance(nested, LocalEntityType)
    marker = {"value": "accepted"} if base is MetadataPolicy else ["accepted"]
    assert nested["callback_marker"] == marker
    if base is Metadata:
        assert nested["empty"] == "callback-preserved"
        assert nested["items"] == []
        assert nested["nested"] == {"flag": False}
    nested.verify(local_approval="approved")
    assert validations == [{"local_approval": "approved"}]
    assert callbacks == [(value, "dict")]
    assert source == before

    other = schema().from_dict(source)
    if base is MetadataPolicy:
        nested["callback_marker"]["value"] = "changed"
    else:
        nested["callback_marker"].append("changed")
    assert other[entity_type]["callback_marker"] == marker
    assert source == before


@pytest.mark.parametrize("base", [Metadata, MetadataPolicy])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "dict_deserialize", "json"])
def test_metadata_fallback_schema_rejection_is_effective(base, path):
    seen = []

    def rejecting_deserializer(value, *, sformat):
        seen.append((deepcopy(value), sformat))
        raise ValueError("local metadata fallback rejected input")

    schema = _metadata_fallback_schema(base, rejecting_deserializer)
    value = ({"name": "original"} if base is Metadata
             else {"name": {"value": "original"}})
    source = {"https://example.org/type": value}
    with pytest.raises(DecodeError, match="local metadata fallback rejected input") as error:
        if path == "constructor":
            schema(**source)
        elif path == "from_dict":
            schema().from_dict(source)
        elif path == "dict_deserialize":
            schema().deserialize(source, "dict")
        else:
            schema().deserialize(json.dumps(source), "json")
    assert seen == [(value, "dict")]
    assert isinstance(error.value.__context__, ValueError)


@pytest.mark.parametrize("base", [Metadata, MetadataPolicy])
def test_metadata_schema_exact_and_language_keys_precede_wildcard(base):
    seen = []

    def deserializer(name):
        def load(value, *, sformat):
            seen.append((name, deepcopy(value), sformat))
            return Message(**value)
        return load

    class LocalSchema(base):
        c_param = base.c_param.copy()
        c_param["https://exact.example.org/type"] = (
            Message, False, None, deserializer("exact"), False)
        c_param["https://language.example.org/type"] = (
            Message, False, None, deserializer("language"), False)
        c_param["*"] = (Message, False, None, deserializer("wildcard"), False)

    source = {
        "https://exact.example.org/type": {"name": "exact"},
        "https://language.example.org/type#sv": {"name": "language"},
        "https://fallback.example.org/type": {"name": "wildcard"},
    }
    parsed = LocalSchema().from_dict(source)
    assert seen == [
        ("exact", {"name": "exact"}, "dict"),
        ("language", {"name": "language"}, "dict"),
        ("wildcard", {"name": "wildcard"}, "dict"),
    ]
    assert all(isinstance(value, Message) for value in parsed.values())


@pytest.mark.parametrize("base", [Metadata, MetadataPolicy])
def test_metadata_fallback_assignment_and_update_remain_raw(base):
    seen = []

    def local_deserializer(value, *, sformat):
        seen.append((value, sformat))
        return Message(**value)

    schema = _metadata_fallback_schema(base, local_deserializer)
    assigned_value = {"name": "assigned"}
    assigned = schema()
    assigned["https://example.org/assigned"] = assigned_value
    assert assigned["https://example.org/assigned"] is assigned_value
    raw_value = {"name": "raw"}
    assigned.update({"https://example.org/raw": raw_value})
    assert assigned["https://example.org/raw"] is raw_value
    assert seen == []


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


def _statement_list_schema(base, claim, deserializer):
    class LocalStatement(base):
        c_param = base.c_param.copy()

    spec = list(LocalStatement.c_param[claim])
    spec[3] = deserializer
    LocalStatement.c_param[claim] = tuple(spec)
    return LocalStatement


def _statement_list_payload(base, claim, value):
    if base is ExplicitRegistrationResponse:
        payload = explicit_registration_response_payload()
    else:
        payload = entity_statement_payload()
        if base is EntityConfiguration:
            payload["iss"] = payload["sub"]
    payload[claim] = deepcopy(value)
    if claim == "crit":
        payload.update(extension="supported", accepted_extension="accepted")
    return payload


def _parse_statement_list(schema, path, payload, claim):
    if path == "constructor":
        return schema(**payload)
    if path == "from_dict":
        return schema().from_dict(payload)
    if path == "json":
        return schema().deserialize(json.dumps(payload), "json")
    statement = schema(**{key: value for key, value in payload.items() if key != claim})
    statement[claim] = payload[claim]
    return statement


@pytest.mark.parametrize("base,claim", [
    (EntityStatement, "crit"),
    (EntityConfiguration, "authority_hints"),
    (EntityConfiguration, "trust_anchor_hints"),
    (SubordinateStatement, "metadata_policy_crit"),
])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_statement_list_fields_use_declared_deserializer(base, claim, path):
    seen = []
    value = (["extension"] if claim == "crit" else
             ["regexp"] if claim == "metadata_policy_crit" else
             ["https://superior.example.org"])
    appended = ("accepted_extension" if claim == "crit" else
                "accepted_operator" if claim == "metadata_policy_crit" else
                "https://accepted.example.org")

    def local_deserializer(items, *, sformat):
        seen.append((deepcopy(items), sformat))
        items.append(appended)
        return items

    schema = _statement_list_schema(base, claim, local_deserializer)
    payload = _statement_list_payload(base, claim, value)
    before = deepcopy(payload)
    statement = _parse_statement_list(schema, path, payload, claim)
    assert statement[claim] == value + [appended]
    assert seen == [(value, "dict")]
    assert payload == before
    if claim == "crit":
        statement.verify(known_extensions=["extension", "accepted_extension"])
    elif claim == "metadata_policy_crit":
        with pytest.raises(MetadataPolicyCritError, match="Unsupported"):
            statement.verify()
    else:
        statement.verify()


@pytest.mark.parametrize("base,claim", [
    (EntityStatement, "crit"),
    (EntityConfiguration, "authority_hints"),
    (EntityConfiguration, "trust_anchor_hints"),
    (SubordinateStatement, "metadata_policy_crit"),
])
@pytest.mark.parametrize("path", ["constructor", "from_dict", "json", "assignment"])
def test_statement_list_field_deserializer_rejection_is_effective(base, claim, path):
    seen = []
    value = (["extension"] if claim == "crit" else
             ["regexp"] if claim == "metadata_policy_crit" else
             ["https://superior.example.org"])

    def rejecting_deserializer(items, *, sformat):
        seen.append((deepcopy(items), sformat))
        raise ValueError("local statement list deserializer rejected input")

    schema = _statement_list_schema(base, claim, rejecting_deserializer)
    payload = _statement_list_payload(base, claim, value)
    with pytest.raises(ValueError, match="local statement list deserializer rejected input"):
        _parse_statement_list(schema, path, payload, claim)
    assert seen == [(value, "dict")]


@pytest.mark.parametrize("base", [
    EntityStatement, EntityConfiguration, SubordinateStatement,
    ExplicitRegistrationResponse,
])
def test_entity_statement_derivatives_preserve_inherited_crit_deserializer(base):
    seen = []

    def local_deserializer(items, *, sformat):
        seen.append((deepcopy(items), sformat))
        return items

    schema = _statement_list_schema(base, "crit", local_deserializer)
    payload = _statement_list_payload(base, "crit", ["extension"])
    statement = schema(**payload)
    statement.verify(known_extensions=["extension"])
    assert statement["crit"] == ["extension"]
    assert seen == [(["extension"], "dict")]


@pytest.mark.parametrize("base,claim,malformed", [
    (EntityStatement, "crit", "extension"),
    (EntityConfiguration, "authority_hints", "https://superior.example.org"),
    (EntityConfiguration, "trust_anchor_hints", None),
    (SubordinateStatement, "metadata_policy_crit", "regexp"),
])
def test_statement_list_malformed_input_cannot_be_laundered(base, claim, malformed):
    seen = []

    def laundering_deserializer(items, *, sformat):
        seen.append(sformat)
        return [items]

    schema = _statement_list_schema(base, claim, laundering_deserializer)
    statement = schema(**_statement_list_payload(base, claim, malformed))
    assert statement[claim] == malformed
    assert seen == []
    error = MetadataPolicyCritError if claim == "metadata_policy_crit" else ValueError
    with pytest.raises(error):
        statement.verify(known_extensions=["extension"])


@pytest.mark.parametrize("base,claim", [
    (EntityStatement, "crit"),
    (EntityConfiguration, "authority_hints"),
    (EntityConfiguration, "trust_anchor_hints"),
    (SubordinateStatement, "metadata_policy_crit"),
])
@pytest.mark.parametrize("result", ["wrapped", ["valid", 1]])
def test_statement_list_deserializer_result_is_validated(base, claim, result):
    def invalid_deserializer(items, *, sformat):
        assert sformat == "dict"
        return deepcopy(result)

    schema = _statement_list_schema(base, claim, invalid_deserializer)
    value = (["extension"] if claim == "crit" else
             ["regexp"] if claim == "metadata_policy_crit" else
             ["https://superior.example.org"])
    with pytest.raises(ValueError, match=claim):
        schema(**_statement_list_payload(base, claim, value))


@pytest.mark.parametrize("value", ["supported", ""])
@pytest.mark.parametrize("path", ["constructor", "json", "assignment", "update"])
def test_schema_subclass_critical_extension_presence_and_order(value, path):
    seen = []

    class LocalStatement(EntityStatement):
        c_param = EntityStatement.c_param.copy()
        c_param["local_claim"] = SINGLE_OPTIONAL_STRING

        def verify(self, **kwargs):
            known = list(kwargs.get("known_extensions") or ())
            known.append("local_claim")
            kwargs["known_extensions"] = known
            result = super().verify(**kwargs)
            seen.append(self["local_claim"])
            if self["local_claim"] not in ("supported", ""):
                raise ValueError("Unsupported local claim value")
            return result

    payload = entity_statement_payload(local_claim=value)
    if path == "constructor":
        statement = LocalStatement(**dict(payload, crit=["local_claim"]))
    elif path == "json":
        statement = LocalStatement().deserialize(
            json.dumps(dict(payload, crit=["local_claim"])),
            "json",
        )
    else:
        statement = LocalStatement(**payload)
        if path == "assignment":
            statement["crit"] = ["local_claim"]
        else:
            statement.update({"crit": ["local_claim"]})

    assert "local_claim" in statement
    assert statement["local_claim"] == value
    assert statement.verify() is None
    assert seen == [value]


@pytest.mark.parametrize("base", [
    EntityStatement, EntityConfiguration, SubordinateStatement,
    ExplicitRegistrationResponse,
])
@pytest.mark.parametrize("path", [
    "constructor", "from_dict", "dict_deserialize", "json", "assignment",
])
@pytest.mark.parametrize("value", [[], ["original"]])
def test_declared_list_critical_extension_preserves_arrays(base, path, value):
    deserialized = []
    validated = []

    def local_deserializer(items, *, sformat):
        deserialized.append((deepcopy(items), sformat))
        return items

    class LocalStatement(base):
        c_param = base.c_param.copy()
        spec = list(OPTIONAL_LIST_OF_STRINGS)
        spec[3] = local_deserializer
        c_param["local_claim"] = tuple(spec)

        def verify(self, **kwargs):
            known = list(kwargs.get("known_extensions") or ())
            known.append("local_claim")
            kwargs["known_extensions"] = known
            result = super().verify(**kwargs)
            validated.append(deepcopy(self["local_claim"]))
            if not isinstance(self["local_claim"], list) or not all(
                    isinstance(item, str) for item in self["local_claim"]):
                raise ValueError("Unsupported local list value")
            return result

    payload = _statement_list_payload(base, "crit", ["local_claim"])
    payload.pop("extension")
    payload.pop("accepted_extension")
    payload["local_claim"] = deepcopy(value)
    before = deepcopy(payload)
    if path == "constructor":
        statement = LocalStatement(**payload)
    elif path == "from_dict":
        statement = LocalStatement().from_dict(payload)
    elif path == "dict_deserialize":
        statement = LocalStatement().deserialize(payload, "dict")
    elif path == "json":
        statement = LocalStatement().deserialize(json.dumps(payload), "json")
    else:
        statement = LocalStatement(**{key: item for key, item in payload.items()
                                      if key != "local_claim"})
        statement["local_claim"] = payload["local_claim"]

    statement.verify()
    assert statement["local_claim"] == value
    assert deserialized == [(value, "dict")]
    assert validated == [value]
    assert payload == before
    assert "local_claim" not in base.c_param


def test_declared_empty_array_extension_preserves_deserializer_result():
    seen = []

    def transforming_deserializer(items, *, sformat):
        seen.append((deepcopy(items), sformat))
        return ["transformed"]

    class LocalStatement(EntityStatement):
        c_param = EntityStatement.c_param.copy()
        spec = list(OPTIONAL_LIST_OF_STRINGS)
        spec[3] = transforming_deserializer
        c_param["local_claim"] = tuple(spec)

    statement = LocalStatement(**entity_statement_payload(
        local_claim=[], crit=["local_claim"]))
    assert statement["local_claim"] == ["transformed"]
    assert seen == [([], "dict")]
    statement.verify(known_extensions=["local_claim"])


def test_declared_empty_array_extension_honors_rejecting_deserializer():
    def rejecting_deserializer(items, *, sformat):
        assert items == []
        assert sformat == "dict"
        raise ValueError("local empty array deserializer rejected input")

    class LocalStatement(EntityStatement):
        c_param = EntityStatement.c_param.copy()
        spec = list(OPTIONAL_LIST_OF_STRINGS)
        spec[3] = rejecting_deserializer
        c_param["local_claim"] = tuple(spec)

    with pytest.raises(Exception, match="local empty array deserializer rejected input"):
        LocalStatement(**entity_statement_payload(
            local_claim=[], crit=["local_claim"]))


def test_declared_empty_array_extension_crit_order_raw_update_and_repair():
    seen = []

    class LocalStatement(EntityStatement):
        c_param = EntityStatement.c_param.copy()
        c_param["local_claim"] = OPTIONAL_LIST_OF_STRINGS

        def verify(self, **kwargs):
            known = list(kwargs.get("known_extensions") or ())
            known.append("local_claim")
            kwargs["known_extensions"] = known
            result = super().verify(**kwargs)
            seen.append(deepcopy(self["local_claim"]))
            if not isinstance(self["local_claim"], list) or not all(
                    isinstance(item, str) for item in self["local_claim"]):
                raise ValueError("Unsupported local list value")
            return result

    statement = LocalStatement(**entity_statement_payload(crit=["local_claim"]))
    with pytest.raises(ValueError, match="absent"):
        statement.verify()
    statement["local_claim"] = []
    statement.verify()

    raw = []
    statement.update({"local_claim": raw})
    assert statement["local_claim"] is raw
    statement.verify()
    raw.append(1)
    with pytest.raises(ValueError, match="Unsupported local list value"):
        statement.verify()
    raw[-1] = "repaired"
    statement.verify()
    assert seen == [[], [], [1], ["repaired"]]


def test_declared_empty_array_extension_validator_rejection_and_repair():
    class LocalStatement(EntityStatement):
        c_param = EntityStatement.c_param.copy()
        c_param["local_claim"] = OPTIONAL_LIST_OF_STRINGS

        def verify(self, **kwargs):
            known = list(kwargs.get("known_extensions") or ())
            known.append("local_claim")
            kwargs["known_extensions"] = known
            super().verify(**kwargs)
            if not self["local_claim"]:
                raise ValueError("Local extension requires a value")

    statement = LocalStatement(**entity_statement_payload(
        local_claim=[], crit=["local_claim"]))
    with pytest.raises(ValueError, match="requires a value"):
        statement.verify()
    statement["local_claim"] = ["repaired"]
    statement.verify()


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
