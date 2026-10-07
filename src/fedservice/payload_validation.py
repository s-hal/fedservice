"""Read-only Federation payload predicates, independent of concrete schemas."""

import re
import math
from urllib.parse import urlsplit

from idpyoidc.message import Message
from idpyoidc.exception import MissingRequiredAttribute
from fedservice.exception import ConstraintError
from fedservice.exception import MetadataPolicyCritError


_NAMING_CONSTRAINT_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
_STRING_ARRAY_OPERATORS = ("subset_of", "one_of", "superset_of", "add")


def valid_naming_constraint(name):
    """Return whether a naming-constraint value is a valid domain name."""
    if not isinstance(name, str):
        return False
    host = name[1:] if name.startswith(".") else name
    return (0 < len(host) <= 253
            and all(_NAMING_CONSTRAINT_LABEL.fullmatch(label) for label in host.split(".")))


def _validate_naming_constraints(naming, *, json_input=False):
    if not isinstance(naming, (dict,) if json_input else (dict, Message)):
        raise ConstraintError("naming_constraints must be a JSON object")
    for key in ("permitted", "excluded"):
        if key not in naming:
            continue
        names = naming[key]
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise ConstraintError("{} naming constraint must be an array of strings".format(key))
        if not all(valid_naming_constraint(name) for name in names):
            raise ConstraintError("{} naming constraint contains an invalid domain".format(key))


def _validate_max_path_length(path_length):
    if type(path_length) is not int or path_length < 0:
        raise ConstraintError("max_path_length must be a non-negative integer")


def _validate_allowed_entity_types(allowed):
    if not isinstance(allowed, list) or not all(isinstance(entity_type, str) for entity_type in allowed):
        raise ConstraintError("allowed_entity_types must be an array of strings")
    if "federation_entity" in allowed:
        raise ConstraintError("federation_entity must not appear in allowed_entity_types")


def _validate_constraints_input(constraints):
    if not isinstance(constraints, dict):
        raise ConstraintError("constraints must be a JSON object")
    if "max_path_length" in constraints:
        _validate_max_path_length(constraints["max_path_length"])
    if "naming_constraints" in constraints:
        _validate_naming_constraints(constraints["naming_constraints"], json_input=True)
    if "allowed_entity_types" in constraints:
        _validate_allowed_entity_types(constraints["allowed_entity_types"])


def _validate_policy_value(value, array_item=False):
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _validate_policy_value(item, array_item=True)
        return
    if array_item and type(value) is dict and all(isinstance(key, str) for key in value):
        for item in value.values():
            _validate_policy_value(item, array_item=True)
        return
    raise ValueError("Policy value/default must be a JSON scalar or array")


def _validate_policy_operands(policy, string_array_operators=_STRING_ARRAY_OPERATORS):
    for operator in string_array_operators:
        if operator in policy:
            operand = policy[operator]
            if not isinstance(operand, list) or not all(isinstance(value, str) for value in operand):
                raise ValueError("{} policy value must be an array of strings".format(operator))
    if "essential" in policy and type(policy["essential"]) is not bool:
        raise ValueError("essential policy value must be a boolean")
    for operator in ("value", "default"):
        if operator in policy:
            _validate_policy_value(policy[operator])
    if "default" in policy and policy["default"] is None:
        raise ValueError("default policy value must not be null")


def _validate_policy_critical(critical, standard_operators):
    if not isinstance(critical, (list, tuple)) or not critical:
        raise MetadataPolicyCritError("metadata_policy_crit must be a non-empty array")
    if not all(isinstance(name, str) and name for name in critical):
        raise MetadataPolicyCritError("metadata_policy_crit must contain operator names")
    if set(critical).intersection(standard_operators):
        raise MetadataPolicyCritError("Standard operators must not appear in metadata_policy_crit")
    # Naming an extension in known_policy_extensions does not implement it.
    # No additional operators currently have merge and application support.
    raise MetadataPolicyCritError("Unsupported critical metadata policy operator")


def _validate_metadata_policy_containers(policy, *, json_input=False):
    object_types = (dict,) if json_input else (dict, Message)
    if not isinstance(policy, object_types) or not policy:
        raise ValueError("metadata_policy must be a nonempty JSON object")
    for typ, parameters in policy.items():
        if not isinstance(parameters, object_types) or not parameters:
            raise ValueError("metadata_policy {} must be a nonempty JSON object".format(typ))
        for attr, item in parameters.items():
            if not isinstance(item, object_types) or not item:
                raise ValueError("metadata_policy {} parameter {} must be a nonempty JSON object".format(
                    typ, attr))


def _validate_metadata_policy_input(policy):
    _validate_metadata_policy_containers(policy, json_input=True)
    for parameters in policy.values():
        for item in parameters.values():
            _validate_policy_operands(item)


def _require_entity_statement_claims(payload):
    for claim in ("iss", "sub", "iat", "exp", "jwks"):
        if claim not in payload:
            raise MissingRequiredAttribute(claim)


def _validate_numeric_date(value, claim):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (
            isinstance(value, float) and not math.isfinite(value)):
        raise ValueError("{} must be a finite JSON number".format(claim))


def _validate_jwks(jwks):
    if not isinstance(jwks, dict):
        raise ValueError("jwks must be a JSON object")
    if "keys" not in jwks or not isinstance(jwks["keys"], list):
        raise ValueError("jwks must contain a keys array")
    if any(not isinstance(key, dict) for key in jwks["keys"]):
        raise ValueError("jwks keys entries must be JSON objects")


def _validate_claim_placement(payload, forbidden, location):
    for claim in forbidden:
        if claim in payload:
            raise ValueError("{} is only allowed in {}".format(claim, location))


def _validate_expected_issuer(payload, expected_issuer):
    if expected_issuer and "iss" in payload and expected_issuer != payload["iss"]:
        raise ValueError("Wrong issuer")


def _validate_entity_hints(hints, claim):
    if not isinstance(hints, list) or not hints:
        raise ValueError("{} must be a nonempty array".format(claim))
    for identifier in hints:
        _validate_entity_identifier(identifier, claim)


def _validate_critical_claims(payload, defined):
    critical = payload["crit"]
    if not isinstance(critical, list) or not critical or any(
            not isinstance(name, str) or not name for name in critical):
        raise ValueError("crit must be a nonempty array of claim names")
    names = set(critical)
    if len(names) != len(critical):
        raise ValueError("crit must not contain duplicate names")
    if names.intersection(defined):
        raise ValueError("crit must not name defined claims")
    if not names.issubset(payload.keys()):
        raise ValueError("crit names an absent claim")
    return names


def _validate_metadata(metadata, *, json_input=False):
    object_types = (dict,) if json_input else (dict, Message)
    if not isinstance(metadata, object_types):
        raise ValueError("metadata must be a JSON object")
    for entity_type, parameters in metadata.items():
        if not isinstance(parameters, object_types):
            raise ValueError("metadata {} must be a JSON object".format(entity_type))
        for name, value in parameters.items():
            if value is None:
                raise ValueError("metadata {} parameter {} must not be null".format(
                    entity_type, name))
            if json_input and name.split("#")[0] in ("contacts", "keywords"):
                if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                    raise ValueError("metadata {} parameter {} must be an array of strings".format(
                        entity_type, name))


def _validate_entity_identifier(value, claim):
    error = "{} must be an HTTPS Entity Identifier without query or fragment".format(claim)
    if not isinstance(value, str) or not value:
        raise ValueError(error)
    if any(char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159
           for char in value):
        raise ValueError(error)
    if any(char in value for char in '?#\\<>"{}|^`') or re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError(error)
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError(error)
        # One @ may separate userinfo from host; additional raw @ is not userinfo data.
        if parsed.netloc.count("@") > 1:
            raise ValueError(error)
        # IP-literal host brackets are legal, but raw brackets are not path characters.
        if "[" in parsed.path or "]" in parsed.path:
            raise ValueError(error)
        # Accessing port also checks malformed and out-of-range port values.
        parsed.port
    except ValueError as err:
        raise ValueError(error) from err
