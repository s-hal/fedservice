"""Read-only Federation payload predicates, independent of concrete schemas."""

import re
import math
from urllib.parse import urlsplit

from idpyoidc.message import Message
from idpyoidc.exception import MissingRequiredAttribute


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


def _validate_metadata(metadata):
    if not isinstance(metadata, (dict, Message)):
        raise ValueError("metadata must be a JSON object")
    for entity_type, parameters in metadata.items():
        if not isinstance(parameters, (dict, Message)):
            raise ValueError("metadata {} must be a JSON object".format(entity_type))
        for name, value in parameters.items():
            if value is None:
                raise ValueError("metadata {} parameter {} must not be null".format(
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
