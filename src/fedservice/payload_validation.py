"""Read-only Federation payload predicates, independent of concrete schemas."""

import re
from urllib.parse import urlsplit

from idpyoidc.message import Message


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
