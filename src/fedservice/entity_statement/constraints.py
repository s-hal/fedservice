"""Trust Chain path-length and host naming constraints."""

import re
from collections.abc import Mapping
from typing import List
from urllib.parse import urlsplit

from fedservice import message

_DOMAIN_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")


def _valid_name(name):
    if not isinstance(name, str):
        return False
    host = name[1:] if name.startswith(".") else name
    return (0 < len(host) <= 253
            and all(_DOMAIN_LABEL.fullmatch(label) for label in host.split(".")))


def _matches(host, name):
    name = name.lower()
    if name.startswith("."):
        return host.endswith(name) and len(host) > len(name)
    return host == name


def _meets_naming_constraints(subject_id, constraints):
    if not isinstance(constraints, Mapping):
        return False
    for key in ("permitted", "excluded"):
        if key in constraints:
            names = constraints[key]
            if not isinstance(names, list) or not all(_valid_name(name) for name in names):
                return False
    try:
        host = urlsplit(subject_id).hostname
    except ValueError:
        return False
    if not host:
        return False
    if any(_matches(host, name) for name in constraints.get("excluded", [])):
        return False
    names = constraints.get("permitted", [])
    return not names or any(_matches(host, name) for name in names)


def meets_restrictions(trust_chain: List[message.EntityConfiguration]) -> bool:
    """Check every constraint from the Trust Anchor down to the leaf."""
    for index, statement in enumerate(trust_chain[:-1]):
        constraints = statement.get("constraints") or {}
        # Exclude the setter and the leaf's final Entity Configuration.
        intermediates = len(trust_chain) - index - 2
        max_path_length = constraints.get("max_path_length")
        if max_path_length is not None and intermediates > max_path_length:
            return False

        if "naming_constraints" in constraints:
            # Keep each declaration independent: a lower constraint cannot
            # weaken an inherited exclusion or broaden inherited permission.
            for subordinate in trust_chain[index:]:
                if not _meets_naming_constraints(
                        subordinate["sub"], constraints["naming_constraints"]):
                    return False
    return True
