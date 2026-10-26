"""Trust Chain path-length, host naming and Registration Policy constraints."""

from collections.abc import Mapping
from typing import List
from urllib.parse import urlsplit

from fedservice import message

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
            if not isinstance(names, list) or not all(
                    message.valid_naming_constraint(name) for name in names):
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

        if "registration_policy" in constraints:
            # Only strictly lower SSs are targets, never the setter or final EC.
            # Intermediate subjects issue the next SS; leaf types come from the EC,
            # before metadata processing or Resolve's requested-type filtering.
            for target_index in range(index + 1, len(trust_chain) - 1):
                subordinate = trust_chain[target_index]
                entity_types = ({"federation_entity"} if target_index < len(trust_chain) - 2
                                else set(trust_chain[-1].get("metadata", {})))
                for rule in constraints["registration_policy"]:
                    if "entity_types" in rule and entity_types.isdisjoint(rule["entity_types"]):
                        continue
                    if not set(rule["policy"]).intersection(subordinate.get("registration_policy", ())):
                        return False
    return True
